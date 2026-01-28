from typing import Literal
from mailproxy.db import db_list_mailboxes, db_mailbox_by_name, db_open, db_mailbox_count_deleted, db_mailbox_count_messages, db_mailbox_size, \
    db_mailbox_uid_next, db_mailbox_uid_validity, db_mailbox_count_unseen
import asyncio, base64, logging, ssl, re
from mailproxy.auth import account_get_oauth_access_token, authenticate, authenticate_sasl
from mailproxy.config import Account, AuthenticationOAUTH2, AuthenticationPLAIN, Config, TLSMode
from mailproxy.model import Mailbox
from mailproxy.utils import BacktrackingStreamReader, match_lineb

def imap_to_quoted_string(value: bytes):
  return b"\"%s\"" % (value.replace(b"\"", b"\\\""),)

class IMAPCommandFailedError(Exception): pass

class IMAPRemoteConnection:
  _tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

  def __init__(self, config: Config, account: Account, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    self.account = account
    self.config = config
    self._reader = reader
    self._writer = writer
    self._command_counter = 0
    self._use_imb_cte = True
    self._capabilities: list[bytes] = []

  async def shutdown(self):
    try:
      self._start_command(b"LOGOUT")
      await self._read_until_response()
      self._writer.close()
      await self._writer.wait_closed()
    finally:
      self._writer.close()

  async def sync_mailbox(self, mailbox_name: str):
    pass

  async def wait_for_update(self, mailbox_name: str, update_event: asyncio.Event):
    try:
      await self._command_select(mailbox_name)
      self._start_command(b"IDLE")
      server_response = await self._read_line()
      if not server_response.startswith(b"+"):
        raise RuntimeError("server didnt respond with + in idle!")
      while True:
        line = await self._read_line()
        if match_lineb(br"* \d+ (EXISTS|EXPUNGE|FETCH).*", line):
          update_event.set()
    finally:
      self._writer.write(b"DONE\r\n")
      await self._read_until_response()

  async def _init(self):
    logging.debug("IMAP init: " + (await self._read_line()).decode())
    self._capabilities = await self._command_capabilities()
    if self.account.imap_tlsmode == TLSMode.STARTTLS:
      if b"STARTTLS" not in self._capabilities:
        raise IMAPCommandFailedError("STARTTLS required by account but not supported by remote!")
      await self._command_starttls()
      self._capabilities = await self._command_capabilities()

    enable_imap4_rev2 = b"IMAP4rev2" in self._capabilities
    self._use_imb_cte = not enable_imap4_rev2
    if enable_imap4_rev2:
      self._start_command(b"ENABLE IMAP4rev2")
      await self._read_until_response()

    if isinstance(self.account.auth, AuthenticationOAUTH2):
      with db_open(self.config.db_path) as db:
        access_token = account_get_oauth_access_token(db, self.account)
      await self._command_authenticate(b"XOAUTH2", f"user={self.account.addresses[0]}\1auth=Bearer {access_token}\1\1".encode())
    elif isinstance(self.account.auth, AuthenticationPLAIN):
      await self._command_authenticate(b"PLAIN", b"%s\0%s" % (self.account.addresses[0].encode(), self.account.auth.password.encode()))

  async def _command_select(self, mailbox_name: str):
    self._start_command(b"SELECT %s" % (self._encode_mailbox(mailbox_name),))
    await self._read_until_response()

  async def _command_authenticate(self, auth_type: bytes, auth_data: bytes):
    if (b"AUTH=%s" % (auth_type,)) not in self._capabilities:
      raise IMAPCommandFailedError(f"Auth type '{auth_type.decode()}' not supported!")
    self._start_command(b"AUTHENTICATE %s" % (auth_type,))
    if not (await self._read_line()).startswith(b"+"):
      await self._read_until_response()
      raise IMAPCommandFailedError("Invalid response from server!")
    self._writer.write(base64.b64encode(auth_data))
    self._writer.write(b"\r\n")
    await self._read_until_response()

  async def _command_capabilities(self):
    self._start_command(b"CAPABILITY")
    capabilities: list[bytes] = []
    async for line in self._read_response_lines():
      if (capdict:=match_lineb(rb"* CAPABILITY (?P<caps>.*)", line)) is not None:
        capabilities.extend(capdict["caps"].split(b" "))
    return capabilities

  async def _command_starttls(self):
    self._start_command(b"STARTTLS")
    await self._read_until_response()
    await self._writer.start_tls(IMAPRemoteConnection._tls_context)

  def _start_command(self, command: bytes):
    self._command_counter += 1
    self._writer.write(b"A%d %s\r\n" % (self._command_counter, command))

  async def _encode_mailbox(self, s: str) -> bytes:
    raise NotImplementedError()
    return b""

  async def _read_line(self):
    return (await self._reader.readuntil(b"\r\n"))[:-2]

  async def _read_until_response(self):
    async for _ in self._read_response_lines(): pass
  async def _read_response_lines(self):
    expected_tag = b"A%d " % (self._command_counter,)
    while (line:=await self._read_line()).startswith(expected_tag):
      yield line
    code, message = line[len(expected_tag):].split(b" ", maxsplit=1)
    if code.lower() != b"OK":
      raise IMAPCommandFailedError(f"remote command failed: {code.decode()} {message.decode()}")

  @staticmethod
  async def open(config: Config, account: Account):
    ssl_param = ssl.create_default_context() if account.imap_tlsmode == TLSMode.DIRECT else None
    reader, writer = await asyncio.open_connection(account.imap_host, account.imap_port, ssl=ssl_param)
    connection = IMAPRemoteConnection(config, account, reader, writer)
    await connection._init()
    return connection

class IMAPServerConnection:
  capabilities = (b"IMAP4rev2", b"AUTH=PLAIN")

  def __init__(self, config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    self._config = config
    self._reader = BacktrackingStreamReader(reader)
    self._writer = writer

    self._last_tag: bytes | None = None
    self._remote_connection: IMAPRemoteConnection | None = None
    self._mailbox: Mailbox | None = None

  def _encode_mailbox_name(self, mailbox_name: str):
    return mailbox_name.encode()

  def _decode_mailbox_name(self, mailbox_name: bytes):
    return mailbox_name.decode()

  def _write_response(self, code: Literal[b"OK"] | Literal[b"NO"] | Literal[b"BAD"], message: bytes):
    assert self._last_tag is not None
    self._writer.write(b"%s %s %s\r\n" % (self._last_tag, code, message))
    self._last_tag = None

  def _write_line(self, line: bytes):
    self._writer.write(line)
    self._writer.write(b"\r\n")

  async def _read_nstring(self, until: bytes) -> bytes | None:
    pass

  async def _read_astring(self, until: bytes) -> bytes:
    pass

  def _write_mailbox_update(self):
    if self._mailbox is None:
      return
    with db_open(self._config.db_path) as db:
      n_messages = db_mailbox_count_messages(db, self._mailbox.id)
      self._write_line(b"* %d EXISTS" % (n_messages,))

  def _write_mailbox_list_response(self, mailbox: Mailbox):
    flags = " ".join(mailbox.flags).encode("ascii")
    hierachry_delimiter_s = imap_to_quoted_string(mailbox.hierachry_delimiter.encode("ascii"))
    name_s = imap_to_quoted_string(self._encode_mailbox_name(mailbox.name))
    self._write_line(b"* LIST (%s) %s %s" % (flags, hierachry_delimiter_s, name_s))

  async def _sync_mailbox(self):
    if self._mailbox is None:
      raise IMAPCommandFailedError("No mailbox selected!")
    assert self._remote_connection is not None, "if a mailbox is selected, a remote connection must be open!"
    if self._mailbox.is_remote:
      await self._remote_connection.sync_mailbox(self._mailbox.name)

  async def _command_capability(self):
    self._write_line(b"* CAPABILITY %s" % (b" ".join(IMAPServerConnection.capabilities),))
    self._write_response(b"OK", b"CAPABILITY completed")

  async def _command_noop(self):
    if self._mailbox is not None:
      assert self._remote_connection is not None, "if a mailbox is selected, a remote connection must be open!"
      await self._remote_connection.sync_mailbox(self._mailbox.name)
      self._write_mailbox_update()
    self._write_response(b"OK", b"NOOP completed")

  async def _command_enable(self):
    caps_str = await self._reader.read_line()
    caps = caps_str.split(b" ")
    if all(c in IMAPServerConnection.capabilities for c in caps):
      self._write_response(b"OK", b"ENABLE completed")
    else:
      self._write_response(b"NO", b"not supported")

  async def _command_logout(self):
    self._write_line(b"* BYE Server logging out")
    self._write_response(b"OK", b"LOGOUT completed")

  async def _command_login(self):
    userid = await self._read_astring(b" ")
    password = await self._read_astring(b"\r\n")
    if (login_account:=authenticate(self._config, userid, password)) is None:
      self._write_response(b"NO", b"login failed")
    else:
      await self._open_remote(login_account)
      self._write_response(b"OK", b"login completed")

  async def _command_authenticate(self):
    try: await self._reader.read_const(b"PLAIN", case_sensitive=False)
    except IMAPCommandFailedError as e: raise IMAPCommandFailedError(b"Only plain auth supported for now!", e)
    await self._reader.read_crlf()
    self._write_line(b"+ login data")
    auth_line = await self._reader.read_line()
    if (login_account:=authenticate_sasl(self._config, auth_line)) is None:
      self._write_response(b"NO", b"auth failed")
    else:
      await self._open_remote(login_account)
      self._write_response(b"OK", b"auth completed")

  async def _command_subscribe(self):
    _ = await self._reader.read_line()
    self._write_response(b"OK", b"SUBSCRIBE completed")

  async def _command_unsubscribe(self):
    _ = await self._reader.read_line()
    self._write_response(b"NO", b"UNSUBSCRIBE not allowed")

  async def _command_idle(self):
    self._write_line(b"+ idling")
    tasks: list[asyncio.Task] = []
    if self._mailbox is not None:
      assert self._remote_connection is not None
      update_event = asyncio.Event()
      async def _update_on_event():
        while True:
          await update_event.wait()
          await self._sync_mailbox()
          self._write_mailbox_update()
          update_event.clear()
      tasks.extend((asyncio.Task(self._remote_connection.wait_for_update(self._mailbox.name, update_event)), asyncio.Task(_update_on_event())))
    try:
      await self._reader.read_const(b"DONE\r\n", case_sensitive=False)
      self._write_response(b"OK", b"IDLE completed")
    finally:
      for task in tasks: task.cancel()
      await asyncio.wait(tasks)

  async def _command_status(self):
    mailbox_name_raw = await self._read_nstring(b" ")
    mailbox_name = None if mailbox_name_raw is None else mailbox_name_raw.decode()
    await self._reader.read_const(b"(")
    attrs_res = await self._reader.readuntil_re(b")", rb"(?P<attrs>[A-Z ]+)\)")
    attrs = attrs_res["attrs"].split(b" ")
    await self._reader.read_crlf()

    if self._remote_connection is None:
      return self._write_response(b"NO", b"invalid state")

    account = self._remote_connection.account
    with db_open(self._config.db_path) as db:
      mailbox = self._mailbox if mailbox_name is None else db_mailbox_by_name(db, account.key, mailbox_name)
      if mailbox is None:
        return self._write_response(b"NO", b"invalid mailbox name")

      await self._remote_connection.sync_mailbox(mailbox.name)

      response: dict[bytes, int] = {}
      if b"MESSAGES" in attrs:
        response[b"MESSAGES"] = db_mailbox_count_messages(db, mailbox.id)
      if b"UIDNEXT" in attrs:
        response[b"UIDNEXT"] = db_mailbox_uid_next(db, account.key, mailbox.id)
      if b"UIDVALIDITY" in attrs:
        response[b"UIDVALIDITY"] = db_mailbox_uid_validity(db, account.key, mailbox.id)
      if b"UNSEEN" in attrs:
        response[b"UNSEEN"] = db_mailbox_count_unseen(db, mailbox.id)
      if b"DELETED" in attrs:
        response[b"DELETED"] = db_mailbox_count_deleted(db, mailbox.id)
      if b"SIZE" in attrs:
        response[b"SIZE"] = db_mailbox_size(db, mailbox.id)

      status_str = b" ".join(b"%s %d" % (k, v) for k, v in response.items())
      self._write_line(b"* STATUS %s (%s)" % (mailbox or b"NIL", status_str))
    self._write_response(b"OK", b"status completed")

  async def _command_select(self):
    if self._remote_connection is None:
      raise IMAPCommandFailedError("Tried to select mailbox before before authentication!")

    mailbox_name = (await self._read_astring(b"\r\n")).decode()
    account = self._remote_connection.account

    with db_open(self._config.db_path) as db:
      mailbox = db_mailbox_by_name(db, account.key, mailbox_name)
      if mailbox is None or mailbox.is_remote:
        await self._remote_connection.sync_mailbox(mailbox_name)
      mailbox = db_mailbox_by_name(db, account.key, mailbox_name)

      if mailbox is None:
        raise IMAPCommandFailedError("mailbox unknown")

      if self._mailbox is not None:
        self._write_line(b"* OK [CLOSED] Previous mailbox is now closed")

      self._write_line(b"* FLAGS (%s)" % (" ".join(mailbox.flags).encode("ascii"),))
      self._write_line(b"* %d EXISTS" % (db_mailbox_count_messages(db, mailbox.id),))
      self._write_mailbox_list_response(mailbox)
      self._write_line(b"* OK [PERMANENTFLAGS (\\Deleted \\Seen \\Answered \\Flagged \\Draft \\*)]")
      self._write_line(b"* OK [UIDNEXT %d]" % (mailbox.uid_next,))
      self._write_line(b"* OK [UIDVALIDITY %d]" % (mailbox.uid_validity,))
      self._mailbox = mailbox

    self._write_response(b"OK", b"[READ-WRITE] SELECT completed")

  async def _command_list(self):
    reference_name_raw = await self._read_astring(b" ")
    pattern_raw = await self._read_astring(b" ") # TODO: whats the format grammer here?

    raise NotImplementedError("how do i parse this?")

    if self._remote_connection is None:
      raise IMAPCommandFailedError("invalid state, must be logged in")

    reference_name = self._decode_mailbox_name(reference_name_raw)
    pattern = self._decode_mailbox_name(pattern_raw)

    with db_open(self._config.db_path) as db:
      for mailbox in db_list_mailboxes(db, self._remote_connection.account.key, reference_name, pattern):
        self._write_mailbox_list_response(mailbox)

    self._write_response(b"OK", b"list completed")

  async def _command_template(self): pass

  async def _open_remote(self, account: Account):
    if self._remote_connection is not None:
      await self._remote_connection.shutdown()
    self._remote_connection = await IMAPRemoteConnection.open(self._config, account)

  async def _handle_command(self):
    self._last_tag = await self._reader.readuntil(b" ") # TODO better validation
    command_raw = await self._reader.readuntil((b" ", b"\r\n")) # TODO better validation
    command = command_raw.upper()
    logging.debug("Client: " + self._last_tag.decode() + " " + command.decode())

    match command:
      case b"CAPABILITY": await self._command_capability()
      case b"NOOP": await self._command_noop()
      case b"ENABLE": await self._command_enable()
      case b"LOGOUT": await self._command_logout()
      case b"LOGIN": await self._command_login()
      case b"AUTHENTICATE": await self._command_authenticate()
      case b"SUBSCRIBE": await self._command_subscribe()
      case b"UNSUBSCRIBE": await self._command_unsubscribe()
      case b"IDLE": await self._command_idle()
      case b"STATUS": await self._command_status()
      case b"SELECT": await self._command_select()
      case b"LIST": await self._command_list()
      case b"STARTTLS": self._write_response(b"NO", b"tls not available!")

  async def run(self):
    self._write_line(b"220 %s Ready" % (self._config.domain.encode("ascii"),))
    try:
      while not self._reader.at_eof:
        try:
          self._reader.mark()
          await self._handle_command()
        except IMAPCommandFailedError:
          self._write_response(b"NO", b"command failed with internal error")
    except Exception as e:
      logging.error("connection closing because of an error", e)
    finally:
      logging.debug("connection closed")
      self._writer.close()
      if self._remote_connection is not None:
        await asyncio.wait_for(self._remote_connection.shutdown(), 1)

async def handle_imap(config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
  connection = IMAPServerConnection(config, reader, writer)
  await connection.run()
