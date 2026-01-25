from typing import Literal
from mailproxy.db import db_mailbox_id, db_open, db_status_deleted, db_status_messages, db_status_size, \
    db_status_uid_next, db_status_uid_validity, db_status_unseen
import asyncio, base64, logging, ssl, re
from mailproxy.auth import account_get_oauth_access_token, authenticate, authenticate_sasl
from mailproxy.config import Account, AuthenticationOAUTH2, AuthenticationPLAIN, Config, TLSMode
from mailproxy.utils import match_lineb

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
  def __init__(self, config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    self._config = config
    self._reader = reader
    self._writer = writer

    self._last_tag: bytes | None = None
    self._remote_connection: IMAPRemoteConnection | None = None
    self._mailbox_id: int | None = None

  def _write_response(self, code: Literal[b"OK"] | Literal[b"NO"] | Literal[b"BAD"], message: bytes):
    assert self._last_tag is not None
    self._writer.write(b"%s %s %s\r\n" % (self._last_tag, code, message))
    self._last_tag = None

  def _write_line(self, line: bytes):
    self._writer.write(line)
    self._writer.write(b"\r\n")

  async def _read_until(self, until: bytes | tuple[bytes, ...], re_validate: bytes, re_flags: int = 0):
    result = await self._reader.readuntil(until)
    if re.fullmatch(re_validate, result, re_flags) is None:
      raise IMAPCommandFailedError("Invalid sequence read by read_until!")
    return result[:-len(until)]

  async def _read_end_line(self):
    await self._read_until(b"\r\n", br"\r\n")

  async def _read_const(self, seq: bytes):
    res = await self._reader.readexactly(len(seq))
    if res != seq:
      raise IMAPCommandFailedError(f"Not all elements matched! {res} != {seq}!")

  async def _read_line_str(self):
    return (await self._reader.readuntil(b"\r\n"))[:-2].decode()

  async def _read_nstring_sp(self) -> bytes | None:
    pass

  async def _read_astring_sp(self) -> bytes:
    pass

  async def _command_capability(self):
    self._write_line(b"* CAPABILITY IMAP4rev2 AUTH=PLAIN")
    self._write_response(b"OK", b"CAPABILITY completed")

  async def _command_noop(self):
    if self._mailbox_id is not None:
      raise NotImplementedError("Need to implement polling updates")
    else:
      self._write_response(b"OK", b"NOOP completed")

  async def _command_logout(self):
    self._write_line(b"* BYE Server logging out")
    self._write_response(b"OK", b"LOGOUT completed")

  async def _command_login(self):
    userid = await self._read_astring_sp()
    password = await self._read_astring_sp()
    await self._read_end_line()
    if (login_account:=authenticate(self._config, userid, password)) is None:
      self._write_response(b"NO", b"login failed")
    else:
      await self._open_remote(login_account)
      self._write_response(b"OK", b"login completed")

  async def _command_authenticate(self):
    try: await self._read_const(b"PLAIN")
    except IMAPCommandFailedError as e: raise IMAPCommandFailedError(b"Only plain auth supported for now!", e)
    await self._read_end_line()
    self._write_line(b"+ login data")
    auth_line = await self._read_line_str()
    if (login_account:=authenticate_sasl(self._config, auth_line)) is None:
      self._write_response(b"NO", b"auth failed")
    else:
      await self._open_remote(login_account)
      self._write_response(b"OK", b"auth completed")

  async def _command_subscribe(self):
    _ = await self._read_until(b"\r\n", br".*\r\n")
    self._write_response(b"OK", b"SUBSCRIBE completed")

  async def _command_unsubscribe(self):
    _ = await self._read_until(b"\r\n", br".*\r\n")
    self._write_response(b"NO", b"UNSUBSCRIBE not allowed")

  async def _command_idle(self):
    self._write_line(b"+ idling")
    if self._mailbox_id is not None:
      raise NotImplementedError("Implement waiting for messages")
    while (await self._read_line_str()) != "DONE": pass
    self._write_response(b"OK", b"IDLE completed")

  async def _command_status(self):
    mailbox = await self._read_nstring_sp()
    await self._read_const(b"(")
    attrs = (await self._read_until(b")", rb"[A-Z ]+\)")).split(b" ")
    await self._read_end_line()
    account = self._config.accounts[0]
    if account is None:
      return self._write_response(b"NO", b"invalid state")

    with db_open(self._config.db_path) as db:
      tmailbox_id = self._mailbox_id if mailbox is None else db_mailbox_id(db, account.key, mailbox)
      if tmailbox_id is None:
        return self._write_response(b"NO", b"invalid mailbox name")

      response: dict[bytes, int] = {}
      if b"MESSAGES" in attrs:
        response[b"MESSAGES"] = db_status_messages(db, tmailbox_id)
      if b"UIDNEXT" in attrs:
        response[b"UIDNEXT"] = db_status_uid_next(db, account.key, tmailbox_id)
      if b"UIDVALIDITY" in attrs:
        response[b"UIDVALIDITY"] = db_status_uid_validity(db, account.key, tmailbox_id)
      if b"UNSEEN" in attrs:
        response[b"UNSEEN"] = db_status_unseen(db, tmailbox_id)
      if b"DELETED" in attrs:
        response[b"DELETED"] = db_status_deleted(db, tmailbox_id)
      if b"SIZE" in attrs:
        response[b"SIZE"] = db_status_size(db, tmailbox_id)

      status_str = b" ".join(b"%s %d" % (k, v) for k, v in response.items())
      self._write_line(b"* STATUS %s (%s)" % (mailbox or b"NIL", status_str))
    self._write_response(b"OK", b"status completed")

  async def _command_template(self): pass

  async def _open_remote(self, account: Account):
    if self._remote_connection is not None:
      await self._remote_connection.shutdown()
    self._remote_connection = await IMAPRemoteConnection.open(self._config, account)

  async def _handle_command(self):
    self._last_tag = await self._read_until(b" ", br"[^ ]+ ") # TODO better validation
    command = await self._read_until((b" ", b"\r\n"), br"[^\s]+( |(\r\n))") # TODO better validation
    logging.debug("Client: " + self._last_tag.decode() + " " + command.decode())

    match command:
      case b"CAPABILITY": await self._command_capability()
      case b"NOOP": await self._command_noop()
      case b"LOGOUT": await self._command_logout()
      case b"LOGIN": await self._command_login()
      case b"AUTHENTICATE": await self._command_authenticate()
      case b"SUBSCRIBE": await self._command_subscribe()
      case b"UNSUBSCRIBE": await self._command_unsubscribe()
      case b"IDLE": await self._command_idle()
      case b"STATUS": await self._command_status()
      case b"STARTTLS": self._write_response(b"NO", b"tls not available!")

  async def run(self):
    self._write_line(b"220 %s Ready" % (self._config.domain.encode("ASCII"),))
    try:
      while not self._reader.at_eof():
        try:
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
