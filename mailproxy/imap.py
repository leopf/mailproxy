from typing import Literal
from mailproxy.db import db_mailbox_id, db_open, db_status_deleted, db_status_messages, db_status_size, \
    db_status_uid_next, db_status_uid_validity, db_status_unseen
import asyncio, base64, logging, ssl, re, enum, mailproxy.parser as P
from mailproxy.auth import account_get_oauth_access_token, authenticate, authenticate_sasl
from mailproxy.config import Account, AuthenticationOAUTH2, AuthenticationPLAIN, Config, TLSMode
from mailproxy.utils import match_line, match_lineb

class IMAPCommandFailedError(Exception): pass

class IMAPClient:
  def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    self._reader = reader
    self._writer = writer
    self._command_counter = 0
    self.capabilities: tuple[str, ...] = ()

  async def init(self):
    logging.debug("IMAP init: " + await self._read_line())
    caps: list[str] = []
    rid = self._command("CAPABILITY")
    async for uline in self._read_returns(rid):
      if (m:=match_line(r"\*\s+CAPABILITY(?P<caps>(\s+[^\s]+)*)", uline)):
        caps.extend(re.split(r"\s+",  m["caps"].strip()))
    self.capabilities = tuple(caps)

  async def authenticate_xoauth2(self, email: str, access_token: str):
    rid = self._command("AUTHENTICATE XOAUTH2")
    if not (await self._read_line()).startswith("+"):
      raise RuntimeError("Invalid response from server!")
    self._writer.write(base64.b64encode(f"user={email}\1auth=Bearer {access_token}\1\1".encode()))
    self._writer.write(b"\r\n")
    async for _ in self._read_returns(rid): pass

  async def list(self, refname: str, mailbox: str):
    if "\"" in refname or "\"" in mailbox:
      raise ValueError("neither base or search can have quote!")

    rid = self._command(f"LIST \"{refname}\" \"{mailbox}\"")
    mailboxes: list[tuple[str, str]] = []

    async for uline in self._read_returns(rid):
      if (m:=match_line(r"\*\s+LIST\s+\((?P<attributes>[^\)]*)\)\s+\"(?P<delimiter>)\"\s+(?P<mailbox>(INBOX)|)", uline)):
        print(m["rest"])

  async def start_tls(self):
    rid = self._command("STARTTLS")
    raise NotImplementedError()

  async def _read_returns(self, rid: int):
    end_linestart = str(rid) + " "
    while not (line := await self._read_line()).startswith(end_linestart):
      yield line

    result = match_line(r"[^ ]+ (?P<code>[^ ]+) (?P<text>.*)", line)
    assert result is not None
    if result["code"] != "OK":
      raise Exception(f"IMAP failed with code '{result['code']}' and message: {result['text']}")

    logging.debug("IMAP command completed: " + line)

  async def _read_line(self):
    line = (await self._reader.readuntil(b"\r\n"))[:-2]
    chunks: list[str] = []
    index = 0
    while index < len(line):
      next_and = line.find(b"&", index)
      if next_and == -1:
        chunks.append(line[index:].decode())
        index = len(line)
      else:
        chunks.append(line[index:next_and].decode())
        end_index = line.find(b"-", next_and + 1)
        chunks.append(base64.b64decode(line[next_and + 1:end_index] + b"=" * (((5 - end_index + next_and) % 4) % 4)).decode("utf-16-be"))
        index = end_index + 1
    return ''.join(chunks)

  def _command(self, line: str):
    self._command_counter += 1
    self._writer.write(str(self._command_counter).encode())
    self._writer.write(b" ")
    self._writer.write(line.encode())
    self._writer.write(b"\r\n")
    return self._command_counter

  @staticmethod
  async def connect(account: Account):
    ssl_param = ssl.create_default_context() if account.imap_tlsmode == TLSMode.DIRECT else None
    reader, writer = await asyncio.open_connection(account.imap_host, account.imap_port, ssl=ssl_param)
    client = IMAPClient(reader, writer)
    await client.init()
    if account.imap_tlsmode == TLSMode.STARTTLS:
      await client.start_tls()
    return client


class IMAPRemoteConnection:
  def __init__(self, config: Config, account: Account, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    self._config = config
    self._account = account
    self._reader = reader
    self._writer = writer
    self._command_counter = 0
    self._use_imb_cte = True
    self._capabilities: list[bytes] = []

  async def _init(self):
    logging.debug("IMAP init: " + (await self._read_line()).decode())
    self._capabilities = await self._command_capabilities()
    if self._account.imap_tlsmode == TLSMode.STARTTLS:
      if b"STARTTLS" not in self._capabilities:
        raise IMAPCommandFailedError("STARTTLS required by account but not supported by remote!")
      await self._command_starttls()
      self._capabilities = await self._command_capabilities()

    enable_imap4_rev2 = b"IMAP4rev2" in self._capabilities
    self._use_imb_cte = not enable_imap4_rev2
    if enable_imap4_rev2:
      self._start_command(b"ENABLE IMAP4rev2")
      await self._read_until_response()

    if isinstance(self._account.auth, AuthenticationOAUTH2):
      with db_open(self._config.db_path) as db:
        access_token = account_get_oauth_access_token(db, self._account)
      await self._command_authenticate(b"XOAUTH2", f"user={self._account.addresses[0]}\1auth=Bearer {access_token}\1\1".encode())
    elif isinstance(self._account.auth, AuthenticationPLAIN):
      await self._command_authenticate(b"PLAIN", b"%s\0%s" % (self._account.addresses[0].encode(), self._account.auth.password.encode()))

  async def _command_authenticate(self, auth_type: bytes, auth_data: bytes):
    # TODO check if supported
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
    pass

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
    self.config = config
    self.reader = reader
    self.writer = writer

    self.last_tag: bytes | None = None
    self.account: Account | None = None
    self.mailbox_id: int | None = None

  def write_response(self, code: Literal[b"OK"] | Literal[b"NO"] | Literal[b"BAD"], message: bytes):
    assert self.last_tag is not None
    self.writer.write(b"%s %s %s\r\n" % (self.last_tag, code, message))
    self.last_tag = None

  def write_line(self, line: bytes):
    self.writer.write(line)
    self.writer.write(b"\r\n")

  async def read_until(self, until: bytes | tuple[bytes, ...], re_validate: bytes, re_flags: int = 0):
    result = await self.reader.readuntil(until)
    if re.fullmatch(re_validate, result, re_flags) is None:
      raise IMAPCommandFailedError("Invalid sequence read by read_until!")
    return result[:-len(until)]

  async def read_end_line(self):
    await self.read_until(b"\r\n", br"\r\n")

  async def read_const(self, seq: bytes):
    res = await self.reader.readexactly(len(seq))
    if res != seq:
      raise IMAPCommandFailedError(f"Not all elements matched! {res} != {seq}!")

  async def read_line_str(self):
    return (await self.reader.readuntil(b"\r\n"))[:-2].decode()

  async def read_nstring_sp(self) -> bytes | None:
    pass

  async def read_astring_sp(self) -> bytes:
    pass

  async def command_capability(self):
    self.write_line(b"* CAPABILITY IMAP4rev2 AUTH=PLAIN")
    self.write_response(b"OK", b"CAPABILITY completed")

  async def command_noop(self):
    if self.mailbox_id is not None:
      raise NotImplementedError("Need to implement polling updates")
    else:
      self.write_response(b"OK", b"NOOP completed")

  async def command_logout(self):
    self.write_line(b"* BYE Server logging out")
    self.write_response(b"OK", b"LOGOUT completed")

  async def command_login(self):
    userid = await self.read_astring_sp()
    password = await self.read_astring_sp()
    await self.read_end_line()
    if (login_account:=authenticate(self.config, userid, password)) is None:
      self.write_response(b"NO", b"login failed")
    else:
      self.account = login_account
      self.write_response(b"OK", b"login completed")

  async def command_authenticate(self):
    try: await self.read_const(b"PLAIN")
    except IMAPCommandFailedError as e: raise IMAPCommandFailedError(b"Only plain auth supported for now!", e)
    await self.read_end_line()
    self.write_line(b"+ login data")
    auth_line = await self.read_line_str()
    if (login_account:=authenticate_sasl(self.config, auth_line)) is None:
      self.write_response(b"NO", b"auth failed")
    else:
      self.account = login_account
      self.write_response(b"OK", b"auth completed")

  async def command_subscribe(self):
    _ = await self.read_until(b"\r\n", br".*\r\n")
    self.write_response(b"OK", b"SUBSCRIBE completed")

  async def command_unsubscribe(self):
    _ = await self.read_until(b"\r\n", br".*\r\n")
    self.write_response(b"NO", b"UNSUBSCRIBE not allowed")

  async def command_idle(self):
    self.write_line(b"+ idling")
    if self.mailbox_id is not None:
      raise NotImplementedError("Implement waiting for messages")
    while (await self.read_line_str()) != "DONE": pass
    self.write_response(b"OK", b"IDLE completed")

  async def command_status(self):
    mailbox = await self.read_nstring_sp()
    await self.read_const(b"(")
    attrs = (await self.read_until(b")", rb"[A-Z ]+\)")).split(b" ")
    await self.read_end_line()
    account = self.config.accounts[0]
    if account is None:
      return self.write_response(b"NO", b"invalid state")

    with db_open(self.config.db_path) as db:
      tmailbox_id = self.mailbox_id if mailbox is None else db_mailbox_id(db, account.key, mailbox)
      if tmailbox_id is None:
        return self.write_response(b"NO", b"invalid mailbox name")

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
      self.write_line(b"* STATUS %s (%s)" % (mailbox or b"NIL", status_str))
    self.write_response(b"OK", b"status completed")

  async def command_template(self): pass

  async def handle_command(self):
    self.last_tag = await self.read_until(b" ", br"[^ ]+ ") # TODO better validation
    command = await self.read_until((b" ", b"\r\n"), br"[^\s]+( |(\r\n))") # TODO better validation
    logging.debug("Client: " + self.last_tag.decode() + " " + command.decode())

    match command:
      case b"CAPABILITY": await self.command_capability()
      case b"NOOP": await self.command_noop()
      case b"LOGOUT": await self.command_logout()
      case b"LOGIN": await self.command_login()
      case b"AUTHENTICATE": await self.command_authenticate()
      case b"SUBSCRIBE": await self.command_subscribe()
      case b"UNSUBSCRIBE": await self.command_unsubscribe()
      case b"IDLE": await self.command_idle()
      case b"STATUS": await self.command_status()
      case b"STARTTLS": self.write_response(b"NO", b"tls not available!")

  async def run(self):
    self.write_line(b"220 %s Ready" % (self.config.domain.encode("ASCII"),))
    try:
      while not self.reader.at_eof():
        try:
          await self.handle_command()
        except IMAPCommandFailedError:
          self.write_response(b"NO", b"command failed with internal error")
    except Exception as e:
      logging.error("connection closing because of an error", e)
    finally:
      logging.debug("connection closed")
      self.writer.close()

async def handle_imap(config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
  connection = IMAPServerConnection(config, reader, writer)
  await connection.run()
