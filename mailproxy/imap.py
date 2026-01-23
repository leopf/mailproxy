from mailproxy.db import db_mailbox_id, db_open, db_status_deleted, db_status_messages, db_status_size, \
    db_status_uid_next, db_status_uid_validity, db_status_unseen
import asyncio, base64, logging, ssl, re, enum, mailproxy.parser as P
from mailproxy.auth import authenticate, authenticate_sasl
from mailproxy.config import Account, Config, TLSMode
from mailproxy.utils import match_line

class DataMissingError(Exception):
  def __init__(self, n: int) -> None:
    super().__init__()
    self.n = n

class IMAPError(Exception): pass

class IMAPReader:
  def __init__(self, reader: asyncio.StreamReader) -> None:
    self._reader = reader

  async def read_until(self, until: bytes, re_validate: bytes, re_flags: int = 0):
    result = await self._reader.readuntil(until)
    if re.fullmatch(re_validate, result, re_flags) is None:
      raise IMAPError("Invalid sequence read by read_until!")
    return result[:-len(until)]

  async def end_line(self):
    await self.read_until(b"\r\n", br"\r\n")

  async def read_opening(self):
    tag = await self.read_until(b" ", br"[^ ]+ ") # TODO better validation
    command = await self.read_until(b" ", br"[^ ]+ ") # TODO better validation
    return tag, command

  async def read_const(self, seq: bytes):
    res = await self._reader.readexactly(len(seq))
    if res != seq:
      raise IMAPError(f"Not all elements matched! {res} != {seq}!")

  async def read_line_str(self):
    return (await self._reader.readuntil(b"\r\n"))[:-2].decode()

  async def read_nstring(self) -> bytes | None:
    pass

  async def read_astring_sp(self) -> bytes:
    pass

  async def read_address(self):
    await self.read_const(b"(")
    name = await self.read_nstring()
    await self.read_const(b" ")
    adl = await self.read_nstring()
    await self.read_const(b" ")
    mailbox = await self.read_nstring()
    await self.read_const(b" ")
    host = await self.read_nstring()
    await self.read_const(b")")

def literal_parser(s: bytes):
  m = re.match(rb"\{(?P<n>\d+)\}\r\n", s, re.DOTALL)
  if m is None:
    raise P.TryParseError("failed to parse literal", s)

  n = int(m.group("n"))
  data_start = m.end()
  missing_n = n - len(s) + data_start
  if missing_n > 0:
    raise DataMissingError(missing_n)
  return s[data_start:data_start + n], s[data_start + n:]

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

class IMAPState(enum.Enum):
  NotAuthenticated = 1
  Authenticated = 2
  Selected = 3

async def handle_imap(config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
  imap_reader = IMAPReader(reader)

  def write_line(line: str):
    writer.write(line.encode("ascii"))
    writer.write(b"\r\n")

  state: IMAPState = IMAPState.NotAuthenticated
  account: Account | None = None
  mailbox_id: int | None = None

  try:
    write_line(f"220 {config.domain} Ready")
    # TODO state validation!
    while not reader.at_eof():
      tag, command = await imap_reader.read_opening()
      logging.debug("Client: " + tag.decode() + " " + command.decode())

      if command == b"CAPABILITY":
        await imap_reader.end_line()
        write_line("* CAPABILITY IMAP4rev2 AUTH=PLAIN")
        write_line(f"{tag} OK CAPABILITY completed")
      elif command == b"NOOP":
        await imap_reader.end_line()
        if state is IMAPState.Selected:
          raise NotImplementedError("Need to implement polling updates")
        else:
          write_line(f"{tag} OK NOOP completed")
      elif command == b"LOGOUT":
        await imap_reader.end_line()
        write_line("* BYE Server logging out")
        write_line(f"{tag} OK LOGOUT completed")
      elif command == b"STARTTLS":
        await imap_reader.end_line()
        write_line(f"{tag} NO Failed")
      elif command == b"LOGIN":
        userid = await imap_reader.read_astring_sp()
        password = await imap_reader.read_astring_sp()
        await imap_reader.end_line()
        if authenticate(config, userid, password):
          write_line(f"{tag} OK Success")
        else:
          write_line(f"{tag} NO Failed")
      elif command == b"AUTHENITCATE":
        try: await imap_reader.read_const(b"PLAIN")
        except IMAPError as e: raise IMAPError(b"Only plain auth supported for now!", e)
        await imap_reader.end_line()
        write_line("+")
        auth_line = await imap_reader.read_line_str()
        if authenticate_sasl(config, auth_line):
          write_line(f"{tag} OK Success")
        else:
          write_line(f"{tag} NO Failed")
      elif command == b"SUBSCRIBE":
        _ = await imap_reader.read_until(b"\r\n", br".*\r\n")
        write_line(f"{tag} OK SUBSCRIBE completed")
      elif command == b"UNSUBSCRIBE":
        _ = await imap_reader.read_until(b"\r\n", br".*\r\n")
        write_line(f"{tag} NO UNSUBSCRIBE not allowed")
      elif command == b"IDLE": pass # TODO: tag wont event be parsed correctly...
      elif command == b"STATUS":
        mailbox = await imap_reader.read_nstring()
        await imap_reader.read_const(b"(")
        attrs = (await imap_reader.read_until(b")", rb"[A-Z ]+\)")).split(b" ")
        await imap_reader.end_line()
        account = config.accounts[0]
        if account is None:
          write_line(f"{tag} NO invalid state")
          continue
        with db_open(config.db_path) as db:
          if mailbox is None:
            tmailbox_id = mailbox_id
          else:
            tmailbox_id = db_mailbox_id(db, mailbox)
          if tmailbox_id is None:
            write_line(f"{tag} NO invalid mailbox name")
            continue

          response: dict[str, int] = {}
          if "MESSAGES" in attrs:
            response["MESSAGES"] = db_status_messages(db, account.key, mailbox_id)
          if "UIDNEXT" in attrs:
            response["UIDNEXT"] = db_status_uid_next(db, account.key, mailbox_id)
          if "UIDVALIDITY" in attrs:
            response["UIDVALIDITY"] = db_status_uid_validity(db, account.key, mailbox_id)
          if "UNSEEN" in attrs:
            response["UNSEEN"] = db_status_unseen(db, account.key, mailbox_id)
          if "DELETED" in attrs:
            response["DELETED"] = db_status_deleted(db, account.key, mailbox_id)
          if "SIZE" in attrs:
            response["SIZE"] = db_status_size(db, account.key, mailbox_id)

          status_str = " ".join(f"{k} {v}" for k, v in response.items())
          write_line(f"* STATUS {mailbox} ({status_str})")
        write_line(f"{tag} OK status completed")


      elif command == b"SELECT": pass

      if (m:=match_line(r"(?P<mode>(SELECT|EXAMINE)) (?P<mailbox>.*)", line)):
        raise NotImplementedError()
        mode = "" # CLOSED, READ-ONLY, READ-WRITE
        write_line("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")
        write_line(f"{tag} OK [{mode}] SELECT completed")
      elif (m:=match_line(r"CREATE (?P<mailbox>.*)", line)):
        raise NotImplementedError()
        # TODO create mailbox, respond no if not allowed or exists
        write_line(f"{tag} OK CREATE completed")
      elif (m:=match_line(r"DELETE (?P<mailbox>.*)", line)):
        raise NotImplementedError()
        # TODO delete mailbox, respond no if not allowed or not exists
        write_line(f"{tag} OK DELETE completed")
      elif (m:=match_line(r"RENAME (?P<mailbox>.*)", line)):
        raise NotImplementedError()
        # TODO rename mailbox
        write_line(f"{tag} OK RENAME completed")

      else:
        write_line(f"{tag} NO failed to run command (wrong state or parsing error)")


  except Exception as e:
    logging.error("connection closing because of an error", e)
  finally:
    logging.debug("connection closed")
    writer.close()
