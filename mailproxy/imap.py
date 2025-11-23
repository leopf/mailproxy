import asyncio, base64, logging, ssl, re, enum
from mailproxy.auth import authenticate_sasl
from mailproxy.config import Config, TLSMode
from mailproxy.utils import match_line

class IMAPClient:
  def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    self._reader = reader
    self._writer = writer
    self._command_counter = 0

  async def init(self):
    logging.debug("IMAP init: " + await self._read_line())

  async def capability(self):
    caps: list[str] = []
    rid = self._command("CAPABILITY")
    async for uline in self._read_returns(rid):
      if (m:=match_line(r"\*\s+CAPABILITY(?P<caps>(\s+[^\s]+)*)", uline)):
        caps.extend(re.split(r"\s+",  m["caps"].strip()))
    return tuple(caps)
  
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
    async for uline in self._read_returns(rid):
      if (m:=match_line(r"\*\s+LIST\s+(?P<rest>.*)", uline)):
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
    return (await self._reader.readuntil(b"\r\n"))[:-2].decode()

  def _command(self, line: str):
    self._command_counter += 1
    self._writer.write(str(self._command_counter).encode())
    self._writer.write(b" ")
    self._writer.write(line.encode())
    self._writer.write(b"\r\n")
    return self._command_counter

  @staticmethod
  async def connect(host: str, port: int, tlsmode: TLSMode):
    ssl_param = ssl.create_default_context() if tlsmode == TLSMode.DIRECT else None
    reader, writer = await asyncio.open_connection(host, port, ssl=ssl_param)
    client = IMAPClient(reader, writer)
    await client.init()
    if tlsmode == TLSMode.STARTTLS:
      await client.start_tls()

    return client
  
class IMAPState(enum.Enum):
  NotAuthenticated = 1
  Authenticated = 2
  Selected = 3

async def handle_imap(config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
  def write_line(line: str):
    writer.write(line.encode("ascii"))
    writer.write(b"\r\n")

  async def read_line():
    return (await reader.readuntil(b"\r\n"))[:-2].decode("utf-8").strip()

  async def parse_line():
    while True:
      line = await read_line()
      pline = match_line(r"(?P<tag>[a-z0-9]+)\s+(?P<rest>.*)", line)
      if pline is None: continue
      return pline["tag"], pline["rest"]

  state: IMAPState = IMAPState.NotAuthenticated

  try:
    write_line(f"220 {config.domain} Ready")

    while not reader.at_eof():
      tag, line = await parse_line()
      logging.debug("Client: " + tag + " " + line)

      if match_line(r"CAPABILITY", line):
        write_line(f"* CAPABILITY IMAP4rev2 AUTH=PLAIN")
        write_line(f"{tag} OK CAPABILITY completed")
      elif match_line(r"NOOP", line):
        if state is IMAPState.Selected:
          raise NotImplementedError("Need to implement polling updates")
        else:
          write_line(f"{tag} OK NOOP completed")
      elif match_line(r"LOGOUT", line):
        write_line("* BYE Server logging out")
        write_line(f"{tag} OK LOGOUT completed")
      elif match_line(r"AUTHENTICATE PLAIN", line):
        write_line("+")
        if (b64_match:=match_line(r"(?P<data>[a-z0-9\+\/]*(=|==)?)", await read_line())) and authenticate_sasl(config, b64_match["data"]):
          write_line(f"{tag} OK Success")
        else:
          write_line(f"{tag} NO Failed")
      elif (m:=match_line(r"(?P<mode>(SELECT|EXAMINE)) (?P<mailbox>.*)", line)):
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
      elif (m:=match_line(r"SUBSCRIBE .*", line)):
        write_line(f"{tag} OK SUBSCRIBE completed")
      elif (m:=match_line(r"UNSUBSCRIBE .*", line)):
        write_line(f"{tag} NO UNSUBSCRIBE not allowed")
      else:
        write_line(f"{tag} NO failed to run command (wrong state or parsing error)")


  except Exception as e:
    logging.error("connection closing because of an error", e)
  finally:
    logging.debug("connection closed")
    writer.close()