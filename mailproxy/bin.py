import functools, asyncio, re, logging, base64, enum, argparse, pathlib, json, webbrowser, urllib.parse, http.server, ssl, \
  importlib.resources

from mailproxy.config import AuthenticationOAUTH2, Config
from mailproxy.oauth import oauth_fetch_access_token_with_refresh_token, oauth_get_authorization_url, oauth_fetch_access_token_with_authorization_code

def match_line(pattern: str, line: str, flags: int = re.I):
  m = re.fullmatch(pattern, line, flags)
  if m is None: return None
  else: return { "": "" } | m.groupdict()

def smtp_forward_mail(config: Config, sender: str, recipients: tuple[str, ...], data: bytes):
  print("FORWARDING:", data.decode())

def authenticate_sasl(sasl_b64: str):
  data = base64.b64decode(sasl_b64).split(b"\0")
  return authenticate(data[1].decode(), data[1].decode())

def authenticate(username: str, password: str) -> bool:
  print("try auth", username, password)
  return True

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
        if (b64_match:=match_line(r"(?P<data>[a-z0-9\+\/]*(=|==)?)", await read_line())) and authenticate_sasl(b64_match["data"]):
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

async def handle_smtp(config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
  def write_line(line: str):
    writer.write(line.encode("ascii"))
    writer.write(b"\r\n")
  
  def reply(code: int, textstring: str):
    if not re.fullmatch(r'[\t\x20-\x7E]+', textstring):
      raise ValueError("Invalid reply!", code, textstring)

    write_line(f"{code} {textstring}")

  authenticated: bool = False
  sender: str = ""
  recipients: list[str] = []

  try:
    write_line(f"220 {config.domain} Ready" )

    while not reader.at_eof():
      line = (await reader.readuntil(b"\r\n"))[:-2].decode("ascii").strip()
      if line == "":
        continue
      
      logging.debug("reading line: " + line)

      if match_line(r"QUIT", line):
        reply(221, f"{config.domain} closing transmission channel")
        return
      elif (m:=match_line(r"HELO (?P<domain>.*)\s*", line)):
        logging.debug("HELO connected from domain: " + m["domain"])
        reply(250, config.domain)
      elif ((m:=match_line(r"EHLO (?P<domain>.*)\s*", line))):
        logging.debug("EHLO connected from domain: " + m["domain"])
        write_line(f"250-{config.domain} hello")
        write_line("250 AUTH PLAIN") # space for last!
      elif match_line(r"NOOP(\s.*)?", line):
        reply(250, "OK")
      elif match_line(r"RSET", line):
        logging.debug("resetting connection")
        sender = ""
        recipients.clear()
        reply(250, "OK")

      # authorization
      elif (m:=match_line(r"AUTH PLAIN (?P<data>[a-z0-9\+\/]*(=|==)?)", line)):
        if authenticate_sasl(m["data"]):
          reply(235, "2.7.0  Authentication Succeeded")
          authenticated = True
        else:
          authenticated = False
          reply(535, "5.7.8  Authentication credentials invalid")

      # following is only stuff allowed in auth
      elif authenticated and (m:=match_line(r"MAIL FROM:<(?P<mailbox>.*)>( AUTH=.*)?", line)):
        logging.debug("sending mail from mailbox: " + m["mailbox"])
        sender = m["mailbox"]
        recipients.clear()
        reply(250, "OK")
      elif authenticated and (m:=match_line(r"RCPT TO:<(?P<recipient>.*)>", line)):
        logging.debug("added recipient: " + m["recipient"])
        recipients.append(m["recipient"])
        reply(250, "OK")
      elif authenticated and match_line(f"DATA", line):
        reply(354, "Start mail input; end with <CRLF>.<CRLF>")
        mail_data = (await reader.readuntil(b"\r\n.\r\n"))[:-5]
        try:
          await asyncio.to_thread(smtp_forward_mail, config, sender, tuple(recipients), mail_data)
          reply(250, "OK")
        except Exception as e:
          logging.error("failed to send message", e)
          reply(451, "local error in processing")
        finally:
          sender = ""
          recipients.clear()
      elif authenticated and match_line(r"VRFY (?P<user>.*)", line):
        raise NotImplementedError("https://datatracker.ietf.org/doc/html/rfc5321#section-3.5")
        """
        if name is allowed, get mailbox name and return with 250 inside <>
        if not, return 553 with message
        """
        reply(250, "OK")
      else:
        reply(500, "unknown")

  except Exception as e:
    logging.error("connection closing because of an error", e)
  finally:
    logging.debug("connection closed")
    writer.close()

async def exec_run(config: Config):
  async with asyncio.TaskGroup() as tg:
    smtp_server = await asyncio.start_server(functools.partial(handle_smtp, config), config.host, config.smtp_port)
    tg.create_task(smtp_server.serve_forever(), name="SMTP server")

    imap_server = await asyncio.start_server(functools.partial(handle_imap, config), config.host, config.imap_port)
    tg.create_task(imap_server.serve_forever(), name="IMAP server")

class TLSMode(enum.Enum):
  DIRECT = "DIRECT"
  STARTTLS = "STARTTLS"
  NONE = "NONE"

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
  

async def exec_dev(config_path: pathlib.Path):
  logging.basicConfig(level=logging.DEBUG)

  config = json.loads(config_path.read_text())
  # TODO validate...

  client = await IMAPClient.connect(config["imap"]["host"], config["imap"]["port"], TLSMode(config["imap"]["tlsmode"].upper()))
  capabilities = await client.capability()
  assert "AUTH=XOAUTH2" in capabilities
  
  await client.authenticate_xoauth2(config["email"], config["access_token"])
  print(await client.list("", ""))

def exec_get_access_token(config: Config, address: str):
  try:
    account = next(account for account in config.accounts if address in account.addresses)
  except StopIteration:
    raise RuntimeError(f"config has no account for address '{address}'")  
  
  auth = account.auth
  if not isinstance(auth, AuthenticationOAUTH2):
    raise RuntimeError("authentication for account must be oauth2 for login")

  access_token_result = oauth_fetch_access_token_with_refresh_token(auth, auth.initial_refresh_token)

  print("success, we have an access and refresh token :)")
  print("expires at: ", str(access_token_result.expires_at))
  print("access token: ", access_token_result.access_token)
  print("refresh token: ", access_token_result.refresh_token)

def exec_login(config: Config, address: str):
  try:
    account = next(account for account in config.accounts if address in account.addresses)
  except StopIteration:
    raise RuntimeError(f"config has no account for address '{address}'")  
  
  auth = account.auth
  if not isinstance(auth, AuthenticationOAUTH2):
    raise RuntimeError("authentication for account must be oauth2 for login")

  try:
    redirection_endpoint: urllib.parse.ParseResult = urllib.parse.urlparse(auth.redirect_url)
  except:
    raise ValueError("Invalid redirect url!")
  
  if redirection_endpoint.hostname is None:
    raise ValueError("hostname of redirect url is None")
  
  if redirection_endpoint.port is None:
    raise ValueError("port of redirect url is None")

  webbrowser.open(oauth_get_authorization_url(auth))

  authorization_code: None | str = None

  class AuthorizationHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
      nonlocal authorization_code
      parsed_url = urllib.parse.urlparse(self.path)
      parsed_qs = urllib.parse.parse_qs(parsed_url.query)
      authorization_code = next(iter(parsed_qs.get("code", [])), None)
      body = b"no code" if authorization_code is None else b"success"
      self.send_response(200)
      self.send_header("Content-Type", "text/plain; charset=utf-8")
      self.send_header("Content-Length", str(len(body)))
      self.end_headers()
      self.wfile.write(body)

  auth_server = http.server.HTTPServer((redirection_endpoint.hostname, redirection_endpoint.port), AuthorizationHandler)

  if redirection_endpoint.scheme == "https":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    with importlib.resources.path("mailproxy.assets", "dummy-cert.pem") as cert_path, importlib.resources.path("mailproxy.assets", "dummy-key.pem") as key_path:
      ctx.load_cert_chain(cert_path, key_path)
    auth_server.socket = ctx.wrap_socket(auth_server.socket, server_side=True)

  while authorization_code is None:
    auth_server.handle_request()

  access_token_result = oauth_fetch_access_token_with_authorization_code(auth, authorization_code)

  print("success, we have an access and refresh token :)")
  print("expires at: ", str(access_token_result.expires_at))
  print("access token: ", access_token_result.access_token)
  print("refresh token: ", access_token_result.refresh_token)

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)

  subparsers = parser.add_subparsers(dest="command")
  
  run_parser = subparsers.add_parser("run")

  login_parser = subparsers.add_parser("login")
  login_parser.add_argument("--address", "-A", help="email address", required=True, type=str)
  
  get_token_parser = subparsers.add_parser("get-token")
  get_token_parser.add_argument("--address", "-A", help="email address", required=True, type=str)

  # ----
  
  args = parser.parse_args()

  config = Config.from_dict(json.loads(args.config.read_text()))
  logging.basicConfig(level=config.log_level)

  if args.command == "run":
    asyncio.run(exec_run(config))
  elif args.command == "login":
    exec_login(config, args.address)
  elif args.command == "get-access-token":
    exec_get_access_token(config, args.address)
  elif args.command == "dev":
    asyncio.run(exec_dev(args.config))
  else:
    raise RuntimeError("unknown command!")
