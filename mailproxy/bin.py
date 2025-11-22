import functools, asyncio, dataclasses, re, logging, base64, enum, argparse, pathlib, json, webbrowser, urllib.parse, http.server, ssl, \
  importlib.resources, urllib.request, urllib.error

def match_line(pattern: str, line: str, flags: int = re.I):
  m = re.fullmatch(pattern, line, flags)
  if m is None: return None
  else: return { "": "" } | m.groupdict()

@dataclasses.dataclass
class Config:
  database_path: str
  domain: str # verify!!
  log_level: int = logging.ERROR
  host: str = "127.0.0.1"
  IMAP_port: int = 143
  SMTP_port: int = 587

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

async def exec_run():
  config = Config(
    log_level=logging.DEBUG,
    database_path="/tmp/mailproxy.sqlite",
    domain="example.com",
    SMTP_port=1587,
    IMAP_port=1143,
  )

  logging.basicConfig(level=config.log_level)

  async with asyncio.TaskGroup() as tg:
    smtp_server = await asyncio.start_server(functools.partial(handle_smtp, config), config.host, config.SMTP_port)
    tg.create_task(smtp_server.serve_forever(), name="SMTP server")

    imap_server = await asyncio.start_server(functools.partial(handle_imap, config), config.host, config.IMAP_port)
    tg.create_task(imap_server.serve_forever(), name="IMAP server")

def exec_get_token(config_path: pathlib.Path):
  config = json.loads(config_path.read_text())

  token_data = f"client_id={urllib.parse.quote(config["client_id"])}&scope={urllib.parse.quote(config["scope"])}" + \
    f"&refresh_token={urllib.parse.quote(config["refresh_token"])}&grant_type=refresh_token"
  if "client_secret" in config:
    token_data += f"&client_secret={urllib.parse.quote(config["client_secret"])}"

  token_request = urllib.request.Request(
    config["token_endpoint"], 
    data=token_data.encode(), 
    method="POST", 
    headers={
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json",
    }
  )

  try:
    with urllib.request.urlopen(token_request) as resp:
      response_json = json.loads(resp.read())
      if response_json["token_type"] != "Bearer":
        raise RuntimeError(f"wrong token response token_type: '{response_json["token_type"]}'") # sanity check      
      
      from datetime import datetime, timedelta
      print("valid until: ", str(datetime.now() + timedelta(seconds=response_json["expires_in"])))
      print("access_token: ", response_json["access_token"])

  except urllib.request.HTTPError as e:
    print("failed to get refresh token: ", e.read())


def exec_login(config_path: pathlib.Path):
  config = json.loads(config_path.read_text())

  if "authorization_endpoint" not in config or not isinstance(config["authorization_endpoint"], str):
    raise ValueError("""expected "authorization_endpoint" to be a str""")
  
  if "client_id" not in config or not isinstance(config["client_id"], str):
    raise ValueError("""expected "client_id" to be a str""")
  
  if "authorization_endpoint" not in config or not isinstance(config["authorization_endpoint"], str):
    raise ValueError("""expected "authorization_endpoint" to be a str""")
  
  if "redirection_endpoint" not in config or not isinstance(config["redirection_endpoint"], str):
    raise ValueError("""expected "client_id" to be a str""")
  
  try:
    redirection_endpoint: urllib.parse.ParseResult = urllib.parse.urlparse(config["redirection_endpoint"])
  except:
    raise ValueError("Invalid redirect url!")

  if redirection_endpoint.hostname not in ("localhost", "127.0.0.1"): # overly restrictive
    raise ValueError("Invalid redirect url!")

  if "scope" not in config or not isinstance(config["scope"], str):
    raise ValueError("""expected "scope" to be a list of strings""")


  provider_query_base = f"client_id={urllib.parse.quote(config["client_id"])}&redirect_uri={urllib.parse.quote(redirection_endpoint.geturl())}" + \
    f"&scope={urllib.parse.quote(config["scope"])}"

  authorize_url = f"{config["authorization_endpoint"]}?{provider_query_base}&response_type=code&response_mode=query"
    
  webbrowser.open(authorize_url)

  authorization_code: None | str = None# "M.C550_BL2.2.U.3f285045-c0c4-3f70-3ff3-732caa3f868c"

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

  auth_server = http.server.HTTPServer((redirection_endpoint.hostname, int(redirection_endpoint.port or 80)), AuthorizationHandler)

  if redirection_endpoint.scheme == "https":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    with importlib.resources.path("mailproxy.assets", "dummy-cert.pem") as cert_path, importlib.resources.path("mailproxy.assets", "dummy-key.pem") as key_path:
      ctx.load_cert_chain(cert_path, key_path)
    auth_server.socket = ctx.wrap_socket(auth_server.socket, server_side=True)

  while authorization_code is None:
    auth_server.handle_request()

  token_data = f"{provider_query_base}&code={urllib.parse.quote(authorization_code)}&grant_type=authorization_code"
  if "client_secret" in config:
    token_data += f"&client_secret={urllib.parse.quote(config["client_secret"])}"

  token_request = urllib.request.Request(
    config["token_endpoint"], 
    data=token_data.encode(), 
    method="POST", 
    headers={
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json",
    }
  )

  try:
    with urllib.request.urlopen(token_request) as resp:
      response_json = json.loads(resp.read())
      if response_json["token_type"] != "Bearer":
        raise RuntimeError(f"wrong token response token_type: '{response_json["token_type"]}'") # sanity check      
      config["refresh_token"] = response_json["refresh_token"]

  except urllib.request.HTTPError as e:
    print("failed to get refresh token: ", e.read())

  config_path.write_text(json.dumps(config, indent=4))

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  subparsers = parser.add_subparsers(dest="command")

  run_parser = subparsers.add_parser("run")

  login_parser = subparsers.add_parser("login")
  login_parser.add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)
  
  get_token_parser = subparsers.add_parser("get-token")
  get_token_parser.add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)

  args = parser.parse_args()

  if args.command == "run":
    asyncio.run(exec_run())
  elif args.command == "login":
    exec_login(args.config)
  elif args.command == "get-token":
    exec_get_token(args.config)
  else:
    raise RuntimeError("unknown command!")
