import functools, asyncio, logging, argparse, pathlib, json, webbrowser, urllib.parse, http.server, ssl, importlib.resources
from mailproxy.config import AuthenticationOAUTH2, Config, TLSMode
from mailproxy.imap import IMAPClient, handle_imap
from mailproxy.auth import oauth_fetch_access_token_with_refresh_token, oauth_get_authorization_url, oauth_fetch_access_token_with_authorization_code
from mailproxy.smtp import smtp_server_handle_client

async def exec_run(config: Config):
  async with asyncio.TaskGroup() as tg:
    smtp_server = await asyncio.start_server(functools.partial(smtp_server_handle_client, config), config.host, config.smtp_port)
    tg.create_task(smtp_server.serve_forever(), name="SMTP server")

    imap_server = await asyncio.start_server(functools.partial(handle_imap, config), config.host, config.imap_port)
    tg.create_task(imap_server.serve_forever(), name="IMAP server")
  

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
