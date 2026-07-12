import functools, asyncio, logging, argparse, pathlib, os, dataclasses, webbrowser, urllib.parse, http.server, ssl, importlib.resources
from typing import TypeVar
from mailproxy.config import config_from_dict, oauth_provider_config_from_dict
from mailproxy.db import db_account_add, db_account_get_by_address, db_account_list, db_account_remove, db_open
from mailproxy.imap_backend import IMAPRemoteConnection
from mailproxy.imap_frontend import handle_imap
from mailproxy.auth import account_get_oauth_access_token, oauth_get_authorization_url, oauth_fetch_access_token_with_authorization_code
from mailproxy.smtp_frontend import smtp_server_handle_client
from mailproxy.model import Account, AuthenticationOAUTH2, AuthenticationPLAIN, Config, OAuthProviderConfig, TLSMode
from mailproxy.utils import json_loads_object, is_object_list

T = TypeVar("T")

def _tlsmode(value: str) -> TLSMode:
  return TLSMode(value.upper())

def _load_config(config_path: pathlib.Path) -> Config:
  raw: object = json_loads_object(config_path.read_text())
  config = config_from_dict(raw)
  config = dataclasses.replace(config, proxy_password=os.environ.get("MAILPROXY_PASSWORD", ""))
  logging.basicConfig(level=config.log_level)
  return config

def _load_oauth_config(preset: str | None, oauth_config: pathlib.Path | None) -> OAuthProviderConfig:
  if preset is not None:
    with importlib.resources.path("mailproxy.presets", f"{preset}.json") as p:
      raw: object = json_loads_object(pathlib.Path(p).read_text())
  elif oauth_config is not None:
    raw = json_loads_object(oauth_config.read_text())
  else:
    raise ValueError("either --preset or --oauth-config must be specified")
  return oauth_provider_config_from_dict(raw)

def _account_from_oauth_config(addresses: tuple[str, ...], provider: OAuthProviderConfig, refresh_token: str) -> tuple[Account, str]:
  auth = AuthenticationOAUTH2(
    scope=provider.scope,
    client_id=provider.client_id,
    client_secret=provider.client_secret,
    authorization_base_url=provider.authorization_base_url,
    token_url=provider.token_url,
    redirect_url=provider.redirect_url,
  )
  account = Account(
    addresses=addresses,
    imap_host=provider.imap_host,
    imap_port=provider.imap_port,
    imap_tlsmode=provider.imap_tlsmode,
    smtp_host=provider.smtp_host,
    smtp_port=provider.smtp_port,
    smtp_tlsmode=provider.smtp_tlsmode,
    auth=auth,
  )
  return account, refresh_token

def _add_imap_args(p: argparse.ArgumentParser) -> None:
  _ = p.add_argument("--imap-host")
  _ = p.add_argument("--imap-port", type=int)
  _ = p.add_argument("--imap-tlsmode", type=str.upper, choices=[m.value for m in TLSMode])

def _add_smtp_args(p: argparse.ArgumentParser) -> None:
  _ = p.add_argument("--smtp-host")
  _ = p.add_argument("--smtp-port", type=int)
  _ = p.add_argument("--smtp-tlsmode", type=str.upper, choices=[m.value for m in TLSMode])

def _add_oauth_config_args(p: argparse.ArgumentParser) -> None:
  _ = p.add_argument("--preset", help="preset name (gmail, microsoft, yahoo)")
  _ = p.add_argument("--oauth-config", type=pathlib.Path, help="path to oauth config json")

def _ns_get(args: argparse.Namespace, name: str, expected: type[T]) -> T:
  value: object = getattr(args, name)
  if not isinstance(value, expected):
    raise TypeError(f"expected {expected.__name__} for --{name}")
  return value

def _ns_optional(args: argparse.Namespace, name: str, expected: type[T]) -> T | None:
  value: object = getattr(args, name)
  if value is None:
    return None
  if not isinstance(value, expected):
    raise TypeError(f"expected {expected.__name__} or None for --{name}")
  return value

def _ns_str_list(args: argparse.Namespace, name: str) -> list[str]:
  value: object = getattr(args, name)
  if not is_object_list(value):
    raise TypeError(f"expected list for --{name}")
  result: list[str] = []
  i = 0
  while i < len(value):
    item = value[i]
    if not isinstance(item, str):
      raise TypeError(f"expected str in list --{name}")
    result.append(item)
    i += 1
  return result

async def exec_run(config: Config):
  if not config.proxy_password:
    raise RuntimeError("MAILPROXY_PASSWORD env var must be set to run the proxy")

  async with asyncio.TaskGroup() as tg:
    smtp_server = await asyncio.start_server(functools.partial(smtp_server_handle_client, config), config.host, config.smtp_port)
    _ = tg.create_task(smtp_server.serve_forever(), name="SMTP server")

    imap_server = await asyncio.start_server(functools.partial(handle_imap, config), config.host, config.imap_port)
    _ = tg.create_task(imap_server.serve_forever(), name="IMAP server")

async def exec_dev(config: Config, address: str, _token: str):
  with db_open(config.db_path) as db:
    account = db_account_get_by_address(db, address)
  if account is None:
    raise RuntimeError(f"no account for address '{address}'")
  _ = await IMAPRemoteConnection.open(config, account)

def exec_account_add(config: Config, addresses: list[str], preset: str | None, oauth_config_path: pathlib.Path | None,
    refresh_token: str | None, imap_host: str | None, imap_port: int | None, imap_tlsmode: str | None,
    smtp_host: str | None, smtp_port: int | None, smtp_tlsmode: str | None, password: str | None):
  if refresh_token is not None:
    provider = _load_oauth_config(preset, oauth_config_path)
    account, initial_refresh_token = _account_from_oauth_config(tuple(addresses), provider, refresh_token)
    with db_open(config.db_path) as db:
      db_account_add(db, account, initial_refresh_token)
  elif password is not None and imap_host is not None and imap_port is not None and imap_tlsmode is not None \
       and smtp_host is not None and smtp_port is not None and smtp_tlsmode is not None:
    auth: AuthenticationOAUTH2 | AuthenticationPLAIN = AuthenticationPLAIN(password=password)
    account = Account(
      addresses=tuple(addresses),
      imap_host=imap_host,
      imap_port=imap_port,
      imap_tlsmode=_tlsmode(imap_tlsmode),
      smtp_host=smtp_host,
      smtp_port=smtp_port,
      smtp_tlsmode=_tlsmode(smtp_tlsmode),
      auth=auth,
    )
    with db_open(config.db_path) as db:
      db_account_add(db, account)
  else:
    raise ValueError("either --refresh-token (with --preset/--oauth-config) or --password (with --imap-*/--smtp-* args) must be specified")

  print(f"added account '{account.key}' ({', '.join(account.addresses)})")

def exec_account_list(config: Config):
  with db_open(config.db_path) as db:
    accounts = db_account_list(db)

  if not accounts:
    print("no accounts")
    return

  for a in accounts:
    auth_type = "OAUTH2" if isinstance(a.auth, AuthenticationOAUTH2) else "PLAIN"
    created = a.created_at.isoformat() if a.created_at else "?"
    print(f"{a.key}\t{', '.join(a.addresses)}\t{a.imap_host}:{a.imap_port}\t{auth_type}\t{created}")

def exec_account_remove(config: Config, address: str):
  with db_open(config.db_path) as db:
    account = db_account_get_by_address(db, address)
    if account is None:
      raise RuntimeError(f"no account for address '{address}'")
    db_account_remove(db, account.key)
  print(f"removed account '{account.key}'")

def exec_get_access_token(config: Config, address: str):
  with db_open(config.db_path) as db:
    account = db_account_get_by_address(db, address)
    if account is None:
      raise RuntimeError(f"no account for address '{address}'")
    if not isinstance(account.auth, AuthenticationOAUTH2):
      raise RuntimeError(f"account '{address}' is not OAUTH2")
    access_token = account_get_oauth_access_token(db, account)

  print("success, we have an access token :)")
  print("access token:", access_token)

def exec_login(provider: OAuthProviderConfig):
  auth = AuthenticationOAUTH2(
    scope=provider.scope,
    client_id=provider.client_id,
    client_secret=provider.client_secret,
    authorization_base_url=provider.authorization_base_url,
    token_url=provider.token_url,
    redirect_url=provider.redirect_url,
  )

  redirection_endpoint: urllib.parse.ParseResult = urllib.parse.urlparse(auth.redirect_url)

  if redirection_endpoint.hostname is None:
    raise ValueError("hostname of redirect url is None")

  if redirection_endpoint.port is None:
    raise ValueError("port of redirect url is None")

  _ = webbrowser.open(oauth_get_authorization_url(auth))

  authorization_code: list[str] = []

  class AuthorizationHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
      parsed_url = urllib.parse.urlparse(self.path)
      parsed_qs = urllib.parse.parse_qs(parsed_url.query)
      code = next(iter(parsed_qs.get("code", [])), None)
      body = b"no code" if code is None else b"success"
      if code is not None:
        authorization_code.append(code)
      self.send_response(200)
      self.send_header("Content-Type", "text/plain; charset=utf-8")
      self.send_header("Content-Length", str(len(body)))
      self.end_headers()
      _ = self.wfile.write(body)

  auth_server = http.server.HTTPServer((redirection_endpoint.hostname, redirection_endpoint.port), AuthorizationHandler)

  if redirection_endpoint.scheme == "https":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    with importlib.resources.path("mailproxy.assets", "dummy-cert.pem") as cert_path, importlib.resources.path("mailproxy.assets", "dummy-key.pem") as key_path:
      ctx.load_cert_chain(cert_path, key_path)
    auth_server.socket = ctx.wrap_socket(auth_server.socket, server_side=True)

  while not authorization_code:
    _ = auth_server.handle_request()

  code = authorization_code[0]
  access_token_result = oauth_fetch_access_token_with_authorization_code(auth, code)

  print("success, we have an access and refresh token :)")
  print("expires at: ", str(access_token_result.expires_at))
  print("access token: ", access_token_result.access_token)
  if access_token_result.refresh_token is not None:
    print("refresh token:", access_token_result.refresh_token)
  else:
    print("refresh token: (none returned, server may not grant offline_access)")

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  subparsers = parser.add_subparsers(dest="command", required=True)

  _ = subparsers.add_parser("run").add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)

  account_parser = subparsers.add_parser("account")
  account_sub = account_parser.add_subparsers(dest="account_command", required=True)

  account_add_parser = account_sub.add_parser("add")
  _ = account_add_parser.add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)
  _ = account_add_parser.add_argument("--address", "-A", help="email address (repeatable, first is primary)", action="append", required=True)
  _add_oauth_config_args(account_add_parser)
  _ = account_add_parser.add_argument("--refresh-token", help="oauth2 refresh token (for OAUTH2 auth)")
  _add_imap_args(account_add_parser)
  _add_smtp_args(account_add_parser)
  _ = account_add_parser.add_argument("--password", help="backend password (for PLAIN auth)")

  _ = account_sub.add_parser("list").add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)

  account_remove_parser = account_sub.add_parser("remove")
  _ = account_remove_parser.add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)
  _ = account_remove_parser.add_argument("--address", "-A", help="email address", required=True)

  login_parser = subparsers.add_parser("login")
  _add_oauth_config_args(login_parser)

  get_access_token_parser = subparsers.add_parser("get-access-token")
  _ = get_access_token_parser.add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)
  _ = get_access_token_parser.add_argument("--address", "-A", help="email address", required=True, type=str)

  dev_parser = subparsers.add_parser("dev")
  _ = dev_parser.add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)
  _ = dev_parser.add_argument("--address", "-A", help="email address", required=True, type=str)
  _ = dev_parser.add_argument("--token", "-T", help="access token (unused, kept for compat)", required=False, type=str)

  args = parser.parse_args()

  command = _ns_get(args, "command", str)
  if command == "run":
    config = _load_config(_ns_get(args, "config", pathlib.Path))
    asyncio.run(exec_run(config))
  elif command == "account":
    config = _load_config(_ns_get(args, "config", pathlib.Path))
    account_command = _ns_get(args, "account_command", str)
    if account_command == "add":
      exec_account_add(config, _ns_str_list(args, "address"),
        _ns_optional(args, "preset", str), _ns_optional(args, "oauth_config", pathlib.Path),
        _ns_optional(args, "refresh_token", str),
        _ns_optional(args, "imap_host", str), _ns_optional(args, "imap_port", int), _ns_optional(args, "imap_tlsmode", str),
        _ns_optional(args, "smtp_host", str), _ns_optional(args, "smtp_port", int), _ns_optional(args, "smtp_tlsmode", str),
        _ns_optional(args, "password", str))
    elif account_command == "list":
      exec_account_list(config)
    elif account_command == "remove":
      exec_account_remove(config, _ns_get(args, "address", str))
  elif command == "login":
    logging.basicConfig(level=logging.INFO)
    provider = _load_oauth_config(_ns_optional(args, "preset", str), _ns_optional(args, "oauth_config", pathlib.Path))
    exec_login(provider)
  elif command == "get-access-token":
    config = _load_config(_ns_get(args, "config", pathlib.Path))
    exec_get_access_token(config, _ns_get(args, "address", str))
  elif command == "dev":
    config = _load_config(_ns_get(args, "config", pathlib.Path))
    asyncio.run(exec_dev(config, _ns_get(args, "address", str), _ns_get(args, "token", str)))
  else:
    raise RuntimeError("unknown command!")
