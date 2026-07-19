import functools, asyncio, logging, argparse, pathlib, os, dataclasses, webbrowser, urllib.parse, http.server, ssl, importlib.resources, typing
from typing import TypeVar
from mailproxy.config import config_from_dict, provider_config_from_dict
from mailproxy.db import db_account_add, db_account_get_by_address, db_account_list, db_account_remove, db_mailbox_add, db_mailbox_by_name, db_mailbox_delete, db_mailbox_list, db_mailbox_rename, db_open
from mailproxy.imap_frontend import handle_imap
from mailproxy.auth import account_get_oauth_access_token, oauth_get_authorization_url, oauth_fetch_access_token_with_authorization_code
from mailproxy.smtp_frontend import smtp_server_handle_client
from mailproxy.model import Account, AuthenticationOAUTH2, AuthenticationPLAIN, Config, OAuthProviderConfig, ProviderConfig, TLSMode
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

def _load_provider_config(preset: str | None, provider_config_path: pathlib.Path | None) -> ProviderConfig:
  if preset is not None:
    with importlib.resources.path("mailproxy.presets", f"{preset}.json") as p:
      raw: object = json_loads_object(pathlib.Path(p).read_text())
  elif provider_config_path is not None:
    raw = json_loads_object(provider_config_path.read_text())
  else:
    raise ValueError("either --preset or --provider-config must be specified")
  return provider_config_from_dict(raw)

def _load_oauth_config(preset: str | None, provider_config_path: pathlib.Path | None) -> OAuthProviderConfig:
  provider = _load_provider_config(preset, provider_config_path)
  if not provider.is_oauth2:
    raise ValueError("provider config is missing OAuth2 fields (scope, client_id, ...)")
  assert provider.scope is not None and provider.client_id is not None and provider.authorization_base_url is not None and provider.token_url is not None and provider.redirect_url is not None
  return OAuthProviderConfig(
    imap_host=provider.imap_host, imap_port=provider.imap_port, imap_tlsmode=provider.imap_tlsmode,
    smtp_host=provider.smtp_host, smtp_port=provider.smtp_port, smtp_tlsmode=provider.smtp_tlsmode,
    scope=provider.scope, client_id=provider.client_id, client_secret=provider.client_secret,
    authorization_base_url=provider.authorization_base_url, token_url=provider.token_url, redirect_url=provider.redirect_url,
  )

def _add_imap_args(p: argparse.ArgumentParser) -> None:
  _ = p.add_argument("--imap-host")
  _ = p.add_argument("--imap-port", type=int)
  _ = p.add_argument("--imap-tlsmode", type=str.upper, choices=[m.value for m in TLSMode])

def _add_smtp_args(p: argparse.ArgumentParser) -> None:
  _ = p.add_argument("--smtp-host")
  _ = p.add_argument("--smtp-port", type=int)
  _ = p.add_argument("--smtp-tlsmode", type=str.upper, choices=[m.value for m in TLSMode])

def _add_provider_config_args(p: argparse.ArgumentParser) -> None:
  _ = p.add_argument("--preset", help="preset name (gmail, microsoft, yahoo)")
  _ = p.add_argument("--provider-config", type=pathlib.Path, help="path to provider config json")

def _ns_get(args: argparse.Namespace, name: str, expected: type[T]) -> T:
  value: object = typing.cast(object, getattr(args, name))
  if not isinstance(value, expected):
    raise TypeError(f"expected {expected.__name__} for --{name}")
  return value

def _ns_optional(args: argparse.Namespace, name: str, expected: type[T]) -> T | None:
  value: object = typing.cast(object, getattr(args, name))
  if value is None:
    return None
  if not isinstance(value, expected):
    raise TypeError(f"expected {expected.__name__} or None for --{name}")
  return value

def _ns_str_list(args: argparse.Namespace, name: str) -> list[str]:
  value: object = typing.cast(object, getattr(args, name))
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
    smtp_server = await asyncio.start_server(functools.partial(smtp_server_handle_client, config), config.host, config.smtp_port, limit=2**24)
    _ = tg.create_task(smtp_server.serve_forever(), name="SMTP server")

    imap_server = await asyncio.start_server(functools.partial(handle_imap, config), config.host, config.imap_port, limit=2**24)
    _ = tg.create_task(imap_server.serve_forever(), name="IMAP server")

def exec_account_add(config: Config, addresses: list[str], preset: str | None, provider_config_path: pathlib.Path | None,
    refresh_token: str | None, imap_host: str | None, imap_port: int | None, imap_tlsmode: str | None,
    smtp_host: str | None, smtp_port: int | None, smtp_tlsmode: str | None, password: str | None):
  provider = _load_provider_config(preset, provider_config_path) if preset is not None or provider_config_path is not None else None

  # Resolve IMAP/SMTP connection params from provider or CLI args
  if provider is not None:
    im_host, im_port, im_tls = provider.imap_host, provider.imap_port, provider.imap_tlsmode
    sm_host, sm_port, sm_tls = provider.smtp_host, provider.smtp_port, provider.smtp_tlsmode
  elif imap_host is None or imap_port is None or imap_tlsmode is None or smtp_host is None or smtp_port is None or smtp_tlsmode is None:
    raise ValueError("provide --preset/--provider-config or all --imap-*/--smtp-* args")
  else:
    im_host, im_port, im_tls = imap_host, imap_port, _tlsmode(imap_tlsmode)
    sm_host, sm_port, sm_tls = smtp_host, smtp_port, _tlsmode(smtp_tlsmode)

  # Build auth
  if refresh_token is not None:
    if provider is None or not provider.is_oauth2:
      raise ValueError("--refresh-token requires an OAuth2 provider config (--preset or --provider-config)")
    assert provider.scope is not None and provider.client_id is not None and provider.authorization_base_url is not None and provider.token_url is not None and provider.redirect_url is not None
    auth: AuthenticationOAUTH2 | AuthenticationPLAIN = AuthenticationOAUTH2(
      scope=provider.scope, client_id=provider.client_id, client_secret=provider.client_secret,
      authorization_base_url=provider.authorization_base_url, token_url=provider.token_url, redirect_url=provider.redirect_url,
    )
  elif password is not None:
    auth = AuthenticationPLAIN(password=password)
  else:
    raise ValueError("either --refresh-token (with OAuth2 provider) or --password must be specified")

  account = Account(
    addresses=tuple(addresses),
    imap_host=im_host, imap_port=im_port, imap_tlsmode=im_tls,
    smtp_host=sm_host, smtp_port=sm_port, smtp_tlsmode=sm_tls,
    auth=auth,
  )
  with db_open(config.db_path) as db:
    db_account_add(db, account, refresh_token)

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

def exec_mailbox_add(config: Config, address: str, name: str):
  with db_open(config.db_path) as db:
    account = db_account_get_by_address(db, address)
    if account is None:
      raise RuntimeError(f"no account for address '{address}'")
    if db_mailbox_by_name(db, account.key, name) is not None:
      raise RuntimeError(f"mailbox '{name}' already exists for account '{account.key}'")
    _ = db_mailbox_add(db, account.key, name, 0, 1, is_remote=False)
  print(f"added local mailbox '{name}' for account '{account.key}'")

def exec_mailbox_list(config: Config, address: str):
  with db_open(config.db_path) as db:
    account = db_account_get_by_address(db, address)
    if account is None:
      raise RuntimeError(f"no account for address '{address}'")
    mailboxes = list(db_mailbox_list(db, account.key))
  if not mailboxes:
    print("no mailboxes")
    return
  for mb in mailboxes:
    kind = "remote" if mb.is_remote else "local"
    print(f"{mb.name}\t{kind}")

def exec_mailbox_remove(config: Config, address: str, name: str):
  with db_open(config.db_path) as db:
    account = db_account_get_by_address(db, address)
    if account is None:
      raise RuntimeError(f"no account for address '{address}'")
    mailbox = db_mailbox_by_name(db, account.key, name)
    if mailbox is None:
      raise RuntimeError(f"no mailbox '{name}' for account '{account.key}'")
    if mailbox.is_remote:
      raise RuntimeError(f"mailbox '{name}' is a remote mailbox, remove via IMAP DELETE")
    db_mailbox_delete(db, mailbox.id)
  print(f"removed local mailbox '{name}'")

def exec_mailbox_rename(config: Config, address: str, old_name: str, new_name: str):
  with db_open(config.db_path) as db:
    account = db_account_get_by_address(db, address)
    if account is None:
      raise RuntimeError(f"no account for address '{address}'")
    mailbox = db_mailbox_by_name(db, account.key, old_name)
    if mailbox is None:
      raise RuntimeError(f"no mailbox '{old_name}' for account '{account.key}'")
    if mailbox.is_remote:
      raise RuntimeError(f"mailbox '{old_name}' is a remote mailbox, rename via IMAP RENAME")
    if db_mailbox_by_name(db, account.key, new_name) is not None:
      raise RuntimeError(f"mailbox '{new_name}' already exists for account '{account.key}'")
    db_mailbox_rename(db, mailbox.id, new_name)
  print(f"renamed local mailbox '{old_name}' to '{new_name}'")

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

def main():
  parser = argparse.ArgumentParser()
  subparsers = parser.add_subparsers(dest="command", required=True)

  _ = subparsers.add_parser("run").add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)

  account_parser = subparsers.add_parser("account")
  account_sub = account_parser.add_subparsers(dest="account_command", required=True)

  account_add_parser = account_sub.add_parser("add")
  _ = account_add_parser.add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)
  _ = account_add_parser.add_argument("--address", "-A", help="email address (repeatable, first is primary)", action="append", required=True)
  _add_provider_config_args(account_add_parser)
  _ = account_add_parser.add_argument("--refresh-token", help="oauth2 refresh token (for OAUTH2 auth)")
  _add_imap_args(account_add_parser)
  _add_smtp_args(account_add_parser)
  _ = account_add_parser.add_argument("--password", help="backend password (for PLAIN auth)")

  _ = account_sub.add_parser("list").add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)

  account_remove_parser = account_sub.add_parser("remove")
  _ = account_remove_parser.add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)
  _ = account_remove_parser.add_argument("--address", "-A", help="email address", required=True)

  mailbox_parser = subparsers.add_parser("mailbox")
  mailbox_sub = mailbox_parser.add_subparsers(dest="mailbox_command", required=True)

  mailbox_add_parser = mailbox_sub.add_parser("add")
  _ = mailbox_add_parser.add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)
  _ = mailbox_add_parser.add_argument("--address", "-A", help="email address", required=True)
  _ = mailbox_add_parser.add_argument("--name", "-N", help="mailbox name", required=True)

  mailbox_list_parser = mailbox_sub.add_parser("list")
  _ = mailbox_list_parser.add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)
  _ = mailbox_list_parser.add_argument("--address", "-A", help="email address", required=True)

  mailbox_remove_parser = mailbox_sub.add_parser("remove")
  _ = mailbox_remove_parser.add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)
  _ = mailbox_remove_parser.add_argument("--address", "-A", help="email address", required=True)
  _ = mailbox_remove_parser.add_argument("--name", "-N", help="mailbox name", required=True)

  mailbox_rename_parser = mailbox_sub.add_parser("rename")
  _ = mailbox_rename_parser.add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)
  _ = mailbox_rename_parser.add_argument("--address", "-A", help="email address", required=True)
  _ = mailbox_rename_parser.add_argument("--old-name", help="old mailbox name", required=True)
  _ = mailbox_rename_parser.add_argument("--new-name", help="new mailbox name", required=True)

  login_parser = subparsers.add_parser("login")
  _add_provider_config_args(login_parser)

  get_access_token_parser = subparsers.add_parser("get-access-token")
  _ = get_access_token_parser.add_argument("--config", "-C", help="config path", required=True, type=pathlib.Path)
  _ = get_access_token_parser.add_argument("--address", "-A", help="email address", required=True, type=str)

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
        _ns_optional(args, "preset", str), _ns_optional(args, "provider_config", pathlib.Path),
        _ns_optional(args, "refresh_token", str),
        _ns_optional(args, "imap_host", str), _ns_optional(args, "imap_port", int), _ns_optional(args, "imap_tlsmode", str),
        _ns_optional(args, "smtp_host", str), _ns_optional(args, "smtp_port", int), _ns_optional(args, "smtp_tlsmode", str),
        _ns_optional(args, "password", str))
    elif account_command == "list":
      exec_account_list(config)
    elif account_command == "remove":
      exec_account_remove(config, _ns_get(args, "address", str))
  elif command == "mailbox":
    config = _load_config(_ns_get(args, "config", pathlib.Path))
    mailbox_command = _ns_get(args, "mailbox_command", str)
    if mailbox_command == "add":
      exec_mailbox_add(config, _ns_get(args, "address", str), _ns_get(args, "name", str))
    elif mailbox_command == "list":
      exec_mailbox_list(config, _ns_get(args, "address", str))
    elif mailbox_command == "remove":
      exec_mailbox_remove(config, _ns_get(args, "address", str), _ns_get(args, "name", str))
    elif mailbox_command == "rename":
      exec_mailbox_rename(config, _ns_get(args, "address", str), _ns_get(args, "old_name", str), _ns_get(args, "new_name", str))
  elif command == "login":
    logging.basicConfig(level=logging.INFO)
    provider = _load_oauth_config(_ns_optional(args, "preset", str), _ns_optional(args, "provider_config", pathlib.Path))
    exec_login(provider)
  elif command == "get-access-token":
    config = _load_config(_ns_get(args, "config", pathlib.Path))
    exec_get_access_token(config, _ns_get(args, "address", str))
  else:
    raise RuntimeError("unknown command!")

if __name__ == "__main__":
  main()
