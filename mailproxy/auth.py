import http.client, urllib.parse, datetime, base64, hashlib, secrets, sqlite3, hmac
from mailproxy.config import oauth_token_response_from_dict
from mailproxy.db import db_account_get_by_address, row_field, row_optional, fetchone
from mailproxy.model import Account, AuthenticationOAUTH2, Config, OAUTHAccessTokenResult
from mailproxy.utils import json_loads_object

class AuthenticationError(Exception):
  pass

def _fetch_access_token(auth: AuthenticationOAUTH2, extra_data: dict[str, str]) -> OAUTHAccessTokenResult:
  data = { "client_id": auth.client_id } | extra_data
  if auth.client_secret is not None:
    data["client_secret"] = auth.client_secret

  parsed = urllib.parse.urlparse(auth.token_url)
  if parsed.hostname is None:
    raise AuthenticationError(f"invalid token_url: {auth.token_url}")

  headers = { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" }
  body = urllib.parse.urlencode(data).encode()
  path = parsed.path or "/"

  if parsed.scheme == "https":
    conn: http.client.HTTPConnection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443)
  else:
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80)

  try:
    conn.request("POST", path, body=body, headers=headers)
    response = conn.getresponse()
    response_body: bytes = response.read()
    if response.status != 200:
      raise AuthenticationError("failed to get refresh token: " + response_body.decode())
    token_response = oauth_token_response_from_dict(json_loads_object(response_body.decode()))
    return OAUTHAccessTokenResult(
      expires_at=datetime.datetime.now() + datetime.timedelta(seconds=token_response.expires_in),
      access_token=token_response.access_token,
      refresh_token=token_response.refresh_token,
    )
  finally:
    conn.close()

def oauth_fetch_access_token_with_refresh_token(auth: AuthenticationOAUTH2, refresh_token: str) -> OAUTHAccessTokenResult:
  return _fetch_access_token(auth, { "grant_type": "refresh_token", "refresh_token": refresh_token })

def oauth_fetch_access_token_with_authorization_code(auth: AuthenticationOAUTH2, authorization_code: str, code_verifier: str | None = None) -> OAUTHAccessTokenResult:
  extra_data = { "grant_type": "authorization_code", "code": authorization_code, "redirect_uri": auth.redirect_url }
  if code_verifier is not None:
    extra_data["code_verifier"] = code_verifier
  return _fetch_access_token(auth, extra_data)

def pkce_generate() -> tuple[str, str]:
  verifier = secrets.token_urlsafe(64)
  challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
  return verifier, challenge

def oauth_get_authorization_url(auth: AuthenticationOAUTH2, code_challenge: str | None = None, state: str | None = None) -> str:
  data = { "client_id": auth.client_id, "scope": auth.scope, "redirect_uri": auth.redirect_url, "response_type": "code" }
  if state is not None:
    data["state"] = state
  if code_challenge is not None:
    data["code_challenge"] = code_challenge
    data["code_challenge_method"] = "S256"
  return f"{auth.authorization_base_url}?{urllib.parse.urlencode(data)}"

def authenticate_sasl(config: Config, db: sqlite3.Connection, sasl_b64: bytes) -> Account | None:
  try:
    decoded = base64.b64decode(sasl_b64)
  except Exception:
    return None
  parts = decoded.split(b"\0", maxsplit=2)
  if len(parts) != 3:
    return None
  _authzid, authcid, passwd = parts
  return authenticate(config, db, authcid, passwd)

def authenticate(config: Config, db: sqlite3.Connection, username: bytes, password: bytes) -> Account | None:
  if not config.proxy_password:
    return None
  account = db_account_get_by_address(db, username.decode())
  if account is None:
    return None
  if not hmac.compare_digest(password, config.proxy_password.encode()):
    return None
  return account

def account_get_oauth_access_token(db: sqlite3.Connection, account: Account) -> str:
  assert isinstance(account.auth, AuthenticationOAUTH2)
  row = fetchone(db, "SELECT access_token, refresh_token, expires_at FROM oauth2_data WHERE account_key=?", (account.key,))
  if row is None:
    raise AuthenticationError(f"no oauth2 data for account '{account.key}'")

  access_token = row_optional(row, "access_token", str)
  refresh_token = row_field(row, "refresh_token", str)
  expires_at_str = row_optional(row, "expires_at", str)
  if access_token is not None and expires_at_str is not None:
    expires_at = datetime.datetime.fromisoformat(expires_at_str)
    if datetime.datetime.now() < expires_at:
      return access_token

  new_auth_result = oauth_fetch_access_token_with_refresh_token(account.auth, refresh_token)
  _ = db.execute("""UPDATE oauth2_data SET access_token=?, refresh_token=?, expires_at=? WHERE account_key=?""",
    (new_auth_result.access_token, new_auth_result.refresh_token or refresh_token, new_auth_result.expires_at.isoformat(), account.key))
  db.commit()
  return new_auth_result.access_token
