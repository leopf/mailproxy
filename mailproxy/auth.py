import urllib.parse, urllib.request, json, datetime, dataclasses, base64, sqlite3
from mailproxy.config import Account, AuthenticationOAUTH2, Config

class AuthenticationError(Exception):
  pass

@dataclasses.dataclass
class OAUTHAccessTokenResult:
  access_token: str
  expires_at: datetime.datetime
  refresh_token: str | None

@dataclasses.dataclass
class OAUTHAccessToken:
  access_token: str
  expires_at: datetime.datetime
  refresh_token: str

def _fetch_access_token(auth: AuthenticationOAUTH2, extra_data: dict[str, str]):
  data = { "client_id": auth.client_id, "scope": auth.scope } | extra_data
  if auth.client_secret is not None:
    data["client_secret"] = auth.client_secret

  token_request = urllib.request.Request(
    auth.token_url,
    data=urllib.parse.urlencode(data).encode(),
    method="POST",
    headers={ "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" }
  )

  try:
    with urllib.request.urlopen(token_request) as resp:
      response_json = json.loads(resp.read())
      if response_json["token_type"] != "Bearer":
        raise AuthenticationError(f"wrong token response token_type: '{response_json["token_type"]}'") # sanity check

      return OAUTHAccessTokenResult(
        expires_at = datetime.datetime.now() + datetime.timedelta(seconds=response_json["expires_in"]),
        access_token = response_json["access_token"],
        refresh_token = response_json.get("refresh_token")
      )

  except urllib.request.HTTPError as e:
    raise AuthenticationError("failed to get refresh token: " + e.read().decode())

def oauth_fetch_access_token_with_refresh_token(auth: AuthenticationOAUTH2, refresh_token: str):
  return _fetch_access_token(auth, { "grant_type": "refresh_token", "refresh_token": refresh_token })

def oauth_fetch_access_token_with_authorization_code(auth: AuthenticationOAUTH2, authorization_code: str):
  return _fetch_access_token(auth, { "grant_type": "authorization_code", "code": authorization_code })

def oauth_get_authorization_url(auth: AuthenticationOAUTH2):
  data = { "client_id": auth.client_id, "scope": auth.scope, "redirect_uri": auth.redirect_url, "response_type": "code", "response_mode": "query" }
  return f"{auth.authorization_base_url}?{urllib.parse.urlencode(data)}"

def authenticate_sasl(config: Config, sasl_b64: str):
  data = base64.b64decode(sasl_b64).split(b"\0")
  return authenticate(config, data[1], data[1])

def authenticate(config: Config, username: bytes, password: bytes) -> Account | None:
  print("try auth", username, password)
  try:
    return next(account for account in config.accounts if username in account.addresses)
  except:
    return None

def account_get_oauth_access_token(db: sqlite3.Connection, account: Account) -> str:
  assert isinstance(account.auth, AuthenticationOAUTH2)
  cur = db.cursor()
  cur.execute("SELECT access_token, refresh_token, expires_at FROM oauth2_data WHERE account_key=? LIMIT 1", (account.key,))
  db_oauth_data_item = cur.fetchone()
  if db_oauth_data_item is not None:
    access_token, refresh_token, expires_at_str = db_oauth_data_item
    assert isinstance(access_token, str) and isinstance(refresh_token, str) and isinstance(expires_at_str, str)
    expires_at = datetime.datetime.fromisoformat(expires_at_str)
    if datetime.datetime.now() < expires_at:
      return access_token
  else:
    refresh_token = account.auth.initial_refresh_token

  new_auth_result = oauth_fetch_access_token_with_refresh_token(account.auth, refresh_token)
  cur.execute("""
  INSERT INTO oauth2_data (account_key, access_token, refresh_token, expires_at) VALUES (?, ?, ?, ?)
  ON CONFLICT(account_key) DO UPDATE SET access_token=excluded.access_token, refresh_token=excluded.refresh_token, expires_at=excluded.expires_at;
  """, (account.key, new_auth_result.access_token, new_auth_result.refresh_token or refresh_token, new_auth_result.expires_at.isoformat()))
  db.commit()
  return new_auth_result.access_token
