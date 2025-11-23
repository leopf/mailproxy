import urllib.parse, urllib.request, json, datetime, dataclasses, base64
from mailproxy.config import Account, AuthenticationOAUTH2, Config

@dataclasses.dataclass
class OAUTHAccessTokenResult:
  access_token: str
  expires_at: datetime.datetime
  refresh_token: str | None

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
        raise RuntimeError(f"wrong token response token_type: '{response_json["token_type"]}'") # sanity check      
      
      return OAUTHAccessTokenResult(
        expires_at = datetime.datetime.now() + datetime.timedelta(seconds=response_json["expires_in"]),
        access_token = response_json["access_token"],
        refresh_token = response_json.get("refresh_token")
      )

  except urllib.request.HTTPError as e:
    raise RuntimeError("failed to get refresh token: " + e.read().decode())

def oauth_fetch_access_token_with_refresh_token(auth: AuthenticationOAUTH2, refresh_token: str):
  return _fetch_access_token(auth, { "grant_type": "refresh_token", "refresh_token": refresh_token })

def oauth_fetch_access_token_with_authorization_code(auth: AuthenticationOAUTH2, authorization_code: str):
  return _fetch_access_token(auth, { "grant_type": "authorization_code", "code": authorization_code })

def oauth_get_authorization_url(auth: AuthenticationOAUTH2):
  data = { "client_id": auth.client_id, "scope": auth.scope, "redirect_uri": auth.redirect_url, "response_type": "code", "response_mode": "query" }
  return f"{auth.authorization_base_url}?{urllib.parse.urlencode(data)}"

def authenticate_sasl(config: Config, sasl_b64: str):
  data = base64.b64decode(sasl_b64).split(b"\0")
  return authenticate(config, data[1].decode(), data[1].decode())

def authenticate(config: Config, username: str, password: str) -> Account | None:
  print("try auth", username, password)  
  try:
    return next(account for account in config.accounts if username in account.addresses)
  except:
    return None