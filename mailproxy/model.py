import dataclasses, datetime, enum, pathlib

@dataclasses.dataclass
class OAUTHAccessTokenResult:
  access_token: str
  expires_at: datetime.datetime
  refresh_token: str | None

class TLSMode(enum.Enum):
  DIRECT = "DIRECT"
  STARTTLS = "STARTTLS"
  NONE = "NONE"

@dataclasses.dataclass(frozen=True)
class AuthenticationOAUTH2:
  scope: str
  client_id: str
  client_secret: str | None
  authorization_base_url: str
  token_url: str
  redirect_url: str

@dataclasses.dataclass(frozen=True)
class AuthenticationPLAIN:
  password: str

@dataclasses.dataclass(frozen=True)
class Account:
  addresses: tuple[str, ...]
  imap_host: str
  imap_port: int
  imap_tlsmode: TLSMode
  smtp_host: str
  smtp_port: int
  smtp_tlsmode: TLSMode
  auth: AuthenticationOAUTH2 | AuthenticationPLAIN
  created_at: datetime.datetime | None = None

  @property
  def key(self) -> str:
    return self.addresses[0]

@dataclasses.dataclass(frozen=True)
class Config:
  domain: str
  log_level: int
  host: str
  imap_port: int
  smtp_port: int
  db_path: pathlib.Path
  proxy_password: str = ""
  tls_cert_path: pathlib.Path | None = None
  tls_key_path: pathlib.Path | None = None

@dataclasses.dataclass(frozen=True)
class Mailbox:
  id: int
  account_key: str
  uid_next: int
  uid_validity: int
  name: str
  hierarchy_delimiter: str
  flags_s: str
  is_remote: bool
  last_synced_uid: int
  is_deleted: bool = False

  @property
  def flags(self) -> tuple[str, ...]:
    return tuple("\\" + flag for flag in self.flags_s.strip("\\").split("\\") if flag)

@dataclasses.dataclass(frozen=True)
class Message:
  uid: int
  mailbox_id: int
  received_date: int
  flags_s: str
  size: int
  body_hash: str
  remote_uid: str | None
  is_deleted: bool = False

@dataclasses.dataclass(frozen=True)
class OAuthProviderConfig:
  imap_host: str
  imap_port: int
  imap_tlsmode: TLSMode
  smtp_host: str
  smtp_port: int
  smtp_tlsmode: TLSMode
  scope: str
  client_id: str
  client_secret: str | None
  authorization_base_url: str
  token_url: str
  redirect_url: str
  use_pkce: bool = False

@dataclasses.dataclass(frozen=True)
class ProviderConfig:
  imap_host: str
  imap_port: int
  imap_tlsmode: TLSMode
  smtp_host: str
  smtp_port: int
  smtp_tlsmode: TLSMode
  scope: str | None = None
  client_id: str | None = None
  client_secret: str | None = None
  authorization_base_url: str | None = None
  token_url: str | None = None
  redirect_url: str | None = None
  use_pkce: bool = False

  @property
  def is_oauth2(self) -> bool:
    return self.scope is not None and self.client_id is not None

@dataclasses.dataclass(frozen=True)
class OAuthTokenResponse:
  token_type: str
  expires_in: int
  access_token: str
  refresh_token: str | None
