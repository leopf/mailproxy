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
  initial_refresh_token: str

@dataclasses.dataclass(frozen=True)
class AuthenticationPLAIN:
  password: str

@dataclasses.dataclass(frozen=True)
class Account:
  addresses: list[str]

  imap_host: str
  imap_port: int
  imap_tlsmode: TLSMode
  smtp_host: str
  smtp_port: int
  smtp_tlsmode: TLSMode

  auth: AuthenticationOAUTH2 | AuthenticationPLAIN

  @property
  def key(self):
    return self.addresses[0]

@dataclasses.dataclass(frozen=True)
class Config:
  accounts: list[Account]
  domain: str
  log_level: int
  host: str
  imap_port: int
  smtp_port: int
  db_path: pathlib.Path

@dataclasses.dataclass(frozen=True)
class Mailbox:
  id: int
  account_key: str
  uid_next: int
  uid_validity: int
  name: str
  hierachry_delimiter: str
  flags_s: str
  is_virtual: bool
  is_remote: bool

  @property
  def flags(self):
    return tuple("\\" + flag for flag in self.flags_s.rstrip("\\").split("\\"))
