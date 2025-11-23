import logging, dataclasses, enum, pathlib, re
from typing import Any, Literal, TypeVar

T = TypeVar("T")
def _get_type(d: Any, field_name: str, expected_type: type[T], default: T | None = None) -> T:
  if not isinstance(d, dict):
    raise ValueError("expected config to be a dict")

  value = d.get(field_name, default)
  if value is None:
    raise ValueError(f"value missing for field '{field_name}'")

  if not isinstance(value, expected_type):
    raise ValueError(f"invalid value type of field '{field_name}'")

  return value

def _get_str(d: Any, field_name: str, default: Any = None):
  return _get_type(d, field_name, str, default)

def _get_port(d: Any, field_name: str, default: int | None = None):
  value = _get_type(d, field_name, int, default)
  if value < 0 or value >= 2**16:
    raise ValueError(f"port out of range for field '{field_name}'!")
  return value

def _get_host(d, field_name: str):
  value = _get_str(d, field_name).strip()
  if not re.fullmatch(r"[A-Za-z0-9.-\[\]:]+", value):
    raise ValueError(f"Invalid characters in {field_name}")
  return value

class TLSMode(enum.Enum):
  DIRECT = "DIRECT"
  STARTTLS = "STARTTLS"
  NONE = "NONE"

  @staticmethod
  def from_value(raw: Any):
    if not isinstance(raw, str) or (value:=raw.upper()) not in TLSMode:
      raise ValueError("Invalid TLSMode!")
    return TLSMode(value)

@dataclasses.dataclass
class AuthenticationOAUTH2:
  scope: str
  client_id: str
  client_secret: str | None
  authorization_base_url: str
  token_url: str
  redirect_url: str
  initial_refresh_token: str

  @staticmethod
  def from_dict(d: Any):
    if _get_str(d, "type") != "OAUTH2":
      return None
    
    return AuthenticationOAUTH2(
      scope=_get_str(d, "scope"),
      client_id=_get_str(d, "client_id"),
      client_secret=_get_str(d, "client_id", "") or None,
      authorization_base_url=_get_str(d, "authorization_base_url"),
      token_url=_get_str(d, "token_url"),
      redirect_url=_get_str(d, "redirect_url"),
      initial_refresh_token=_get_str(d, "initial_refresh_token"),
    )

@dataclasses.dataclass
class AuthenticationPLAIN:
  password: str

  @staticmethod
  def from_dict(d: Any):
    if _get_str(d, "type") != "PLAIN":
      return None
    
    return AuthenticationPLAIN(_get_str(d, "password"))

@dataclasses.dataclass
class Account:
  addresses: list[str]
  db_path: pathlib.Path

  imap_host: str
  imap_port: int
  imap_tlsmode: TLSMode
  smtp_host: str
  smtp_port: int
  smtp_tlsmode: TLSMode

  auth: AuthenticationOAUTH2 | AuthenticationPLAIN

  @staticmethod
  def from_dict(d: Any, data_dir: pathlib.Path):
    if not isinstance(d, dict):
      raise ValueError("expected config to be a dict")
    
    addresses = d.get("addresses", [])
    if not isinstance(addresses, list) or len(addresses) == 0 or \
        any(not isinstance(address, str) for address in addresses):
      raise ValueError("Invalid addresses")
    
    db_path_str = _get_str(d, "db_path", str(data_dir.joinpath(re.sub(r"[^a-zA-Z0-9]", "_", addresses[0]) + ".sqlite")))
      
    auth = AuthenticationPLAIN.from_dict(d.get("auth")) or AuthenticationOAUTH2.from_dict(d.get("auth"))
    if auth is None:
      raise ValueError("auth type invalid!")

    return Account(
      addresses=addresses,
      db_path=pathlib.Path(db_path_str),
      imap_host=_get_host(d, "imap_host"),
      imap_port=_get_port(d, "imap_port"),
      imap_tlsmode=TLSMode.from_value(_get_str(d, "imap_tlsmode")),
      smtp_host=_get_host(d, "smtp_host"),
      smtp_port=_get_port(d, "smtp_port"),
      smtp_tlsmode=TLSMode.from_value(_get_str(d, "smtp_tlsmode")),
      auth=auth,
    )
    

@dataclasses.dataclass
class Config:
  accounts: list[Account]
  domain: str
  
  log_level: int = logging.ERROR

  host: str = "0.0.0.0"
  imap_port: int = 143
  smtp_port: int = 587

  @staticmethod
  def from_dict(d: Any):
    if not isinstance(d, dict):
      raise ValueError("expected config to be a dict")

    data_dir = pathlib.Path(_get_str(d, "data_dir"))
    if not data_dir.exists():
      raise ValueError("Invalid data_dir")

    if "accounts" not in d or not isinstance(d["accounts"], list) or len(d["accounts"]) == 0:
      raise ValueError("Invalid accounts")

    return Config(
      accounts=[ Account.from_dict(a, data_dir) for a in d["accounts"] ],
      domain=_get_host(d, "domain"),
      log_level=logging.getLevelNamesMapping().get(_get_str(d, "log_level", "DEBUG"), logging.DEBUG),
      host=_get_host(d, "host"),
      imap_port=_get_port(d, "imap_port", 143),
      smtp_port=_get_port(d, "smtp_port", 587),
    )
