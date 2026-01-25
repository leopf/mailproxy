import logging, pathlib, re
from typing import Any, TypeVar
from mailproxy.model import Account, AuthenticationOAUTH2, AuthenticationPLAIN, Config, TLSMode

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

def _get_host(d, field_name: str, default: str | None = None):
  value = _get_str(d, field_name, default).strip()
  if not re.fullmatch(r"[A-Za-z0-9.\-\[\]:]+", value):
    raise ValueError(f"Invalid characters in {field_name} regading value '{value}'")
  return value

def tls_mode_from_value(raw: Any):
  if not isinstance(raw, str) or (value:=raw.upper()) not in TLSMode:
    raise ValueError("Invalid TLSMode!")
  return TLSMode(value)

def auth_oauth2_from_dict(d: Any):
  if _get_str(d, "type") != "OAUTH2":
    return None

  return AuthenticationOAUTH2(
    scope=_get_str(d, "scope"),
    client_id=_get_str(d, "client_id"),
    client_secret=_get_str(d, "client_secret", "") or None,
    authorization_base_url=_get_str(d, "authorization_base_url"),
    token_url=_get_str(d, "token_url"),
    redirect_url=_get_str(d, "redirect_url"),
    initial_refresh_token=_get_str(d, "initial_refresh_token"),
  )

def auth_plain_from_dict(d: Any):
  if _get_str(d, "type") != "PLAIN":
    return None

  return AuthenticationPLAIN(_get_str(d, "password"))

def account_from_dict(d: Any):
  if not isinstance(d, dict):
    raise ValueError("expected config to be a dict")

  addresses = d.get("addresses", [])
  if not isinstance(addresses, list) or len(addresses) == 0 or \
      any(not isinstance(address, str) for address in addresses):
    raise ValueError("Invalid addresses")

  auth = auth_plain_from_dict(d.get("auth")) or auth_oauth2_from_dict(d.get("auth"))
  if auth is None:
    raise ValueError("auth type invalid!")

  return Account(
    addresses=addresses,
    imap_host=_get_host(d, "imap_host"),
    imap_port=_get_port(d, "imap_port"),
    imap_tlsmode=tls_mode_from_value(_get_str(d, "imap_tlsmode")),
    smtp_host=_get_host(d, "smtp_host"),
    smtp_port=_get_port(d, "smtp_port"),
    smtp_tlsmode=tls_mode_from_value(_get_str(d, "smtp_tlsmode")),
    auth=auth,
  )

def config_from_dict(d: Any):
  if not isinstance(d, dict):
    raise ValueError("expected config to be a dict")

  db_path_str = _get_str(d, "db_path")

  if "accounts" not in d or not isinstance(d["accounts"], list) or len(d["accounts"]) == 0:
    raise ValueError("Invalid accounts")

  return Config(
    db_path=pathlib.Path(db_path_str),
    accounts=[ account_from_dict(a) for a in d["accounts"] ],
    log_level=logging.getLevelNamesMapping().get(_get_str(d, "log_level", "DEBUG"), logging.DEBUG),
    domain=_get_host(d, "domain"),
    host=_get_host(d, "host", "0.0.0.0"),
    imap_port=_get_port(d, "imap_port", 143),
    smtp_port=_get_port(d, "smtp_port", 587),
  )
