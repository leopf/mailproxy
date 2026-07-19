import logging, pathlib, re
from typing import TypeVar
from mailproxy.model import Config, OAuthProviderConfig, OAuthTokenResponse, ProviderConfig, TLSMode
from mailproxy.utils import is_str_object_dict

T = TypeVar("T")

def _field(data: object, name: str, expected: type[T]) -> T:
  if not is_str_object_dict(data):
    raise ValueError("data must be a JSON object")
  if name not in data:
    raise ValueError(f"missing field '{name}'")
  value: object = data[name]
  if not isinstance(value, expected):
    raise ValueError(f"field '{name}' must be {expected.__name__}")
  return value

def _optional_field(data: object, name: str, expected: type[T]) -> T | None:
  if not is_str_object_dict(data):
    raise ValueError("data must be a JSON object")
  if name not in data:
    return None
  value: object = data[name]
  if value is None:
    return None
  if not isinstance(value, expected):
    raise ValueError(f"field '{name}' must be {expected.__name__} or null")
  return value

def _field_with_default(data: object, name: str, expected: type[T], default: T) -> T:
  if not is_str_object_dict(data):
    raise ValueError("data must be a JSON object")
  if name not in data:
    return default
  value: object = data[name]
  if value is None:
    return default
  if not isinstance(value, expected):
    raise ValueError(f"field '{name}' must be {expected.__name__}")
  return value

def _validate_host(name: str, value: str) -> str:
  value = value.strip()
  if not re.fullmatch(r"[A-Za-z0-9.\-\[\]:]+", value):
    raise ValueError(f"Invalid characters in {name} regarding value '{value}'")
  return value

def _validate_port(name: str, value: int) -> int:
  if value < 0 or value >= 2**16:
    raise ValueError(f"port out of range for field '{name}'!")
  return value

def config_from_dict(d: object) -> Config:
  tls_cert_path = _optional_field(d, "tls_cert_path", str)
  tls_key_path = _optional_field(d, "tls_key_path", str)
  if (tls_cert_path is None) != (tls_key_path is None):
    raise ValueError("tls_cert_path and tls_key_path must be set together")
  return Config(
    db_path=pathlib.Path(_field(d, "db_path", str)),
    domain=_validate_host("domain", _field(d, "domain", str)),
    log_level=logging.getLevelNamesMapping().get(_field_with_default(d, "log_level", str, "DEBUG"), logging.DEBUG),
    host=_validate_host("host", _field_with_default(d, "host", str, "0.0.0.0")),
    imap_port=_validate_port("imap_port", _field_with_default(d, "imap_port", int, 143)),
    smtp_port=_validate_port("smtp_port", _field_with_default(d, "smtp_port", int, 587)),
    tls_cert_path=None if tls_cert_path is None else pathlib.Path(tls_cert_path),
    tls_key_path=None if tls_key_path is None else pathlib.Path(tls_key_path),
  )

def oauth_provider_config_from_dict(d: object) -> OAuthProviderConfig:
  return OAuthProviderConfig(
    imap_host=_field(d, "imap_host", str),
    imap_port=_validate_port("imap_port", _field(d, "imap_port", int)),
    imap_tlsmode=TLSMode(_field(d, "imap_tlsmode", str).upper()),
    smtp_host=_field(d, "smtp_host", str),
    smtp_port=_validate_port("smtp_port", _field(d, "smtp_port", int)),
    smtp_tlsmode=TLSMode(_field(d, "smtp_tlsmode", str).upper()),
    scope=_field(d, "scope", str),
    client_id=_field(d, "client_id", str),
    client_secret=_optional_field(d, "client_secret", str),
    authorization_base_url=_field(d, "authorization_base_url", str),
    token_url=_field(d, "token_url", str),
    redirect_url=_field(d, "redirect_url", str),
  )

def provider_config_from_dict(d: object) -> ProviderConfig:
  return ProviderConfig(
    imap_host=_field(d, "imap_host", str),
    imap_port=_validate_port("imap_port", _field(d, "imap_port", int)),
    imap_tlsmode=TLSMode(_field(d, "imap_tlsmode", str).upper()),
    smtp_host=_field(d, "smtp_host", str),
    smtp_port=_validate_port("smtp_port", _field(d, "smtp_port", int)),
    smtp_tlsmode=TLSMode(_field(d, "smtp_tlsmode", str).upper()),
    scope=_optional_field(d, "scope", str),
    client_id=_optional_field(d, "client_id", str),
    client_secret=_optional_field(d, "client_secret", str),
    authorization_base_url=_optional_field(d, "authorization_base_url", str),
    token_url=_optional_field(d, "token_url", str),
    redirect_url=_optional_field(d, "redirect_url", str),
  )

def oauth_token_response_from_dict(d: object) -> OAuthTokenResponse:
  token_type = _field(d, "token_type", str)
  if token_type != "Bearer":
    raise ValueError(f"wrong token response token_type: '{token_type}'")
  return OAuthTokenResponse(
    token_type=token_type,
    expires_in=_field(d, "expires_in", int),
    access_token=_field(d, "access_token", str),
    refresh_token=_optional_field(d, "refresh_token", str),
  )
