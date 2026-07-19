import re, base64, importlib.resources, json, pathlib, ssl, typing
from typing import TypeGuard


def json_loads_object(s: str) -> object:
  result: object = typing.cast(object, json.loads(s))
  return result

def is_str_object_dict(d: object) -> TypeGuard[dict[str, object]]:
  if not isinstance(d, dict):
    return False
  return all(isinstance(key, str) for key in typing.cast(dict[object, object], d))

def is_object_list(value: object) -> TypeGuard[list[object]]:
  return isinstance(value, list)

def match_line(pattern: str, line: str, flags: int = re.I) -> dict[str, str] | None:
  m = re.fullmatch(pattern, line, flags)
  if m is None: return None
  else: return { "": "" } | m.groupdict()

def match_lineb(pattern: bytes, line: bytes, flags: int = re.I) -> dict[str, bytes] | None:
  m = re.fullmatch(pattern, line, flags)
  if m is None: return None
  else: return { "": b"" } | m.groupdict()

def server_tls_context(cert_path: pathlib.Path | None, key_path: pathlib.Path | None) -> ssl.SSLContext:
  ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  if cert_path is not None and key_path is not None:
    ctx.load_cert_chain(cert_path, key_path)
  else:
    with importlib.resources.path("mailproxy.assets", "dummy-cert.pem") as dummy_cert, \
        importlib.resources.path("mailproxy.assets", "dummy-key.pem") as dummy_key:
      ctx.load_cert_chain(dummy_cert, dummy_key)
  return ctx

def encode_7bit_mailbox_name(s: str):
    return re.sub(
        r'[^\x00-\x7F]+',
        lambda m: '&' + base64.b64encode(m.group().encode('utf-16be')).decode().rstrip('=').replace('/', ',') + '-',
        s.replace('&', '&-')
    )

def decode_7bit_mailbox_name(s: str):
    return re.sub(
        r'&([^&-]+)-',
        lambda m: base64.b64decode(m.group(1).replace(',', '/') + '=' * ((4 - len(m.group(1)) % 4) % 4)).decode('utf-16be'),
        s.replace('&-', '&')
    )
