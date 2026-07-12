import datetime, re

_QUOTED_RE = re.compile(rb'"(?:[^"\\]|\\.)*"')
_LITERAL_RE = re.compile(rb'\{(\d+)\}')
_SEARCH_TOKEN_RE = re.compile(rb'"(?:[^"\\]|\\.)*"|[^\s]+')
_FETCH_LINE_RE = re.compile(rb'\* \d+ FETCH \((?P<items>.*)\)', re.DOTALL)

def imap_to_quoted_string(value: bytes) -> bytes:
  return b"\"%s\"" % (value.replace(b"\"", b"\\\""),)

def list_match(name: str, pattern: str) -> bool:
  regex = "".join(".*" if c == "*" else "[^/]*" if c == "%" else re.escape(c) for c in pattern)
  return re.fullmatch(regex, name) is not None

def flags_to_s(flags: bytes | list[bytes]) -> str:
  if isinstance(flags, bytes):
    parts = flags.split(b" ") if flags else []
  else:
    parts = flags
  normalized = [f.decode("ascii").lstrip("\\") for f in parts if f.strip()]
  return "\\" + "\\".join(normalized) + "\\" if normalized else "\\\\"

def parse_internal_date(date_s: bytes) -> int:
  dt = datetime.datetime.strptime(date_s.decode("ascii"), "%d-%b-%Y %H:%M:%S %z")
  return int(dt.timestamp())

_MONTHS = (b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec")

def format_internal_date(ts: int) -> bytes:
  dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
  return b"%02d-%s-%04d %02d:%02d:%02d +0000" % (dt.day, _MONTHS[dt.month - 1], dt.year, dt.hour, dt.minute, dt.second)

def split_message(data: bytes) -> tuple[bytes, bytes]:
  for sep in (b"\r\n\r\n", b"\n\n"):
    if (idx := data.find(sep)) != -1:
      return data[:idx], data[idx + len(sep):]
  return data, b""

def _skip_quoted(data: bytes, pos: int) -> int:
  """Return the position after a quoted string starting at data[pos]."""
  m = _QUOTED_RE.match(data, pos)
  return m.end() if m else pos + 1

def _skip_literal(data: bytes, pos: int) -> int:
  """Return the position after a {n} literal starting at data[pos]."""
  m = _LITERAL_RE.match(data, pos)
  return m.end() + int(m.group(1)) if m else pos + 1

def split_fetch_items(items_s: bytes) -> list[bytes]:
  """Split FETCH items into top-level tokens, splitting on spaces at bracket
  depth 0 while keeping quoted strings, {n} literals, and bracketed groups intact."""
  tokens: list[bytes] = []
  pos = 0
  n = len(items_s)
  while pos < n:
    while pos < n and items_s[pos] == ord(" "):
      pos += 1
    if pos >= n:
      break
    start = pos
    depth = 0
    while pos < n:
      char = items_s[pos]
      if char == ord('"'):
        pos = _skip_quoted(items_s, pos)
      elif char == ord("{"):
        pos = _skip_literal(items_s, pos)
      elif char in (ord("("), ord("[")):
        depth += 1
        pos += 1
      elif char in (ord(")"), ord("]")):
        depth -= 1
        pos += 1
      elif char == ord(" ") and depth == 0:
        break
      else:
        pos += 1
    tokens.append(items_s[start:pos])
  return tokens

def _strip_pair(val: bytes, open_ch: bytes, close_ch: bytes) -> bytes:
  """Strip a matching pair of surrounding delimiter bytes, if present."""
  if len(val) >= 2 and val[:1] == open_ch and val[-1:] == close_ch:
    return val[1:-1]
  return val

def _literal_body(val: bytes) -> bytes:
  """Extract the body from a {n}... literal, or return val unchanged."""
  m = re.fullmatch(rb'\{(\d+)\}(.*)', val, re.DOTALL)
  return m.group(2)[:int(m.group(1))] if m else val

def parse_fetch_line(line: bytes) -> dict[bytes, bytes | int] | None:
  m = _FETCH_LINE_RE.match(line)
  if m is None:
    return None
  result: dict[bytes, bytes | int] = {}
  tokens = split_fetch_items(m.group("items"))
  i = 0
  while i + 1 < len(tokens):
    key, val = tokens[i].upper(), tokens[i + 1]
    if key == b"UID":
      if val.isdigit(): result[b"UID"] = int(val)
    elif key == b"FLAGS":
      result[b"FLAGS"] = _strip_pair(val, b"(", b")")
    elif key == b"INTERNALDATE":
      result[b"INTERNALDATE"] = _strip_pair(val, b'"', b'"')
    elif key == b"RFC822.SIZE":
      if val.isdigit(): result[b"RFC822.SIZE"] = int(val)
    elif key in (b"BODY[]", b"RFC822"):
      result[b"BODY[]"] = _literal_body(val)
    i += 2
  return result

def parse_sequence_set(set_s: bytes, max_val: int) -> list[int]:
  result: list[int] = []
  seen: set[int] = set()
  for part in set_s.split(b","):
    part = part.strip()
    if not part:
      continue
    if b":" in part:
      lo_s, hi_s = part.split(b":", 1)
      lo = max_val if lo_s == b"*" else int(lo_s)
      hi = max_val if hi_s == b"*" else int(hi_s)
      for num in range(min(lo, hi), max(lo, hi) + 1):
        if 1 <= num <= max_val and num not in seen:
          seen.add(num)
          result.append(num)
    else:
      num = max_val if part == b"*" else int(part)
      if 1 <= num <= max_val and num not in seen:
        seen.add(num)
        result.append(num)
  return result

def flags_s_to_set(flags_s: str) -> set[str]:
  return set(f for f in flags_s.strip("\\").split("\\") if f)

def flags_set_to_s(flags: set[str]) -> str:
  return "\\" + "\\".join(sorted(flags)) + "\\" if flags else "\\\\"

def flags_to_list_b(flags_s: str) -> list[bytes]:
  return [b"\\" + f.encode("ascii") for f in flags_s.strip("\\").split("\\") if f]

def flags_to_b(flags_s: str) -> bytes:
  return b" ".join(flags_to_list_b(flags_s))

def tokenize_search_criteria(criteria_s: bytes) -> list[bytes]:
  tokens: list[bytes] = []
  for m in _SEARCH_TOKEN_RE.finditer(criteria_s):
    token = m.group()
    if token[:1] == b'"':
      tokens.append(re.sub(rb'\\(.)', rb'\1', token[1:-1]))
    else:
      tokens.append(token)
  return tokens

def get_header(data: bytes, name: str) -> bytes:
  header, _ = split_message(data)
  name_b = (name + ":").encode("ascii").lower()
  lines = header.split(b"\r\n")
  result = bytearray()
  for line in lines:
    if line.lower().startswith(name_b):
      result.extend(line[len(name_b):].strip())
    elif result and (line[:1] in (b" ", b"\t")):
      result.extend(b" " + line.strip())
    elif result:
      break
  return bytes(result)

def filter_headers(data: bytes, field_names: list[bytes]) -> bytes:
  header, _ = split_message(data)
  lines = header.split(b"\r\n")
  result: list[bytes] = []
  current_fields: list[bytes] = []
  for line in lines:
    matched = False
    for field in field_names:
      field_lower = field.lower() + b":"
      if line.lower().startswith(field_lower):
        current_fields.append(line)
        matched = True
        break
    if not matched:
      if current_fields and (line[:1] in (b" ", b"\t")):
        current_fields.append(line)
      elif current_fields:
        result.extend(current_fields)
        current_fields = []
  if current_fields:
    result.extend(current_fields)
  return b"\r\n".join(result) + (b"\r\n" if result else b"")

def header_contains(data: bytes, name: str, needle: bytes) -> bool:
  value = get_header(data, name)
  return needle.lower() in value.lower()

def body_contains(data: bytes, needle: bytes) -> bool:
  _, body = split_message(data)
  return needle.lower() in body.lower()

def text_contains(data: bytes, needle: bytes) -> bool:
  header, body = split_message(data)
  return needle.lower() in header.lower() or needle.lower() in body.lower()

def parse_search_date(date_s: bytes) -> int:
  dt = datetime.datetime.strptime(date_s.decode("ascii"), "%d-%b-%Y")
  return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp())

class IMAPCommandFailedError(Exception):
  pass
