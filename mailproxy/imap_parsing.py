import datetime, re

def imap_to_quoted_string(value: bytes) -> bytes:
  return b"\"%s\"" % (value.replace(b"\"", b"\\\""),)

def list_match(name: str, pattern: str) -> bool:
  regex = "".join(".*" if c == "*" else "[^/]*" if c == "%" else re.escape(c) for c in pattern)
  return re.fullmatch(regex, name) is not None

def flags_to_s(flags: bytes | list[bytes]) -> str:
  if isinstance(flags, bytes):
    s = flags.decode("ascii") if flags else ""
    return "\\" + s.replace(" ", "\\") + "\\" if s else "\\\\"
  return "\\" + "\\".join(f.decode("ascii") for f in flags) + "\\" if flags else "\\\\"

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

def split_fetch_items(items_s: bytes) -> list[bytes]:
  result: list[bytes] = []
  i = 0
  while i < len(items_s):
    while i < len(items_s) and items_s[i:i+1] == b" ":
      i += 1
    if i >= len(items_s):
      break
    start = i
    paren_depth = 0
    bracket_depth = 0
    while i < len(items_s):
      c = items_s[i:i+1]
      if c == b"(":
        paren_depth += 1
      elif c == b")":
        paren_depth -= 1
      elif c == b"[":
        bracket_depth += 1
      elif c == b"]":
        bracket_depth -= 1
      elif c == b" " and paren_depth == 0 and bracket_depth == 0:
        break
      i += 1
    result.append(items_s[start:i])
  return result

def parse_fetch_line(line: bytes) -> dict[bytes, bytes | int] | None:
  m = re.fullmatch(rb'\* \d+ FETCH \((?P<items>.*)\)', line, re.DOTALL)
  if m is None:
    return None
  items = m.group("items")
  result: dict[bytes, bytes | int] = {}

  if (body_match := re.search(rb'BODY\[\] \{(\d+)\}', items)) is not None:
    n = int(body_match.group(1))
    body_start = body_match.end()
    result[b"BODY[]"] = items[body_start:body_start + n]
    items = items[:body_match.start()] + items[body_start + n:]

  if (uid_m := re.search(rb'UID (\d+)', items)) is not None:
    result[b"UID"] = int(uid_m.group(1))
  if (flags_m := re.search(rb'FLAGS \((.*?)\)', items, re.DOTALL)) is not None:
    result[b"FLAGS"] = flags_m.group(1)
  if (date_m := re.search(rb'INTERNALDATE "(.*?)"', items, re.DOTALL)) is not None:
    result[b"INTERNALDATE"] = date_m.group(1)
  if (size_m := re.search(rb'RFC822\.SIZE (\d+)', items)) is not None:
    result[b"RFC822.SIZE"] = int(size_m.group(1))

  return result

def parse_sequence_set(set_s: bytes, max_val: int) -> list[int]:
  result: list[int] = []
  for part in set_s.split(b","):
    part = part.strip()
    if b":" in part:
      lo_s, hi_s = part.split(b":", 1)
      lo = max_val if lo_s == b"*" else int(lo_s)
      hi = max_val if hi_s == b"*" else int(hi_s)
      result.extend(range(min(lo, hi), max(lo, hi) + 1))
    else:
      result.append(max_val if part == b"*" else int(part))
  return [n for n in result if 1 <= n <= max_val]

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
  i = 0
  while i < len(criteria_s):
    while i < len(criteria_s) and criteria_s[i:i+1] == b" ":
      i += 1
    if i >= len(criteria_s):
      break
    if criteria_s[i:i+1] == b'"':
      i += 1
      start = i
      while i < len(criteria_s) and criteria_s[i:i+1] != b'"':
        i += 1
      tokens.append(criteria_s[start:i])
      i += 1
    else:
      start = i
      while i < len(criteria_s) and criteria_s[i:i+1] != b" ":
        i += 1
      tokens.append(criteria_s[start:i])
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
