import asyncio, datetime, re
from collections.abc import Callable
from typing import Protocol

class IMAPReadError(Exception):
  pass

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

# RFC 9051 §9 formal syntax — byte sets for atom/astring termination.
# atom-specials = "(" / ")" / "{" / SP / CTL / list-wildcards / quoted-specials / resp-specials
# list-wildcards = "*" / "%"   quoted-specials = DQUOTE / "\"   resp-specials = "]" / "^"
_ATOM_TERM = frozenset(b'(){} \t\r\n*%"\\]^')
# astring-char = atom-char / resp-specials  (includes "]" and "^")
_ASTRING_TERM = frozenset(b'(){} \t\r\n*%"\\')

class _StreamReaderLike(Protocol):
  """Protocol for the underlying reader IMAPReader wraps."""
  async def read(self, n: int) -> bytes: ...
  def at_eof(self) -> bool: ...

class IMAPReader:
  """Grammar-aware streaming reader for IMAP (RFC 9051 §9).

  Wraps an asyncio.StreamReader and provides primitives that consume exactly
  the bytes a grammar production requires — atoms, quoted strings, literals,
  numbers, nstrings, astrings — plus low-level helpers (peek, read_const,
  read_until, read_text_line).  No IMAP-level concept (envelope, bodystructure,
  flag list, FETCH item) lives here; callers compose primitives."""

  def __init__(self, reader: _StreamReaderLike, pre_read: int = 64) -> None:
    self._reader: _StreamReaderLike = reader
    self._pre_read: int = pre_read
    self._buf: bytearray = bytearray()
    self._at_eof: bool = False

  @property
  def at_eof(self) -> bool:
    return not self._buf and (self._at_eof or self._reader.at_eof())

  async def _ensure(self, n: int) -> None:
    while len(self._buf) < n:
      if self._at_eof:
        raise asyncio.IncompleteReadError(bytes(self._buf), n)
      data = await self._reader.read(max(n - len(self._buf), self._pre_read))
      if not data:
        self._at_eof = True
        raise asyncio.IncompleteReadError(bytes(self._buf), n)
      self._buf.extend(data)

  async def peek(self, n: int = 1) -> bytes:
    try:
      await self._ensure(n)
    except asyncio.IncompleteReadError:
      pass
    return bytes(self._buf[:n])

  async def readexactly(self, n: int) -> bytes:
    await self._ensure(n)
    result = bytes(self._buf[:n])
    del self._buf[:n]
    return result

  async def read_until(self, delim: bytes) -> bytes:
    while True:
      idx = self._buf.find(delim)
      if idx != -1:
        result = bytes(self._buf[:idx])
        del self._buf[:idx + len(delim)]
        return result
      if self._at_eof:
        raise asyncio.IncompleteReadError(bytes(self._buf), None)
      data = await self._reader.read(self._pre_read)
      if not data:
        self._at_eof = True
        if not self._buf:
          raise asyncio.IncompleteReadError(b"", None)
      else:
        self._buf.extend(data)

  async def _gather_while(self, keep: Callable[[int], bool]) -> bytes:
    result = bytearray()
    while True:
      if not self._buf:
        try:
          await self._ensure(1)
        except asyncio.IncompleteReadError:
          break
      i = 0
      n = len(self._buf)
      while i < n and keep(self._buf[i]):
        i += 1
      if i:
        result.extend(self._buf[:i])
        del self._buf[:i]
      if i < n:
        break
    return bytes(result)

  async def skip_sp(self) -> None:
    c = await self.readexactly(1)
    if c != b' ':
      raise IMAPReadError(f"expected SP, got {c!r}")

  async def skip_wsp(self) -> None:
    _ = await self._gather_while(lambda b: b == 0x20)

  async def read_crlf(self) -> None:
    await self.read_const(b'\r\n')

  async def read_const(self, expected: bytes) -> None:
    result = await self.readexactly(len(expected))
    if result != expected:
      raise IMAPReadError(f"expected {expected!r}, got {result!r}")

  async def read_atom(self) -> bytes:
    result = await self._gather_while(lambda b: b not in _ATOM_TERM)
    if not result:
      raise IMAPReadError("expected atom")
    return result

  async def read_tag(self) -> bytes:
    """Read an untagged marker `*` or a tagged atom (e.g. A1)."""
    c = await self.peek(1)
    if c == b'*':
      _ = await self.readexactly(1)
      return b'*'
    return await self.read_atom()

  async def read_number(self) -> int:
    result = await self._gather_while(lambda b: 0x30 <= b <= 0x39)
    if not result:
      raise IMAPReadError("expected number")
    return int(result)

  async def read_quoted(self) -> bytes:
    await self.read_const(b'"')
    result = bytearray()
    while True:
      c = await self.readexactly(1)
      if c == b'\\':
        result.extend(await self.readexactly(1))
      elif c == b'"':
        break
      else:
        result.extend(c)
    return bytes(result)

  async def read_literal(self) -> bytes:
    await self.read_const(b'{')
    count_s = await self.read_until(b'}')
    if count_s.endswith(b'+'):
      count_s = count_s[:-1]
    await self.read_crlf()
    return await self.readexactly(int(count_s))

  async def read_astring(self) -> bytes:
    c = await self.peek(1)
    if c == b'"':
      return await self.read_quoted()
    if c == b'{':
      return await self.read_literal()
    result = await self._gather_while(lambda b: b not in _ASTRING_TERM)
    if not result:
      raise IMAPReadError("expected astring")
    return result

  async def read_nstring(self) -> bytes | None:
    c = await self.peek(1)
    if c == b'"':
      return await self.read_quoted()
    if c == b'{':
      return await self.read_literal()
    result = await self.read_atom()
    if result.upper() == b'NIL':
      return None
    return result

  async def read_token(self) -> bytes:
    """Read one raw token respecting () [] nesting, quoted strings, and literals.
    Stops at SP or ) at depth 0, or CRLF.  Returns the raw token bytes
    (including delimiters for quoted/literal/group tokens)."""
    c = await self.peek(1)
    if not c:
      raise IMAPReadError("expected token, got EOF")
    if c == b'"':
      return await self._read_quoted_raw()
    if c == b'{':
      return await self._read_literal_raw()
    return await self._read_token_run()

  async def _read_quoted_raw(self) -> bytes:
    result = bytearray(await self.readexactly(1))  # consume opening "
    while True:
      c = await self.readexactly(1)
      result.extend(c)
      if c == b'\\':
        result.extend(await self.readexactly(1))
      elif c == b'"':
        break
    return bytes(result)

  async def _read_literal_raw(self) -> bytes:
    header = bytearray()
    while True:
      c = await self.readexactly(1)
      header.extend(c)
      if c == b'}':
        break
    await self.read_crlf()
    count = int(header[1:-1].rstrip(b'+'))
    data = await self.readexactly(count)
    return bytes(header) + b'\r\n' + data

  async def _read_token_run(self) -> bytes:
    result = bytearray()
    depth = 0
    while True:
      c = await self.peek(1)
      if not c:
        break
      b = c[0]
      if b in (0x28, 0x5B):  # ( [
        depth += 1
      elif b in (0x29, 0x5D):  # ) ]
        if depth == 0:
          break
        depth -= 1
      elif b == 0x20 and depth == 0:  # SP
        break
      elif b in (0x0D, 0x0A):  # CR LF
        break
      result.extend(await self.readexactly(1))
    if not result:
      raise IMAPReadError("expected token")
    return bytes(result)

  async def read_text_line(self) -> bytes:
    return await self.read_until(b'\r\n')
