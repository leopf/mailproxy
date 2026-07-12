import re, asyncio, base64, json
from typing import TypeGuard


def json_loads_object(s: str) -> object:
  result: object = json.loads(s)
  return result

def is_str_object_dict(d: object) -> TypeGuard[dict[str, object]]:
  if not isinstance(d, dict):
    return False
  return all(isinstance(key, str) for key in d)

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

def encode_7bit_mailbox_name(s: str):
    return re.sub(
        r'[^\x00-\x7F]+',
        lambda m: '&' + base64.b64encode(m.group().encode('utf-16be')).decode().rstrip('=').replace('/', ',') + '-',
        s.replace('&', '&-')
    )

def decode_7bit_mailbox_name(s: str):
    return re.sub(
        r'&([^&-]+)-',
        lambda m: base64.b64decode(m.group(1).replace(',', '/') + '==='[:len(m.group(1)) % 4]).decode('utf-16be'),
        s.replace('&-', '&')
    )

class ReadValidationError(Exception):
  pass

class ScopedStreamReader:
  def __init__(self, reader: asyncio.StreamReader, pre_read: int = 64) -> None:
    self._reader: asyncio.StreamReader = reader
    self._pre_read: int = pre_read
    self._buf: bytearray = bytearray()
    self._pos_scope: list[int] = [0]
    self._at_eof: bool = False

  @property
  def at_eof(self):
    return self._at_eof

  @property
  def position(self):
    return self._pos_scope[-1]

  async def read_crlf(self):
    await self.read_const(b"\r\n")

  async def read_line(self):
    return await self.readuntil(b"\r\n")

  async def readuntil_re(self, until: bytes | tuple[bytes, ...], pattern: bytes, exclude_delimiter: bool = False, flags: int = 0):
    result = await self.readuntil(until, exclude_delimiter=exclude_delimiter)
    if (m:=re.fullmatch(pattern, result, flags)) is None:
      raise ReadValidationError(f"Failed to match pattern '{pattern}' against '{result}'.")
    return m.groupdict() | { "": b"" }

  async def read_const(self, value: bytes, case_sensitive: bool = True):
    value = value if case_sensitive else value.lower()
    result = await self.readexactly(len(value))
    result = result if case_sensitive else result.lower()
    if result != value:
      raise ReadValidationError(f"expected {value}, got {result}!")

  async def readuntil(self, until: bytes | tuple[bytes, ...], exclude_delimiter: bool = True):
    runtil = (until,) if isinstance(until, bytes) else tuple(sorted(until, key=lambda tok: len(tok)))
    start_pos = self.position

    while True:
      read_n = self.position - start_pos
      for tok in runtil:
        if len(tok) > read_n:
          break
        if self._buf[:self.position].endswith(tok):
          end_pos = self.position - len(tok) if exclude_delimiter else self.position
          return bytes(self._buf[start_pos:end_pos])
      if len(await self._read(1)) == 0:
        raise asyncio.IncompleteReadError(bytes(self._buf[start_pos:self.position]), None)

  async def readexactly(self, n: int):
    start_pos = self.position
    while self.position - start_pos < n:
      result = await self._read(n + self.position - start_pos)
      if len(result) == 0:
        raise asyncio.IncompleteReadError(bytes(self._buf[start_pos:self.position]), n)
    assert self.position == start_pos + n, "position should be startpos + n here"
    return bytes(self._buf[start_pos:self.position])

  def close_scope(self, advance: bool):
    if len(self._pos_scope) == 1:
      raise RuntimeError("Invalid call to close_scope")

    top_scope = self._pos_scope.pop()

    if advance:
      self._pos_scope[-1] = top_scope

    if self._pos_scope[0] > 0:
      trim_len = self._pos_scope[0]
      del self._buf[:trim_len]
      self._pos_scope = [ p - trim_len for p in self._pos_scope ]

  def open_scope(self):
    self._pos_scope.append(self._pos_scope[-1])

  async def _read(self, n: int = -1):
    if n == -1:
      base_res = await self._reader.read()
      self._at_eof = len(base_res) == 0
      self._buf.extend(base_res)
    if len(self._buf) == self.position:
      base_res = await self._reader.read(max(n, self._pre_read))
      self._at_eof = len(base_res) == 0
      self._buf.extend(base_res)
    result = self._buf[self.position:self.position + n]
    self._pos_scope[-1] += len(result)
    return result
