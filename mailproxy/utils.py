import re, asyncio, io, os

def match_line(pattern: str, line: str, flags: int = re.I) -> dict[str, str] | None:
  m = re.fullmatch(pattern, line, flags)
  if m is None: return None
  else: return { "": "" } | m.groupdict()

def match_lineb(pattern: bytes, line: bytes, flags: int = re.I) -> dict[str, bytes] | None:
  m = re.fullmatch(pattern, line, flags)
  if m is None: return None
  else: return { "": b"" } | m.groupdict()

class ReadValidationError(Exception):
  pass

class BacktrackingStreamReader:
  def __init__(self, reader: asyncio.StreamReader, pre_read: int = 64) -> None:
    self._reader = reader
    self._pre_read = pre_read
    self._buf = bytearray()
    self._pos = 0
    self._at_eof = False

  @property
  def at_eof(self):
    return self._at_eof

  async def read_crlf(self):
    await self.read_const(b"\r\n")

  async def read_line(self):
    return await self.readuntil(b"\r\n")

  async def readuntil_re(self, until: bytes | tuple[bytes, ...], pattern: bytes, exclude_delimiter = False, flags = 0):
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
    start_pos = self._pos

    while True:
      read_n = self._pos - start_pos
      for tok in runtil:
        if len(tok) > read_n:
          break
        if self._buf[:self._pos].endswith(tok):
          end_pos = self._pos - len(tok) if exclude_delimiter else self._pos
          return bytes(self._buf[start_pos:end_pos])
      if len(await self._read(1)) == 0:
        raise asyncio.IncompleteReadError(bytes(self._buf[start_pos:self._pos]), None)

  async def readexactly(self, n: int):
    start_pos = self._pos
    while self._pos - start_pos < n:
      result = await self._read(n + self._pos - start_pos)
      if len(result) == 0:
        raise asyncio.IncompleteReadError(bytes(self._buf[start_pos:self._pos]), n)
    assert self._pos == start_pos + n, "position should be startpos + n here"
    return bytes(self._buf[start_pos:self._pos])

  def reset(self):
    self._pos = 0

  def mark(self):
    del self._buf[:self._pos]
    self._pos = 0

  async def _read(self, n: int = -1):
    if n == -1:
      base_res = await self._reader.read()
      self._at_eof = len(base_res) == 0
      self._buf.extend(base_res)
    if len(self._buf) == self._pos:
      base_res = await self._reader.read(max(n, self._pre_read))
      self._at_eof = len(base_res) == 0
      self._buf.extend(base_res)
    result = self._buf[self._pos:self._pos + n]
    self._pos += len(result)
    return result
