import asyncio, re
from collections.abc import Awaitable, Callable
from typing import Protocol


class ReadError(Exception):
  pass


class _StreamReaderLike(Protocol):
  async def read(self, n: int) -> bytes: ...
  def at_eof(self) -> bool: ...


def _literal_prefix(pattern: bytes) -> tuple[bytes, bool]:
  ci = pattern.startswith(b"(?i)")
  i = 4 if ci else 0
  prefix = bytearray()
  while i < len(pattern):
    c = pattern[i]
    if c in b"[]().*+?{|^\\":
      break
    prefix.append(c)
    i += 1
  return bytes(prefix), ci


def _partial_prefixes(pattern: bytes) -> list[bytes]:
  prefixes: list[bytes] = []
  depth = 0
  i = 0
  if pattern.startswith(b"(?i)"):
    i = 4
  while i < len(pattern):
    c = pattern[i]
    if c == ord(b'(') and i + 1 < len(pattern) and pattern[i + 1] == ord(b'?'):
      i = pattern.index(b')', i) + 1
    elif c == ord(b'['):
      i = pattern.index(b']', i) + 1
    elif c == ord(b'('):
      depth += 1
      i += 1
    elif c == ord(b')'):
      depth -= 1
      i += 1
      if depth == 0:
        prefixes.append(pattern[:i])
    elif c in b"*+?" and depth == 0:
      i += 1
      prefixes.append(pattern[:i])
    else:
      i += 1
  return prefixes


def _is_prefix(data: bytes, lit: bytes, ci: bool) -> bool:
  if len(data) > len(lit):
    return False
  if ci:
    return lit[:len(data)].lower() == data.lower()
  return lit[:len(data)] == data


def _is_partial_match(data: bytes, lit_prefix: bytes, ci: bool, partial_compiled: list[re.Pattern[bytes]]) -> bool:
  if lit_prefix and _is_prefix(data, lit_prefix, ci):
    return True
  for pc in partial_compiled:
    pm = pc.match(data)
    if pm is not None and pm.end() == len(data):
      return True
  return False


class ScopedReader:
  _reader: _StreamReaderLike
  _pre_read: int
  _buf: bytearray
  _cursors: list[int]
  _at_eof: bool

  def __init__(self, reader: _StreamReaderLike, pre_read: int = 64) -> None:
    self._reader = reader
    self._pre_read = pre_read
    self._buf = bytearray()
    self._cursors = [0]
    self._at_eof = False

  @property
  def at_eof(self) -> bool:
    return self._cursors[-1] >= len(self._buf) and (self._at_eof or self._reader.at_eof())

  @property
  def buffer_size(self) -> int:
    return len(self._buf)

  def open_scope(self) -> None:
    self._cursors.append(self._cursors[-1])

  def commit_scope(self) -> None:
    if len(self._cursors) == 1:
      raise RuntimeError("cannot commit root scope")
    self._cursors[-2] = self._cursors[-1]
    _ = self._cursors.pop()
    self._maybe_evict()

  def rollback_scope(self) -> None:
    if len(self._cursors) == 1:
      raise RuntimeError("cannot rollback root scope")
    _ = self._cursors.pop()

  def _maybe_evict(self) -> None:
    if len(self._cursors) == 1 and self._cursors[0] > 0:
      del self._buf[:self._cursors[0]]
      self._cursors[0] = 0

  async def _ensure(self, n: int) -> None:
    while self._cursors[-1] + n > len(self._buf):
      self._maybe_evict()
      if self._at_eof:
        raise asyncio.IncompleteReadError(bytes(self._buf[self._cursors[-1]:]), n)
      needed = (self._cursors[-1] + n) - len(self._buf)
      data = await self._reader.read(max(needed, self._pre_read))
      if not data:
        self._at_eof = True
        raise asyncio.IncompleteReadError(bytes(self._buf[self._cursors[-1]:]), n)
      self._buf.extend(data)

  async def readexactly(self, n: int) -> bytes:
    if n < 0:
      raise ValueError("n must be non-negative")
    await self._ensure(n)
    start = self._cursors[-1]
    self._cursors[-1] = start + n
    return bytes(self._buf[start:start + n])

  async def read_until(self, delim: bytes) -> bytes:
    if not delim:
      raise ValueError("delim must not be empty")
    while True:
      idx = self._buf.find(delim, self._cursors[-1])
      if idx != -1:
        start = self._cursors[-1]
        self._cursors[-1] = idx + len(delim)
        return bytes(self._buf[start:idx])
      if self._at_eof:
        raise asyncio.IncompleteReadError(bytes(self._buf[self._cursors[-1]:]), None)
      self._maybe_evict()
      data = await self._reader.read(self._pre_read)
      if not data:
        self._at_eof = True
      else:
        self._buf.extend(data)

  async def read_const(self, expected: bytes) -> bytes:
    try:
      result = await self.readexactly(len(expected))
    except asyncio.IncompleteReadError as e:
      raise ReadError(f"expected {expected!r}, got {bytes(e.partial)!r}") from e
    if result != expected:
      raise ReadError(f"expected {expected!r}, got {result!r}")
    return result

  async def read_re(self, pattern: bytes) -> re.Match[bytes]:
    compiled = re.compile(pattern)
    lit_prefix, ci = _literal_prefix(pattern)
    partial_compiled = [re.compile(p) for p in _partial_prefixes(pattern)]
    while True:
      start = self._cursors[-1]
      n = len(self._buf)
      m = compiled.match(self._buf, start)
      if m is not None:
        if m.end() < n or (m.end() == start and start < n) or self._at_eof:
          self._cursors[-1] = m.end()
          return m
      elif start < n:
        data = bytes(self._buf[start:n])
        if not _is_partial_match(data, lit_prefix, ci, partial_compiled):
          raise ReadError(f"pattern {pattern!r} did not match")
      if self._at_eof:
        if m is not None:
          self._cursors[-1] = m.end()
          return m
        if start >= n:
          raise asyncio.IncompleteReadError(b"", None)
        data = bytes(self._buf[start:n])
        if _is_partial_match(data, lit_prefix, ci, partial_compiled):
          raise asyncio.IncompleteReadError(data, None)
        raise ReadError(f"pattern {pattern!r} did not match")
      self._maybe_evict()
      data = await self._reader.read(self._pre_read)
      if not data:
        self._at_eof = True
      else:
        self._buf.extend(data)

  async def skip_re(self, pattern: bytes) -> None:
    _ = await self.read_re(pattern)

  async def read_crlf(self) -> None:
    _ = await self.read_const(b"\r\n")

  async def read_text_line(self) -> bytes:
    return await self.read_until(b"\r\n")

  async def read_one_of[T1, T2](
    self, r1: Callable[[], Awaitable[T1]], r2: Callable[[], Awaitable[T2]]
  ) -> T1 | T2:
    self.open_scope()
    try:
      result = await r1()
    except ReadError:
      self.rollback_scope()
    else:
      self.commit_scope()
      return result
    self.open_scope()
    try:
      result = await r2()
    except ReadError:
      self.rollback_scope()
    else:
      self.commit_scope()
      return result
    raise ReadError("read_one_of: no alternative matched")

  async def handle_options(self, options: list[Callable[[], Awaitable[None]]]) -> None:
    for option in options:
      self.open_scope()
      try:
        await option()
      except ReadError:
        self.rollback_scope()
        continue
      self.commit_scope()
      return
    raise ReadError("handle_options: no option matched")
