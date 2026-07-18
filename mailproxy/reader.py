import asyncio
from collections.abc import Awaitable, Callable
from typing import Protocol


class ReadError(Exception):
  pass


class _StreamReaderLike(Protocol):
  async def read(self, n: int) -> bytes: ...
  def at_eof(self) -> bool: ...


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

  async def skip_sp(self) -> None:
    try:
      c = await self.readexactly(1)
    except asyncio.IncompleteReadError as e:
      raise ReadError(f"expected SP, got {bytes(e.partial)!r}") from e
    if c != b" ":
      raise ReadError(f"expected SP, got {c!r}")

  async def skip_wsp(self) -> None:
    while True:
      n = len(self._buf)
      i = self._cursors[-1]
      while i < n and self._buf[i] == 0x20:
        i += 1
      self._cursors[-1] = i
      if i < n:
        return
      if self._at_eof:
        return
      self._maybe_evict()
      data = await self._reader.read(self._pre_read)
      if not data:
        self._at_eof = True
        return
      self._buf.extend(data)

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
