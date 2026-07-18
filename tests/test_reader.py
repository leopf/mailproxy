import asyncio, unittest
from collections.abc import Coroutine
from typing import Any
from mailproxy.reader import ScopedReader, ReadError


class _MockStreamReader:
  _data: bytes
  _pos: int
  _chunk: int

  def __init__(self, data: bytes, chunk: int = 0) -> None:
    self._data = data
    self._pos = 0
    self._chunk = chunk

  def at_eof(self) -> bool:
    return self._pos >= len(self._data)

  async def read(self, n: int = -1) -> bytes:
    if self._pos >= len(self._data):
      return b""
    if n == -1:
      end = len(self._data)
    else:
      end = self._pos + n
    if self._chunk > 0:
      end = min(end, self._pos + self._chunk)
    result = self._data[self._pos:end]
    self._pos += len(result)
    return result


def _make_reader(data: bytes, pre_read: int = 4, chunk: int = 0) -> ScopedReader:
  return ScopedReader(_MockStreamReader(data, chunk), pre_read=pre_read)


def _run[T](coro: Coroutine[Any, Any, T]) -> T:  # pyright: ignore[reportExplicitAny]
  return asyncio.run(coro)


# --- primitives ---


class TestReadexactly(unittest.TestCase):
  def test_simple(self):
    r = _make_reader(b"hello")
    self.assertEqual(_run(r.readexactly(5)), b"hello")

  def test_partial(self):
    r = _make_reader(b"hello")
    self.assertEqual(_run(r.readexactly(3)), b"hel")
    self.assertEqual(_run(r.readexactly(2)), b"lo")

  def test_eof_raises(self):
    r = _make_reader(b"hi")
    with self.assertRaises(asyncio.IncompleteReadError):
      _ = _run(r.readexactly(5))

  def test_zero_returns_empty(self):
    r = _make_reader(b"abc")
    self.assertEqual(_run(r.readexactly(0)), b"")

  def test_negative_raises(self):
    r = _make_reader(b"abc")
    with self.assertRaises(ValueError):
      _ = _run(r.readexactly(-1))


class TestReadUntil(unittest.TestCase):
  def test_simple(self):
    r = _make_reader(b"hello world")
    self.assertEqual(_run(r.read_until(b" ")), b"hello")

  def test_consumes_delim(self):
    r = _make_reader(b"a)b")
    self.assertEqual(_run(r.read_until(b")")), b"a")
    self.assertEqual(_run(r.readexactly(1)), b"b")

  def test_multibyte_delim(self):
    r = _make_reader(b"foo\r\nbar")
    self.assertEqual(_run(r.read_until(b"\r\n")), b"foo")
    self.assertEqual(_run(r.readexactly(3)), b"bar")

  def test_eof_no_delim_raises(self):
    r = _make_reader(b"no delim here")
    with self.assertRaises(asyncio.IncompleteReadError):
      _ = _run(r.read_until(b"\r\n"))

  def test_empty_delim_raises(self):
    r = _make_reader(b"abc")
    with self.assertRaises(ValueError):
      _ = _run(r.read_until(b""))


class TestReadRe(unittest.TestCase):
  def test_simple_match(self):
    r = _make_reader(b"HELLO world")
    m = _run(r.read_re(br"[A-Z]+"))
    self.assertEqual(m.group(0), b"HELLO")
    self.assertEqual(_run(r.readexactly(1)), b" ")

  def test_capture_group(self):
    r = _make_reader(b"MAIL FROM:<x@y>")
    m = _run(r.read_re(br"(?i)MAIL FROM: *<([^>]*)>"))
    self.assertEqual(m.group(1), b"x@y")

  def test_zero_width_match(self):
    r = _make_reader(b"hello")
    m = _run(r.read_re(br"\s*"))
    self.assertEqual(m.group(0), b"")
    self.assertEqual(_run(r.readexactly(1)), b"h")

  def test_inverse_pattern(self):
    r = _make_reader(b"FROM:<x>")
    m = _run(r.read_re(br"[^< \r]*"))
    self.assertEqual(m.group(0), b"FROM:")
    self.assertEqual(_run(r.read_const(b"<")), b"<")

  def test_empty_match_at_stop_byte(self):
    r = _make_reader(b"<x")
    m = _run(r.read_re(br"[^< \r]*"))
    self.assertEqual(m.group(0), b"")
    self.assertEqual(_run(r.read_const(b"<")), b"<")

  def test_streaming_extension(self):
    r = _make_reader(b"HE", pre_read=1, chunk=1)
    m = _run(r.read_re(br"[A-Z]+"))
    self.assertEqual(m.group(0), b"HE")
    self.assertTrue(r.at_eof)

  def test_streaming_extension_with_more_data(self):
    r = _make_reader(b"HE", pre_read=2, chunk=2)
    m = _run(r.read_re(br"[A-Z]+"))
    self.assertEqual(m.group(0), b"HE")

  def test_no_match_raises_read_error(self):
    r = _make_reader(b"123abc")
    with self.assertRaises(ReadError):
      _ = _run(r.read_re(br"[A-Z]+"))

  def test_eof_empty_buffer_raises_incomplete(self):
    r = _make_reader(b"")
    with self.assertRaises(asyncio.IncompleteReadError):
      _ = _run(r.read_re(br"[A-Z]+"))

  def test_zero_width_on_empty_at_eof(self):
    r = _make_reader(b"")
    m = _run(r.read_re(br"\s*"))
    self.assertEqual(m.group(0), b"")

  def test_match_reaches_end_at_eof(self):
    r = _make_reader(b"HE")
    m = _run(r.read_re(br"[A-Z]+"))
    self.assertEqual(m.group(0), b"HE")

  def test_match_reaches_end_not_eof_reads_more(self):
    r = _make_reader(b"HE world", pre_read=3)
    m = _run(r.read_re(br"[A-Z]+"))
    self.assertEqual(m.group(0), b"HE")
    self.assertEqual(_run(r.readexactly(1)), b" ")

  def test_star_consumes_run(self):
    r = _make_reader(b"   hello")
    m = _run(r.read_re(br" *"))
    self.assertEqual(m.group(0), b"   ")
    self.assertEqual(_run(r.readexactly(1)), b"h")

  def test_rollback_mid_match(self):
    r = _make_reader(b"X YZ", pre_read=1, chunk=1)
    async def opt1():
      _ = await r.read_re(br"[^ \r]*")
      raise ReadError("simulated")
    async def opt2():
      return await r.readexactly(4)
    result = _run(r.read_one_of(opt1, opt2))
    self.assertEqual(result, b"X YZ")

  def test_streaming_inverse_across_chunks(self):
    r = _make_reader(b"FROM:<x>", pre_read=2, chunk=2)
    m = _run(r.read_re(br"[^< \r]*"))
    self.assertEqual(m.group(0), b"FROM:")
    self.assertEqual(_run(r.read_const(b"<")), b"<")

  def test_partial_literal_waits_for_more(self):
    r = _make_reader(b"QUIT", pre_read=1, chunk=1)
    m = _run(r.read_re(br"(?i)QUIT"))
    self.assertEqual(m.group(0), b"QUIT")

  def test_partial_variable_waits_for_more(self):
    r = _make_reader(b"MAIL FROM: <x>", pre_read=2, chunk=2)
    m = _run(r.read_re(br"(?i)MAIL FROM: *<([^>]*)>"))
    self.assertEqual(m.group(1), b"x")

  def test_wrong_verb_fails_fast(self):
    r = _make_reader(b"NOOP\r\n")
    with self.assertRaises(ReadError):
      _ = _run(r.read_re(br"(?i)QUIT"))

  def test_eof_on_partial_raises_incomplete(self):
    r = _make_reader(b"QUI")
    with self.assertRaises(asyncio.IncompleteReadError):
      _ = _run(r.read_re(br"(?i)QUIT"))

  def test_eof_on_partial_variable_raises_incomplete(self):
    r = _make_reader(b"MAIL FROM: <x")
    with self.assertRaises(asyncio.IncompleteReadError):
      _ = _run(r.read_re(br"(?i)MAIL FROM: *<([^>]*)>"))

  def test_case_insensitive_verb(self):
    r = _make_reader(b"quit\r\n")
    m = _run(r.read_re(br"(?i)QUIT"))
    self.assertEqual(m.group(0), b"quit")


class TestSkipRe(unittest.TestCase):
  def test_consumes_run(self):
    r = _make_reader(b"   hello")
    _run(r.skip_re(br" *"))
    self.assertEqual(_run(r.readexactly(1)), b"h")

  def test_zero_width_noop(self):
    r = _make_reader(b"hello")
    _run(r.skip_re(br" *"))
    self.assertEqual(_run(r.readexactly(1)), b"h")

  def test_eof_no_raise(self):
    r = _make_reader(b"   ")
    _run(r.skip_re(br" *"))
    self.assertTrue(r.at_eof)

  def test_empty_buffer_zero_width(self):
    r = _make_reader(b"")
    _run(r.skip_re(br" *"))
    self.assertTrue(r.at_eof)

  def test_across_chunks(self):
    r = _make_reader(b"     hello", pre_read=2, chunk=2)
    _run(r.skip_re(br" *"))
    self.assertEqual(_run(r.readexactly(5)), b"hello")


class TestReadConst(unittest.TestCase):
  def test_match(self):
    r = _make_reader(b"OK\r\n")
    self.assertEqual(_run(r.read_const(b"OK")), b"OK")
    _run(r.read_crlf())

  def test_mismatch_raises(self):
    r = _make_reader(b"NO")
    with self.assertRaises(ReadError):
      _ = _run(r.read_const(b"OK"))

  def test_returns_bytes(self):
    r = _make_reader(b"FETCH")
    self.assertEqual(_run(r.read_const(b"FETCH")), b"FETCH")

  def test_empty_match(self):
    r = _make_reader(b"abc")
    self.assertEqual(_run(r.read_const(b"")), b"")


class TestReadCrlf(unittest.TestCase):
  def test_match(self):
    r = _make_reader(b"\r\nabc")
    _run(r.read_crlf())
    self.assertEqual(_run(r.readexactly(3)), b"abc")

  def test_mismatch(self):
    r = _make_reader(b"\nabc")
    with self.assertRaises(ReadError):
      _run(r.read_crlf())


class TestReadTextLine(unittest.TestCase):
  def test_simple(self):
    r = _make_reader(b"hello world\r\nnext")
    self.assertEqual(_run(r.read_text_line()), b"hello world")
    self.assertEqual(_run(r.readexactly(4)), b"next")

  def test_empty(self):
    r = _make_reader(b"\r\n")
    self.assertEqual(_run(r.read_text_line()), b"")


class TestAtEof(unittest.TestCase):
  def test_not_eof_with_data(self):
    r = _make_reader(b"data")
    self.assertFalse(r.at_eof)

  def test_eof_empty(self):
    r = _make_reader(b"")
    self.assertTrue(r.at_eof)

  def test_eof_after_consume(self):
    r = _make_reader(b"AB")
    _ = _run(r.readexactly(2))
    self.assertTrue(r.at_eof)

  def test_not_eof_with_buffered_beyond_cursor(self):
    r = _make_reader(b"AB", pre_read=2)
    _ = _run(r.readexactly(1))
    self.assertFalse(r.at_eof)


# --- scope management ---


class TestScopes(unittest.TestCase):
  def test_commit_advances_parent(self):
    r = _make_reader(b"hello")
    r.open_scope()
    self.assertEqual(_run(r.readexactly(3)), b"hel")
    r.commit_scope()
    self.assertEqual(_run(r.readexactly(2)), b"lo")

  def test_rollback_restores_position(self):
    r = _make_reader(b"hello")
    r.open_scope()
    self.assertEqual(_run(r.readexactly(3)), b"hel")
    r.rollback_scope()
    self.assertEqual(_run(r.readexactly(5)), b"hello")

  def test_rollback_no_eviction_behavior(self):
    r = _make_reader(b"hello world")
    _ = _run(r.readexactly(5))
    r.open_scope()
    _ = _run(r.readexactly(6))
    r.rollback_scope()
    # rollback restores position: the 6 bytes are available again
    self.assertEqual(_run(r.readexactly(6)), b" world")

  def test_nested(self):
    r = _make_reader(b"abcdefghij")
    r.open_scope()
    self.assertEqual(_run(r.readexactly(2)), b"ab")
    r.open_scope()
    self.assertEqual(_run(r.readexactly(3)), b"cde")
    r.rollback_scope()
    self.assertEqual(_run(r.readexactly(4)), b"cdef")
    r.commit_scope()
    self.assertEqual(_run(r.readexactly(4)), b"ghij")

  def test_commit_root_raises(self):
    r = _make_reader(b"abc")
    with self.assertRaises(RuntimeError):
      r.commit_scope()

  def test_rollback_root_raises(self):
    r = _make_reader(b"abc")
    with self.assertRaises(RuntimeError):
      r.rollback_scope()

  def test_open_commit_no_read_still_evicts(self):
    r = _make_reader(b"hello", pre_read=5)
    _ = _run(r.readexactly(5))
    r.open_scope()
    r.commit_scope()
    # commit evicts even without a read in scope; the consumed prefix is gone
    self.assertTrue(r.at_eof)
    with self.assertRaises(asyncio.IncompleteReadError):
      _ = _run(r.readexactly(1))


class TestEviction(unittest.TestCase):
  def test_commit_evicts_when_collapsed(self):
    r = _make_reader(b"hello world")
    self.assertEqual(_run(r.readexactly(5)), b"hello")
    r.open_scope()
    _ = _run(r.readexactly(6))
    r.commit_scope()
    # stack collapsed to depth 1, buf evicted; we're at EOF
    self.assertTrue(r.at_eof)
    with self.assertRaises(asyncio.IncompleteReadError):
      _ = _run(r.readexactly(1))

  def test_no_eviction_during_scope_behavior(self):
    r = _make_reader(b"abcXYZ", pre_read=3)
    _ = _run(r.readexactly(3))
    r.open_scope()
    _ = _run(r.readexactly(3))
    r.rollback_scope()
    # data is still readable after rollback (scope's read discarded)
    self.assertEqual(_run(r.readexactly(3)), b"XYZ")

  def test_commit_at_depth_then_rollback(self):
    r = _make_reader(b"abcdefghij", pre_read=10)
    r.open_scope()
    _ = _run(r.readexactly(3))
    r.open_scope()
    _ = _run(r.readexactly(2))
    r.commit_scope()
    # inner committed to middle (cursor at 5), but middle can still roll back to root
    r.rollback_scope()
    self.assertEqual(_run(r.readexactly(10)), b"abcdefghij")

  def test_eviction_bounded_root_reads(self):
    r = _make_reader(b"a" * 20, pre_read=4)
    for _ in range(20):
      _ = _run(r.readexactly(1))
    self.assertTrue(r.at_eof)
    self.assertLessEqual(r.buffer_size, 4)


# --- combinators ---


class TestReadOneOf(unittest.TestCase):
  def test_first_matches(self):
    r = _make_reader(b"hello")
    result = _run(r.read_one_of(lambda: r.read_const(b"hello"), lambda: r.read_const(b"world")))
    self.assertEqual(result, b"hello")

  def test_second_matches_after_first_fails(self):
    r = _make_reader(b"world")
    result = _run(r.read_one_of(lambda: r.read_const(b"hello"), lambda: r.read_const(b"world")))
    self.assertEqual(result, b"world")

  def test_position_restored_after_failed_first(self):
    r = _make_reader(b"world")
    _ = _run(r.read_one_of(lambda: r.read_const(b"hello"), lambda: r.read_const(b"world")))
    self.assertTrue(r.at_eof)

  def test_both_fail_raises(self):
    r = _make_reader(b"foo")
    with self.assertRaises(ReadError):
      _ = _run(r.read_one_of(lambda: r.read_const(b"hello"), lambda: r.read_const(b"world")))

  def test_rollback_mid_parse(self):
    r = _make_reader(b"XYZ")
    async def opt1():
      _ = await r.readexactly(2)
      raise ReadError("simulated")
    async def opt2():
      return await r.readexactly(3)
    result = _run(r.read_one_of(opt1, opt2))
    self.assertEqual(result, b"XYZ")

  def test_returns_value_of_first(self):
    r = _make_reader(b"abc")
    async def opt1():
      return await r.readexactly(3)
    async def opt2():
      return await r.readexactly(1)
    self.assertEqual(_run(r.read_one_of(opt1, opt2)), b"abc")

  def test_non_read_error_propagates(self):
    r = _make_reader(b"hello")
    async def opt1():
      raise ValueError("bug")
    async def opt2():
      return await r.read_const(b"hello")
    with self.assertRaises(ValueError):
      _ = _run(r.read_one_of(opt1, opt2))

  def test_nested_one_of(self):
    # three-way via nesting: matches the third option
    r = _make_reader(b"third")
    async def opt3():
      return await r.read_const(b"third")
    result = _run(r.read_one_of(
      lambda: r.read_const(b"first"),
      lambda: r.read_one_of(lambda: r.read_const(b"second"), opt3),
    ))
    self.assertEqual(result, b"third")


class TestHandleOptions(unittest.TestCase):
  def test_first_matches(self):
    r = _make_reader(b"hello")
    called: list[str] = []
    async def opt1():
      _ = await r.read_const(b"hello")
      called.append("1")
    async def opt2():
      _ = await r.read_const(b"world")
      called.append("2")
    _run(r.handle_options([opt1, opt2]))
    self.assertEqual(called, ["1"])

  def test_second_matches(self):
    r = _make_reader(b"world")
    called: list[str] = []
    async def opt1():
      _ = await r.read_const(b"hello")
      called.append("1")
    async def opt2():
      _ = await r.read_const(b"world")
      called.append("2")
    _run(r.handle_options([opt1, opt2]))
    self.assertEqual(called, ["2"])

  def test_none_matches_raises(self):
    r = _make_reader(b"foo")
    async def opt1():
      _ = await r.read_const(b"hello")
    async def opt2():
      _ = await r.read_const(b"world")
    with self.assertRaises(ReadError):
      _run(r.handle_options([opt1, opt2]))

  def test_order_respected(self):
    r = _make_reader(b"hello")
    called: list[str] = []
    async def opt1():
      _ = await r.read_const(b"hello")
      called.append("1")
    async def opt2():
      _ = await r.read_const(b"hello")
      called.append("2")
    _run(r.handle_options([opt1, opt2]))
    self.assertEqual(called, ["1"])

  def test_non_read_error_propagates(self):
    r = _make_reader(b"hello")
    async def opt1():
      raise ValueError("bug")
    async def opt2():
      _ = await r.read_const(b"hello")
    with self.assertRaises(ValueError):
      _run(r.handle_options([opt1, opt2]))

  def test_empty_list_raises(self):
    r = _make_reader(b"hello")
    with self.assertRaises(ReadError):
      _run(r.handle_options([]))

  def test_position_restored_between_options(self):
    r = _make_reader(b"world")
    async def opt1():
      _ = await r.readexactly(3)
      raise ReadError("no")
    async def opt2():
      _ = await r.read_const(b"world")
    _run(r.handle_options([opt1, opt2]))
    self.assertTrue(r.at_eof)


# --- streaming across wire-read boundaries ---


class TestStreaming(unittest.TestCase):
  def test_readexactly_across_chunks(self):
    r = _make_reader(b"hello world", pre_read=2, chunk=2)
    self.assertEqual(_run(r.readexactly(11)), b"hello world")

  def test_read_until_across_chunks(self):
    r = _make_reader(b"hello world\r\nnext", pre_read=2, chunk=2)
    self.assertEqual(_run(r.read_until(b"\r\n")), b"hello world")
    self.assertEqual(_run(r.readexactly(4)), b"next")

  def test_rollback_after_partial_streaming_read(self):
    r = _make_reader(b"XYZ", pre_read=1, chunk=1)
    async def opt1():
      _ = await r.readexactly(2)
      raise ReadError("simulated")
    async def opt2():
      return await r.readexactly(3)
    result = _run(r.read_one_of(opt1, opt2))
    self.assertEqual(result, b"XYZ")

  def test_skip_re_across_chunks(self):
    r = _make_reader(b"     hello", pre_read=2, chunk=2)
    _run(r.skip_re(br" *"))
    self.assertEqual(_run(r.readexactly(5)), b"hello")

  def test_handle_options_across_chunks(self):
    r = _make_reader(b"second", pre_read=2, chunk=2)
    async def opt1():
      _ = await r.read_const(b"first")
    async def opt2():
      _ = await r.read_const(b"second")
    _run(r.handle_options([opt1, opt2]))
    self.assertTrue(r.at_eof)

  def test_eviction_with_chunked_feed(self):
    # buffer stays bounded as we consume byte-by-byte from a chunked stream
    r = _make_reader(b"a" * 30, pre_read=4, chunk=4)
    for _ in range(30):
      _ = _run(r.readexactly(1))
    self.assertTrue(r.at_eof)
    self.assertLessEqual(r.buffer_size, 4)


if __name__ == "__main__":
  _ = unittest.main()
