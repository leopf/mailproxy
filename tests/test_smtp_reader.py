import asyncio, unittest
from collections.abc import Coroutine
from typing import Any
from mailproxy.reader import ReadError
from mailproxy.smtp.reader import SMTPReader


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


def _make_reader(data: bytes, pre_read: int = 64, chunk: int = 0) -> SMTPReader:
  return SMTPReader(_MockStreamReader(data, chunk), pre_read=pre_read)


def _run[T](coro: Coroutine[Any, Any, T]) -> T:  # pyright: ignore[reportExplicitAny]
  return asyncio.run(coro)


class TestReadCiConst(unittest.TestCase):
  def test_match_exact(self):
    r = _make_reader(b"QUIT\r\n")
    self.assertEqual(_run(r.read_ci_const(b"QUIT")), b"QUIT")

  def test_match_case_insensitive(self):
    r = _make_reader(b"quit\r\n")
    self.assertEqual(_run(r.read_ci_const(b"QUIT")), b"quit")

  def test_mismatch_raises_read_error(self):
    r = _make_reader(b"NOOP\r\n")
    with self.assertRaises(ReadError):
      _ = _run(r.read_ci_const(b"QUIT"))

  def test_eof_propagates_incomplete_read_error(self):
    r = _make_reader(b"QUI")
    with self.assertRaises(asyncio.IncompleteReadError):
      _ = _run(r.read_ci_const(b"QUIT"))


class TestReadDataBody(unittest.TestCase):
  def test_simple(self):
    data = b"From: x\r\nSubject: y\r\n\r\nbody\r\n.\r\n"
    r = _make_reader(data)
    result = _run(r.read_data_body())
    self.assertEqual(result, b"From: x\r\nSubject: y\r\n\r\nbody\r\n")

  def test_dot_escape(self):
    data = b"..dot line\r\n.\r\n"
    r = _make_reader(data)
    result = _run(r.read_data_body())
    self.assertEqual(result, b".dot line\r\n")

  def test_empty_body(self):
    data = b".\r\n"
    r = _make_reader(data)
    result = _run(r.read_data_body())
    self.assertEqual(result, b"")

  def test_only_terminator(self):
    data = b".\r\nrest"
    r = _make_reader(data)
    result = _run(r.read_data_body())
    self.assertEqual(result, b"")
    self.assertEqual(_run(r.readexactly(4)), b"rest")

  def test_dot_not_at_line_start(self):
    data = b"a.b\r\n.\r\n"
    r = _make_reader(data)
    result = _run(r.read_data_body())
    self.assertEqual(result, b"a.b\r\n")

  def test_streaming(self):
    body = b"line1\r\nline2\r\n.\r\n"
    r = _make_reader(body, pre_read=4, chunk=4)
    result = _run(r.read_data_body())
    self.assertEqual(result, b"line1\r\nline2\r\n")


class TestReadResponse(unittest.TestCase):
  def test_single_line(self):
    r = _make_reader(b"220 ready\r\n")
    code, text = _run(r.read_response())
    self.assertEqual(code, 220)
    self.assertEqual(text, "ready")

  def test_multi_line(self):
    data = b"250-hello\r\n250 AUTH PLAIN\r\n"
    r = _make_reader(data)
    code, text = _run(r.read_response())
    self.assertEqual(code, 250)
    self.assertEqual(text, "hello\nAUTH PLAIN")

  def test_three_lines(self):
    data = b"250-a\r\n250-b\r\n250 c\r\n"
    r = _make_reader(data)
    code, text = _run(r.read_response())
    self.assertEqual(code, 250)
    self.assertEqual(text, "a\nb\nc")

  def test_error_code(self):
    r = _make_reader(b"535 auth fail\r\n")
    code, text = _run(r.read_response())
    self.assertEqual(code, 535)
    self.assertEqual(text, "auth fail")

  def test_eof_raises(self):
    r = _make_reader(b"22")
    with self.assertRaises(asyncio.IncompleteReadError):
      _ = _run(r.read_response())

  def test_continuation_then_final(self):
    data = b"334 \r\n235 ok\r\n"
    r = _make_reader(data)
    code1, text1 = _run(r.read_response())
    self.assertEqual(code1, 334)
    self.assertEqual(text1, "")
    code2, text2 = _run(r.read_response())
    self.assertEqual(code2, 235)
    self.assertEqual(text2, "ok")

  def test_streaming(self):
    data = b"250-a\r\n250 b\r\n"
    r = _make_reader(data, pre_read=4, chunk=4)
    code, text = _run(r.read_response())
    self.assertEqual(code, 250)
    self.assertEqual(text, "a\nb")


if __name__ == "__main__":
  _ = unittest.main()
