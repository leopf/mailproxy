import asyncio, base64, pathlib, unittest
from collections.abc import Coroutine
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from mailproxy.model import Account, AuthenticationPLAIN, Config, TLSMode
from mailproxy.smtp.frontend import SMTPServerSession


class _MockStreamReader:
  _data: bytes
  _pos: int

  def __init__(self, data: bytes) -> None:
    self._data = data
    self._pos = 0

  def at_eof(self) -> bool:
    return self._pos >= len(self._data)

  async def read(self, n: int = -1) -> bytes:
    if self._pos >= len(self._data):
      return b""
    if n == -1:
      end = len(self._data)
    else:
      end = self._pos + n
    result = self._data[self._pos:end]
    self._pos += len(result)
    return result


class _MockStreamWriter:
  _written: bytearray
  _closed: bool

  def __init__(self) -> None:
    self._written = bytearray()
    self._closed = False

  def write(self, data: bytes) -> None:
    self._written.extend(data)

  def close(self) -> None:
    self._closed = True

  async def drain(self) -> None:
    pass

  async def start_tls(self, _ctx: object) -> None:
    pass


def _run[T](coro: Coroutine[Any, Any, T]) -> T:  # pyright: ignore[reportExplicitAny]
  return asyncio.run(coro)


def _make_config() -> Config:
  return Config(
    domain="test.local", log_level=0, host="127.0.0.1",
    imap_port=143, smtp_port=25, db_path=pathlib.Path("/tmp/nonexistent.db"),
    proxy_password="secret",
  )


def _make_account() -> Account:
  return Account(
    addresses=("user@test.local",),
    imap_host="", imap_port=0, imap_tlsmode=TLSMode.NONE,
    smtp_host="", smtp_port=0, smtp_tlsmode=TLSMode.NONE,
    auth=AuthenticationPLAIN(password="pw"),
  )


class _SessionHarness:
  session: SMTPServerSession
  writer: _MockStreamWriter

  def __init__(self, input_bytes: bytes) -> None:
    config = _make_config()
    reader = _MockStreamReader(input_bytes)
    self.writer = _MockStreamWriter()
    self.session = SMTPServerSession(config, reader, self.writer)  # pyright: ignore[reportArgumentType]

  def output(self) -> bytes:
    return bytes(self.writer._written)  # pyright: ignore[reportPrivateUsage]

  async def run(self) -> None:
    await self.session.run()


def _b64_plain(user: str, password: str) -> bytes:
  return base64.b64encode(b"\0" + user.encode() + b"\0" + password.encode())


class TestBasicCommands(unittest.TestCase):
  def test_ehlo(self):
    h = _SessionHarness(b"EHLO test\r\n")
    _run(h.run())
    out = h.output()
    self.assertIn(b"220 test.local Ready\r\n", out)
    self.assertIn(b"250-test.local hello\r\n", out)
    self.assertIn(b"250 AUTH PLAIN STARTTLS\r\n", out)

  def test_helo(self):
    h = _SessionHarness(b"HELO test\r\n")
    _run(h.run())
    self.assertIn(b"250 test.local\r\n", h.output())

  def test_noop(self):
    h = _SessionHarness(b"NOOP\r\n")
    _run(h.run())
    self.assertIn(b"250 OK\r\n", h.output())

  def test_rset(self):
    h = _SessionHarness(b"RSET\r\n")
    _run(h.run())
    self.assertIn(b"250 OK\r\n", h.output())

  def test_vrfy(self):
    h = _SessionHarness(b"VRFY someone\r\n")
    _run(h.run())
    self.assertIn(b"252 cannot VRFY\r\n", h.output())

  def test_quit(self):
    h = _SessionHarness(b"QUIT\r\n")
    _run(h.run())
    self.assertIn(b"221 test.local closing transmission channel\r\n", h.output())
    self.assertTrue(h.session._done)  # pyright: ignore[reportPrivateUsage]

  def test_case_insensitive_verb(self):
    h = _SessionHarness(b"noop\r\n")
    _run(h.run())
    self.assertIn(b"250 OK\r\n", h.output())

  def test_unknown_command(self):
    h = _SessionHarness(b"BOGUS extra\r\n")
    _run(h.run())
    self.assertIn(b"500 unknown\r\n", h.output())

  def test_eof_closes(self):
    h = _SessionHarness(b"")
    _run(h.run())
    self.assertEqual(h.output(), b"220 test.local Ready\r\n")


class TestAuth(unittest.TestCase):
  def test_auth_plain_inline_success(self):
    auth_data = _b64_plain("user@test.local", "secret")
    h = _SessionHarness(b"EHLO t\r\nAUTH PLAIN " + auth_data + b"\r\nQUIT\r\n")
    fake_account = _make_account()
    mock_db = MagicMock()
    with patch("mailproxy.smtp.frontend.db_open", return_value=mock_db), \
         patch("mailproxy.smtp.frontend.authenticate_sasl", return_value=fake_account):
      _run(h.run())
    out = h.output()
    self.assertIn(b"235 2.7.0  Authentication Succeeded\r\n", out)

  def test_auth_plain_inline_failure(self):
    auth_data = _b64_plain("user@test.local", "wrong")
    h = _SessionHarness(b"EHLO t\r\nAUTH PLAIN " + auth_data + b"\r\nQUIT\r\n")
    mock_db = MagicMock()
    with patch("mailproxy.smtp.frontend.db_open", return_value=mock_db), \
         patch("mailproxy.smtp.frontend.authenticate_sasl", return_value=None):
      _run(h.run())
    self.assertIn(b"535 5.7.8  Authentication credentials invalid\r\n", h.output())

  def test_auth_plain_twoline(self):
    auth_data = _b64_plain("user@test.local", "secret")
    h = _SessionHarness(b"EHLO t\r\nAUTH PLAIN\r\n" + auth_data + b"\r\nQUIT\r\n")
    fake_account = _make_account()
    mock_db = MagicMock()
    with patch("mailproxy.smtp.frontend.db_open", return_value=mock_db), \
         patch("mailproxy.smtp.frontend.authenticate_sasl", return_value=fake_account):
      _run(h.run())
    out = h.output()
    self.assertIn(b"334 \r\n", out)
    self.assertIn(b"235 2.7.0  Authentication Succeeded\r\n", out)

  def test_auth_non_plain_rejected(self):
    h = _SessionHarness(b"AUTH CRAM-MD5\r\nQUIT\r\n")
    _run(h.run())
    self.assertIn(b"504 only PLAIN auth supported\r\n", h.output())


class TestMailRcpt(unittest.TestCase):
  def test_mail_without_auth(self):
    h = _SessionHarness(b"MAIL FROM:<sender@test.local>\r\nQUIT\r\n")
    _run(h.run())
    self.assertIn(b"550 not authenticated\r\n", h.output())

  def test_rcpt_without_auth(self):
    h = _SessionHarness(b"RCPT TO:<rcpt@test.local>\r\nQUIT\r\n")
    _run(h.run())
    self.assertIn(b"550 not authenticated\r\n", h.output())

  def test_mail_wrong_keyword(self):
    h = _SessionHarness(b"MAIL XFROM:<x>\r\nQUIT\r\n")
    _run(h.run())
    self.assertIn(b"500 unknown\r\n", h.output())

  def test_rcpt_wrong_keyword(self):
    h = _SessionHarness(b"RCPT XTO:<x>\r\nQUIT\r\n")
    _run(h.run())
    self.assertIn(b"500 unknown\r\n", h.output())

  def test_mail_with_space_before_angle(self):
    fake_account = _make_account()
    input_bytes = b"EHLO t\r\nAUTH PLAIN " + _b64_plain("u", "p") + b"\r\n"
    input_bytes += b"MAIL FROM: <sender@test.local>\r\nQUIT\r\n"
    h = _SessionHarness(input_bytes)
    mock_db = MagicMock()
    with patch("mailproxy.smtp.frontend.db_open", return_value=mock_db), \
         patch("mailproxy.smtp.frontend.authenticate_sasl", return_value=fake_account):
      _run(h.run())
    self.assertIn(b"250 OK\r\n", h.output())
    self.assertEqual(h.session._sender, "sender@test.local")  # pyright: ignore[reportPrivateUsage]


class TestData(unittest.TestCase):
  def test_data_without_auth(self):
    h = _SessionHarness(b"DATA\r\nQUIT\r\n")
    _run(h.run())
    self.assertIn(b"503 not authenticated\r\n", h.output())

  def test_data_forward(self):
    fake_account = _make_account()
    mail_body = b"From: x\r\nSubject: y\r\n\r\nbody\r\n"
    input_bytes = b"EHLO t\r\nAUTH PLAIN " + _b64_plain("u", "p") + b"\r\n"
    input_bytes += b"MAIL FROM:<s@t>\r\nRCPT TO:<r@t>\r\nDATA\r\n" + mail_body + b".\r\nQUIT\r\n"
    h = _SessionHarness(input_bytes)
    mock_db = MagicMock()
    mock_forward = AsyncMock()
    with patch("mailproxy.smtp.frontend.db_open", return_value=mock_db), \
         patch("mailproxy.smtp.frontend.authenticate_sasl", return_value=fake_account), \
         patch("mailproxy.smtp.frontend.smtp_forward_mail", mock_forward):
      _run(h.run())
    self.assertIn(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n", h.output())
    self.assertIn(b"250 OK\r\n", h.output())
    mock_forward.assert_called_once()
    call_args = mock_forward.call_args
    self.assertEqual(call_args.args[3], ("r@t",))
    self.assertEqual(call_args.args[4], mail_body)

  def test_data_dot_escape(self):
    fake_account = _make_account()
    mail_body = b"..dot\r\n.\r\n"
    input_bytes = b"EHLO t\r\nAUTH PLAIN " + _b64_plain("u", "p") + b"\r\n"
    input_bytes += b"MAIL FROM:<s@t>\r\nRCPT TO:<r@t>\r\nDATA\r\n" + mail_body + b"QUIT\r\n"
    h = _SessionHarness(input_bytes)
    mock_db = MagicMock()
    mock_forward = AsyncMock()
    with patch("mailproxy.smtp.frontend.db_open", return_value=mock_db), \
         patch("mailproxy.smtp.frontend.authenticate_sasl", return_value=fake_account), \
         patch("mailproxy.smtp.frontend.smtp_forward_mail", mock_forward):
      _run(h.run())
    mock_forward.assert_called_once()
    self.assertEqual(mock_forward.call_args.args[4], b".dot\r\n")


class TestStartTLS(unittest.TestCase):
  def test_starttls_buffer_drained(self):
    h = _SessionHarness(b"STARTTLS\r\nNOOP\r\n")
    _run(h.run())
    out = h.output()
    self.assertIn(b"220 Ready to start TLS\r\n", out)
    self.assertIn(b"250 OK\r\n", out)
    self.assertTrue(h.session._tls_active)  # pyright: ignore[reportPrivateUsage]

  def test_starttls_already_active(self):
    h = _SessionHarness(b"STARTTLS\r\nSTARTTLS\r\nQUIT\r\n")
    _run(h.run())
    out = h.output()
    self.assertIn(b"220 Ready to start TLS\r\n", out)
    self.assertIn(b"503 TLS already active\r\n", out)


if __name__ == "__main__":
  _ = unittest.main()
