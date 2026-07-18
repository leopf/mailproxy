import asyncio, pathlib, unittest
from collections.abc import Coroutine
from typing import Any
from unittest.mock import MagicMock, patch
from mailproxy.model import Account, AuthenticationOAUTH2, AuthenticationPLAIN, TLSMode
from mailproxy.smtp.backend import _smtp_send, _smtp_authenticate, smtp_forward_mail  # pyright: ignore[reportPrivateUsage]
from mailproxy.smtp.reader import SMTPReader


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
  _start_tls_called: bool

  def __init__(self) -> None:
    self._written = bytearray()
    self._closed = False
    self._start_tls_called = False

  def write(self, data: bytes) -> None:
    self._written.extend(data)

  def close(self) -> None:
    self._closed = True

  async def drain(self) -> None:
    pass

  async def start_tls(self, _ctx: object) -> None:
    self._start_tls_called = True


def _run[T](coro: Coroutine[Any, Any, T]) -> T:  # pyright: ignore[reportExplicitAny]
  return asyncio.run(coro)


def _make_account_plain() -> Account:
  return Account(
    addresses=("user@test.local",),
    imap_host="", imap_port=0, imap_tlsmode=TLSMode.NONE,
    smtp_host="smtp.test.local", smtp_port=25, smtp_tlsmode=TLSMode.NONE,
    auth=AuthenticationPLAIN(password="pw"),
  )


def _make_account_oauth2() -> Account:
  return Account(
    addresses=("user@test.local",),
    imap_host="", imap_port=0, imap_tlsmode=TLSMode.NONE,
    smtp_host="smtp.test.local", smtp_port=25, smtp_tlsmode=TLSMode.NONE,
    auth=AuthenticationOAUTH2(
      scope="scope", client_id="cid", client_secret=None,
      authorization_base_url="https://auth.example/authorize",
      token_url="https://auth.example/token", redirect_url="https://app.example/cb",
    ),
  )


class TestSmtpSend(unittest.TestCase):
  def test_success(self):
    reader = _MockStreamReader(b"250 ok\r\n")
    smtp_reader = SMTPReader(reader)
    writer = _MockStreamWriter()
    code, msg = _run(_smtp_send(writer, smtp_reader, "NOOP"))  # pyright: ignore[reportArgumentType]
    self.assertEqual(code, 250)
    self.assertEqual(msg, "ok")
    self.assertEqual(bytes(writer._written), b"NOOP\r\n")  # pyright: ignore[reportPrivateUsage]

  def test_expect_code_match(self):
    reader = _MockStreamReader(b"250 ok\r\n")
    smtp_reader = SMTPReader(reader)
    writer = _MockStreamWriter()
    code, _ = _run(_smtp_send(writer, smtp_reader, "EHLO test", expect_code=250))  # pyright: ignore[reportArgumentType]
    self.assertEqual(code, 250)

  def test_expect_code_mismatch_raises(self):
    reader = _MockStreamReader(b"535 fail\r\n")
    smtp_reader = SMTPReader(reader)
    writer = _MockStreamWriter()
    with self.assertRaises(RuntimeError):
      _ = _run(_smtp_send(writer, smtp_reader, "AUTH PLAIN x", expect_code=235))  # pyright: ignore[reportArgumentType]

  def test_multi_line_response(self):
    reader = _MockStreamReader(b"250-hello\r\n250 AUTH PLAIN\r\n")
    smtp_reader = SMTPReader(reader)
    writer = _MockStreamWriter()
    code, msg = _run(_smtp_send(writer, smtp_reader, "EHLO test"))  # pyright: ignore[reportArgumentType]
    self.assertEqual(code, 250)
    self.assertEqual(msg, "hello\nAUTH PLAIN")


class TestSmtpAuthenticatePlain(unittest.TestCase):
  def test_plain_auth_success(self):
    reader = _MockStreamReader(b"235 ok\r\n")
    smtp_reader = SMTPReader(reader)
    writer = _MockStreamWriter()
    account = _make_account_plain()
    _run(_smtp_authenticate(writer, smtp_reader, account, pathlib.Path("/tmp/x.db")))  # pyright: ignore[reportArgumentType]
    sent = bytes(writer._written)  # pyright: ignore[reportPrivateUsage]
    self.assertTrue(sent.startswith(b"AUTH PLAIN "))

  def test_plain_auth_failure(self):
    reader = _MockStreamReader(b"535 fail\r\n")
    smtp_reader = SMTPReader(reader)
    writer = _MockStreamWriter()
    account = _make_account_plain()
    with self.assertRaises(RuntimeError):
      _run(_smtp_authenticate(writer, smtp_reader, account, pathlib.Path("/tmp/x.db")))  # pyright: ignore[reportArgumentType]


class TestSmtpAuthenticateOAuth2(unittest.TestCase):
  def test_oauth2_success(self):
    reader = _MockStreamReader(b"235 ok\r\n")
    smtp_reader = SMTPReader(reader)
    writer = _MockStreamWriter()
    account = _make_account_oauth2()
    mock_db = MagicMock()
    with patch("mailproxy.smtp.backend.db_open", return_value=mock_db), \
         patch("mailproxy.smtp.backend.account_get_oauth_access_token", return_value="token123"):
      _run(_smtp_authenticate(writer, smtp_reader, account, pathlib.Path("/tmp/x.db")))  # pyright: ignore[reportArgumentType]
    sent = bytes(writer._written)  # pyright: ignore[reportPrivateUsage]
    self.assertTrue(sent.startswith(b"AUTH XOAUTH2 "))

  def test_oauth2_challenge_then_failure(self):
    reader = _MockStreamReader(b"334 \r\n535 fail\r\n")
    smtp_reader = SMTPReader(reader)
    writer = _MockStreamWriter()
    account = _make_account_oauth2()
    mock_db = MagicMock()
    with patch("mailproxy.smtp.backend.db_open", return_value=mock_db), \
         patch("mailproxy.smtp.backend.account_get_oauth_access_token", return_value="token123"):
      with self.assertRaises(RuntimeError):
        _run(_smtp_authenticate(writer, smtp_reader, account, pathlib.Path("/tmp/x.db")))  # pyright: ignore[reportArgumentType]


def _server_responses(starttls: bool = False, num_recipients: int = 1) -> bytes:
  responses = b"220 ready\r\n"
  responses += b"250-hello\r\n250 AUTH PLAIN\r\n"
  if starttls:
    responses += b"220 go tls\r\n"
    responses += b"250-hello\r\n250 AUTH PLAIN\r\n"
  responses += b"235 ok\r\n"
  responses += b"250 ok\r\n"
  for _ in range(num_recipients):
    responses += b"250 ok\r\n"
  responses += b"354 go\r\n"
  responses += b"250 queued\r\n"
  responses += b"221 bye\r\n"
  return responses


class TestSmtpForwardMail(unittest.TestCase):
  def test_plain_forward_sequence(self):
    responses = _server_responses(num_recipients=2)
    mock_reader = _MockStreamReader(responses)
    mock_writer = _MockStreamWriter()
    account = _make_account_plain()
    async def _mock_open_connection(*_args: object, **_kwargs: object):
      return mock_reader, mock_writer
    with patch("mailproxy.smtp.backend.asyncio.open_connection", side_effect=_mock_open_connection):
      _run(smtp_forward_mail(pathlib.Path("/tmp/x.db"), account, "s@t", ("r1@t", "r2@t"), b"body\r\n"))
    sent = bytes(mock_writer._written)  # pyright: ignore[reportPrivateUsage]
    self.assertIn(b"EHLO ", sent)
    self.assertIn(b"AUTH PLAIN ", sent)
    self.assertIn(b"MAIL FROM:<s@t>\r\n", sent)
    self.assertIn(b"RCPT TO:<r1@t>\r\n", sent)
    self.assertIn(b"RCPT TO:<r2@t>\r\n", sent)
    self.assertIn(b"DATA\r\n", sent)
    self.assertIn(b"body\r\n\r\n.\r\n", sent)
    self.assertIn(b"QUIT\r\n", sent)
    self.assertTrue(mock_writer._closed)  # pyright: ignore[reportPrivateUsage]

  def test_starttls_forward_sequence(self):
    account = Account(
      addresses=("user@test.local",),
      imap_host="", imap_port=0, imap_tlsmode=TLSMode.NONE,
      smtp_host="smtp.test.local", smtp_port=25, smtp_tlsmode=TLSMode.STARTTLS,
      auth=AuthenticationPLAIN(password="pw"),
    )
    responses = _server_responses(starttls=True)
    mock_reader = _MockStreamReader(responses)
    mock_writer = _MockStreamWriter()
    async def _mock_open_connection(*_args: object, **_kwargs: object):
      return mock_reader, mock_writer
    with patch("mailproxy.smtp.backend.asyncio.open_connection", side_effect=_mock_open_connection):
      _run(smtp_forward_mail(pathlib.Path("/tmp/x.db"), account, "s@t", ("r@t",), b"body\r\n"))
    sent = bytes(mock_writer._written)  # pyright: ignore[reportPrivateUsage]
    self.assertIn(b"STARTTLS\r\n", sent)
    self.assertTrue(mock_writer._start_tls_called)  # pyright: ignore[reportPrivateUsage]
    self.assertEqual(sent.count(b"EHLO "), 2)

  def test_mail_from_failure_raises(self):
    responses = b"220 ready\r\n250-h\r\n250 AUTH PLAIN\r\n235 ok\r\n550 nope\r\n"
    mock_reader = _MockStreamReader(responses)
    mock_writer = _MockStreamWriter()
    account = _make_account_plain()
    async def _mock_open_connection(*_args: object, **_kwargs: object):
      return mock_reader, mock_writer
    with patch("mailproxy.smtp.backend.asyncio.open_connection", side_effect=_mock_open_connection):
      with self.assertRaises(RuntimeError):
        _run(smtp_forward_mail(pathlib.Path("/tmp/x.db"), account, "s@t", ("r@t",), b"body\r\n"))


if __name__ == "__main__":
  _ = unittest.main()
