import asyncio, base64, pathlib, tempfile, unittest
from collections.abc import Awaitable, Callable
from typing import override

from mailproxy.smtp_frontend import smtp_server_handle_client
from mailproxy.model import Config
from tests.helpers import BidiPipe, make_config, seed_account


def _b64plain(user: str, password: str) -> str:
  return base64.b64encode(("\0%s\0%s" % (user, password)).encode()).decode()


class SMTPFRONT:
  """Drives an smtp_server_handle_client. Send a command with ``send``, then
  ``await reply()`` to read the server's response line(s)."""

  def __init__(self, config: Config, forward_mail: Callable[..., Awaitable[None]] | None = None):
    self.pipe: BidiPipe = BidiPipe()
    self.task: asyncio.Task[None] = asyncio.create_task(smtp_server_handle_client(
      config, self.pipe.b_reader, self.pipe.b_writer, forward_mail=forward_mail))  # pyright: ignore[reportArgumentType]

  def send(self, line: str):
    self.pipe.feed_b((line + "\r\n").encode())

  def send_data(self, line: str):
    if not line.endswith("\r\n"):
      line += "\r\n"
    self.pipe.feed_b(line.encode())

  async def reply(self, timeout: float = 2.0) -> None:
    self.last_reply: bytes = b""
    while True:
      line = await asyncio.wait_for(self.pipe.a_reader.readuntil(b"\r\n"), timeout)
      self.last_reply = line
      if len(line) < 4 or line[3] != 0x2D:  # continuation line 'X-...' -> keep reading
        return

  async def close(self):
    _ = self.task.cancel()
    try:
      await self.task
    except asyncio.CancelledError:
      pass


class TestSMTPFrontend(unittest.IsolatedAsyncioTestCase):
  @override
  def setUp(self):
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
    self.config: Config = make_config(pathlib.Path(self._tmpdir.name) / "test.sqlite", proxy_password="pw")
    self.account: str = "test@example.com"
    _ = seed_account(self.config, self.account)

  @override
  def tearDown(self):
    self._tmpdir.cleanup()

  async def test_smtp_forward_rejects_451(self):
    async def fake_forward(_config: Config, _account: object, _sender: str, _recipients: object, _mail_data: bytes) -> None:
      raise RuntimeError("rejected")
    sess = SMTPFRONT(self.config, forward_mail=fake_forward)

    await sess.reply()  # 220
    sess.send("EHLO client.example")
    await sess.reply()  # 250 hello
    sess.send("AUTH PLAIN %s" % _b64plain(self.account, "pw"))
    await sess.reply()
    self.assertIn(b"235", sess.last_reply)
    sess.send("MAIL FROM:<me@example.com>")
    await sess.reply()
    sess.send("RCPT TO:<you@example.com>")
    await sess.reply()
    sess.send("DATA")
    await sess.reply()  # 354
    sess.send_data("Subject: hi\r\n\r\nbody")
    sess.send_data(".")
    await sess.reply()
    self.assertIn(b"451", sess.last_reply)
    await sess.close()


  async def test_smtp_forward_success_250(self):
    calls: list[tuple[str, object, bytes]] = []
    async def fake_forward(_config: Config, _account: object, sender: str, recipients: object, mail_data: bytes) -> None:
      calls.append((sender, recipients, mail_data))
    sess = SMTPFRONT(self.config, forward_mail=fake_forward)
    await sess.reply()  # 220
    sess.send("EHLO client.example")
    await sess.reply()
    sess.send("AUTH PLAIN %s" % _b64plain(self.account, "pw"))
    await sess.reply()
    sess.send("MAIL FROM:<me@example.com>")
    await sess.reply()
    sess.send("RCPT TO:<you@example.com>")
    await sess.reply()
    sess.send("DATA")
    await sess.reply()
    sess.send_data("Subject: hi\r\n\r\nbody")
    sess.send_data(".")
    await sess.reply()
    self.assertIn(b"250", sess.last_reply)
    self.assertEqual(len(calls), 1)
    sender, recipients, data = calls[0]
    self.assertEqual(sender, "me@example.com")
    self.assertEqual(recipients, ("you@example.com",))
    self.assertIn(b"Subject: hi", data)
    await sess.close()

  async def test_mail_without_auth_530(self):
    sess = SMTPFRONT(self.config)
    await sess.reply()  # 220
    sess.send("MAIL FROM:<me@example.com>")
    await sess.reply()
    self.assertIn(b"530", sess.last_reply)
    await sess.close()


if __name__ == "__main__":
  _ = unittest.main()
