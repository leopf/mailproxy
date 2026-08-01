import asyncio, pathlib, tempfile, unittest
from typing import override

from mailproxy.model import Account, AuthenticationPLAIN, Config, TLSMode
from mailproxy.smtp_backend import smtp_forward_mail

from tests.helpers import BidiPipe, make_config


def _smtp_account(password: str = "pw") -> Account:
  return Account(
    addresses=("test@example.com",),
    imap_host="imap.example.com",
    imap_port=993,
    imap_tlsmode=TLSMode.DIRECT,
    smtp_host="smtp.example.com",
    smtp_port=587,
    smtp_tlsmode=TLSMode.DIRECT,
    auth=AuthenticationPLAIN(password=password),
  )


class FakeSMTPServer:
  """Scripted SMTP server: replies each proxy command, captures commands."""

  def __init__(self, replies: list[tuple[int, str]]):
    self.replies: list[tuple[int, str]] = list(replies)
    self.commands: list[bytes] = []
    self.pipe: BidiPipe = BidiPipe()

  async def run(self):
    # greeting
    self.pipe.feed_a(_reply(self.replies.pop(0)))
    while True:
      line = await self.pipe.b_reader.readuntil(b"\r\n")
      cmd = line[:-2]
      self.commands.append(cmd)
      if cmd.upper() == b"QUIT":
        self.pipe.feed_a(_reply(self.replies.pop(0)))
        return
      if cmd.upper().startswith(b"DATA"):
        # reply 354 immediately (proxy writes the body only after this)
        self.pipe.feed_a(_reply(self.replies.pop(0)))
        while True:
          d = await self.pipe.b_reader.readuntil(b"\r\n")
          if d == b".\r\n":
            break
        # then the final accept/reject
        self.pipe.feed_a(_reply(self.replies.pop(0)))
      else:
        self.pipe.feed_a(_reply(self.replies.pop(0)))


def _reply(code_text: tuple[int, str]) -> bytes:
  code, text = code_text
  return ("%d %s\r\n" % (code, text)).encode()


def _greeting() -> list[tuple[int, str]]:
  return [
    (220, "smtp ready"),
    (250, "EHLO ok"),
    (235, "auth ok"),
    (250, "mail ok"),
    (250, "rcpt ok"),
    (354, "go"),
    (250, "message accepted"),
    (221, "bye"),
  ]


class TestSMTPBackend(unittest.IsolatedAsyncioTestCase):
  @override
  def setUp(self):
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
    self.config: Config = make_config(pathlib.Path(self._tmpdir.name) / "test.sqlite")

  @override
  def tearDown(self):
    self._tmpdir.cleanup()

  async def _forward(self, server: FakeSMTPServer, mail: bytes = b"Subject: hi\r\n\r\nbody"):
    pipe: BidiPipe = server.pipe
    async def conn():
      return pipe.a_reader, pipe.a_writer
    task = asyncio.create_task(smtp_forward_mail(
      self.config, _smtp_account(), "me@example.com", ("you@example.com",), mail,
      open_connection=conn))  # pyright: ignore[reportArgumentType]
    peer = asyncio.create_task(server.run())
    await asyncio.wait_for(task, timeout=5)
    await asyncio.wait_for(peer, timeout=5)
    self.assertTrue(peer.done())

  async def test_happy_path(self):
    server = FakeSMTPServer(_greeting())
    await self._forward(server)
    self.assertTrue(any(c.startswith(b"AUTH PLAIN") for c in server.commands), server.commands)
    self.assertIn(b"MAIL FROM:<me@example.com>", server.commands)
    self.assertIn(b"RCPT TO:<you@example.com>", server.commands)
    self.assertIn(b"QUIT", server.commands)

  async def test_data_rejected_raises(self):
    replies = _greeting()
    replies[6] = (554, "message rejected")
    server = FakeSMTPServer(replies)
    with self.assertRaises(Exception):
      await self._forward(server)


if __name__ == "__main__":
  _ = unittest.main()
