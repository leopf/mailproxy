import pathlib, tempfile, unittest

from mailproxy.imap_frontend import IMAPServerConnection

from tests.fake_remote import FakeRemoteConnection
from tests.helpers import (MemoryPipe, make_config, seed_account,
                         seed_mailbox)


class IMAPHarness:
  """Runs a single IMAPServerConnection against an in-memory pipe and a fake
  remote. Feed client commands via ``pipe.feed``, then ``await run()``."""

  def __init__(self, config, address: str = "test@example.com", remote=None):
    self.config = config
    self.address = address
    self.pipe = MemoryPipe()
    self.remote = remote
    self.conn = IMAPServerConnection(config, self.pipe.reader, self.pipe.writer, remote_factory=self._factory)  # pyright: ignore[reportArgumentType]

  async def _factory(self, config, account):
    if self.remote is None:
      self.remote = FakeRemoteConnection(config, account)
    return self.remote

  def login_cmd(self) -> None:
    self.pipe.feed(("A1 LOGIN %s pw\r\n" % self.address).encode())

  def run(self):
    return self.conn.run()

  def output(self) -> bytes:
    return self.pipe.output()


class TestFrontend(unittest.IsolatedAsyncioTestCase):
  def setUp(self):
    self._tmpdir = tempfile.TemporaryDirectory()
    self.config = make_config(pathlib.Path(self._tmpdir.name) / "test.sqlite")
    seed_account(self.config, "test@example.com")

  def tearDown(self):
    self._tmpdir.cleanup()

  def _h(self) -> IMAPHarness:
    return IMAPHarness(self.config)

  async def test_capability(self):
    h = self._h()
    h.pipe.feed(b"A1 CAPABILITY\r\n")
    h.pipe.feed_eof()
    await h.run()
    out = h.output()
    self.assertIn(b"A1 OK CAPABILITY completed", out)
    self.assertIn(b"IMAP4rev1", out)

  async def test_select_remote_mailbox_calls_sync(self):
    seed_mailbox(self.config, "test@example.com", "INBOX", is_remote=True)
    h = self._h()
    h.login_cmd()
    h.pipe.feed(b"A2 SELECT INBOX\r\n")
    h.pipe.feed_eof()
    await h.run()
    assert h.remote is not None
    self.assertIn("sync_mailbox", [c[0] for c in h.remote.calls])
    self.assertIn(b"A1 OK login completed", h.output())
    self.assertIn(b"A2 OK", h.output())

  async def test_examine_sets_read_only(self):
    seed_mailbox(self.config, "test@example.com", "INBOX", is_remote=True)
    h = self._h()
    h.pipe.feed(b"A1 LOGIN test@example.com pw\r\n")
    h.pipe.feed(b"A2 EXAMINE INBOX\r\n")
    h.pipe.feed_eof()
    await h.run()
    self.assertIn(b"[READ-ONLY]", h.output())

  async def test_unknown_command_returns_bad_without_login(self):
    h = self._h()
    h.pipe.feed(b"A1 FROBNICATE\r\n")
    h.pipe.feed_eof()
    await h.run()
    self.assertIn(b"A1 BAD", h.output())


if __name__ == "__main__":
  unittest.main()
