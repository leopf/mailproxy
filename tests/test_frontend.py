import pathlib, tempfile, unittest
from typing import override

from tests.fake_remote import FakeRemoteConnection
from tests.harness import IMAPHarness
from tests.helpers import make_config, seed_account, seed_mailbox
from mailproxy.model import Config


class TestFrontend(unittest.IsolatedAsyncioTestCase):
  @override
  def setUp(self):
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
    self.config: Config = make_config(pathlib.Path(self._tmpdir.name) / "test.sqlite")
    _ = seed_account(self.config, "test@example.com")

  @override
  def tearDown(self):
    self._tmpdir.cleanup()

  def _h(self, remote: FakeRemoteConnection | None = None) -> IMAPHarness:
    return IMAPHarness(self.config, remote=remote)

  async def test_capability(self):
    h = self._h()
    h.cmd("A1", "CAPABILITY")
    h.finish()
    await h.run()
    out = h.output()
    self.assertIn(b"A1 OK CAPABILITY completed", out)
    self.assertIn(b"IMAP4rev1", out)

  async def test_select_remote_mailbox_calls_sync(self):
    _ = seed_mailbox(self.config, "test@example.com", "INBOX", is_remote=True)
    h = self._h()
    h.login_cmd()
    h.cmd("A2", "SELECT INBOX")
    h.finish()
    await h.run()
    assert h.remote is not None
    self.assertIn("sync_mailbox", [c[0] for c in h.remote.calls])
    self.assertIn(b"A1 OK login completed", h.output())
    self.assertIn(b"A2 OK", h.output())

  async def test_examine_sets_read_only(self):
    _ = seed_mailbox(self.config, "test@example.com", "INBOX", is_remote=True)
    h = self._h()
    h.login_cmd()
    h.cmd("A2", "EXAMINE INBOX")
    h.finish()
    await h.run()
    self.assertIn(b"[READ-ONLY]", h.output())

  async def test_unknown_command_returns_bad_without_login(self):
    h = self._h()
    h.cmd("A1", "FROBNICATE")
    h.finish()
    await h.run()
    self.assertIn(b"A1 BAD", h.output())


if __name__ == "__main__":
  _ = unittest.main()
