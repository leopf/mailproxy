import pathlib, tempfile, unittest
from typing import override

from tests.fake_remote import FakeRemoteConnection
from tests.harness import IMAPHarness
from tests.helpers import make_account, make_config, seed_account, seed_mailbox, seed_message
from mailproxy.imap_parsing import IMAPConnectionLostError
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

  async def test_list_accepts_unquoted_wildcard(self):
    _ = seed_mailbox(self.config, "test@example.com", "INBOX", is_remote=True)
    h = self._h()
    h.login()
    h.cmd("A2", 'LIST "" *')
    h.finish()
    await h.run()
    out = h.output()
    self.assertIn(b"A2 OK", out)
    self.assertIn(b"INBOX", out)

  async def test_remote_loss_does_not_drop_client(self):
    mid = seed_mailbox(self.config, "test@example.com", "INBOX", is_remote=True)
    _ = seed_message(self.config, mid, b"Subject: x\r\n\r\nbody")
    remote = FakeRemoteConnection(self.config, make_account("test@example.com"))

    def boom(*_args: object) -> None:
      raise IMAPConnectionLostError("socket gone")

    remote.behaviors["uid_store"] = boom
    h = self._h(remote=remote)
    h.login()
    h.cmd("A2", "SELECT INBOX")
    h.cmd("A3", "STORE 1 +FLAGS (\\Seen)")
    h.cmd("A4", "CAPABILITY")
    h.finish()
    await h.run()
    out = h.output()
    self.assertIn(b"A3 NO", out)
    self.assertIn(b"A4 OK CAPABILITY completed", out)


if __name__ == "__main__":
  _ = unittest.main()
