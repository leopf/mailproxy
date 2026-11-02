import pathlib, tempfile, unittest
from typing import override

from mailproxy.model import Config
from tests.fake_remote import FakeRemoteConnection
from tests.harness import IMAPHarness
from tests.helpers import make_account, make_config, seed_account, seed_mailbox, seed_message


class TestClientIntegration(unittest.IsolatedAsyncioTestCase):
  @override
  def setUp(self):
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
    self.config: Config = make_config(pathlib.Path(self._tmpdir.name) / "test.sqlite")
    self.account: str = "test@example.com"
    _ = seed_account(self.config, self.account)

  @override
  def tearDown(self):
    self._tmpdir.cleanup()

  async def test_full_client_session(self):
    mid = seed_mailbox(self.config, self.account, "INBOX", is_remote=True)
    _ = seed_message(self.config, mid, b"Subject: one\r\n\r\nbody one")
    _ = seed_message(self.config, mid, b"Subject: two\r\n\r\nbody two")
    remote = FakeRemoteConnection(self.config, make_account(self.account))
    h = IMAPHarness(self.config, self.account, remote=remote)
    h.login()
    h.cmd("A2", 'LIST "" *')
    h.cmd("A3", "SELECT INBOX")
    h.cmd("A4", "UID FETCH 1:* (UID FLAGS)")
    h.cmd("A5", "UID FETCH 1 (BODY.PEEK[])")
    h.cmd("A6", "UID STORE 1 +FLAGS (\\Flagged)")
    h.cmd("A7", "NOOP")
    h.cmd("A8", "LOGOUT")
    h.finish()
    await h.run()

    out = h.output()
    self.assertIn(b"A2 OK", out)
    self.assertIn(b"INBOX", out)
    self.assertIn(b"* 2 EXISTS", out)
    self.assertIn(b"UID 1", out)
    self.assertIn(b"body one", out)
    self.assertTrue(any(c[0] == "uid_store_many" for c in remote.calls), remote.calls)
    self.assertIn(b"A8 OK", out)
