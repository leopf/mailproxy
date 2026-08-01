import pathlib, tempfile, unittest

from mailproxy.db import DatabaseSession
from mailproxy.imap_frontend import IMAPServerConnection

from tests.fake_remote import FakeRemoteConnection
from tests.helpers import (MemoryPipe, make_config, seed_account, seed_mailbox,
                         seed_message)


class IMAPHarness:
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

  def login(self):
    self.pipe.feed(("A1 LOGIN %s pw\r\n" % self.address).encode())

  def cmd(self, tag: str, line: str):
    self.pipe.feed(("%s %s\r\n" % (tag, line)).encode())

  def finish(self):
    self.pipe.feed_eof()

  async def run(self):
    await self.conn.run()

  def output(self) -> bytes:
    return self.pipe.output()


def db(config):
  return DatabaseSession(config)


class TestBugRegressions(unittest.IsolatedAsyncioTestCase):
  def setUp(self):
    self._tmpdir = tempfile.TemporaryDirectory()
    self.config = make_config(pathlib.Path(self._tmpdir.name) / "test.sqlite")
    self.account = "test@example.com"
    seed_account(self.config, self.account)
    self.remote = FakeRemoteConnection(self.config, seed_account_remote(self.config, self.account))

  def tearDown(self):
    self._tmpdir.cleanup()

  def _h(self) -> IMAPHarness:
    return IMAPHarness(self.config, self.account, remote=self.remote)

  # --- Bug 4: BODY.PEEK[HEADER.FIELDS.NOT (...)] should EXCLUDE listed fields ---

  async def test_header_fields_not_excludes_listed_fields(self):
    mid = seed_mailbox(self.config, self.account, "INBOX", is_remote=True)
    body = b"From: a@b\r\nTo: c@d\r\nSubject: hi\r\nX-Large: y\r\n\r\nhello"
    seed_message(self.config, mid, body)
    h = self._h()
    h.login()
    h.cmd("A2", "SELECT INBOX")
    h.cmd("A3", "FETCH 1 (BODY.PEEK[HEADER.FIELDS.NOT (TO SUBJECT)])")
    h.finish()
    await h.run()
    out = h.output()
    # .NOT must drop To and Subject, keep From and X-Large
    self.assertIn(b"From: a@b", out)
    self.assertIn(b"X-Large: y", out)
    self.assertNotIn(b"To: c@d", out)
    self.assertNotIn(b"Subject: hi", out)

  # --- Bug 2: local->remote COPY must not create a phantom row ---

  async def test_copy_local_to_remote_creates_no_phantom(self):
    local_mid = seed_mailbox(self.config, self.account, "Archive", is_remote=False)
    remote_mid = seed_mailbox(self.config, self.account, "INBOX", is_remote=True)
    body = b"Subject: copy me\r\n\r\ncontent"
    seed_message(self.config, local_mid, body)
    h = self._h()
    h.login()
    h.cmd("A2", "SELECT Archive")
    h.cmd("A3", "COPY 1 INBOX")
    h.finish()
    await h.run()
    # uid_append must have been called on the remote
    self.assertTrue(any(c[0] == "uid_append" for c in self.remote.calls), self.remote.calls)
    with DatabaseSession(self.config) as d:
      row = d.fetchone("SELECT COUNT(*) AS n FROM messages WHERE mailbox_id=? AND remote_uid IS NULL AND is_deleted=0", (remote_mid,))
      assert row is not None
      self.assertEqual(row["n"], 0, "expected no phantom NULL-remote_uid row in remote INBOX")
      dest_lsn = d.fetchone("SELECT last_synced_uid FROM mailboxes WHERE id=?", (remote_mid,))
      assert dest_lsn is not None
      # last_synced must NOT have been advanced ahead by a local copy
      self.assertEqual(dest_lsn["last_synced_uid"], 0)


  # --- Bug 8: IDLE on a LOCAL mailbox must not contact the remote ---

  async def test_idle_on_local_mailbox_does_not_contact_remote(self):
    seed_mailbox(self.config, self.account, "Archive", is_remote=False)
    h = self._h()
    h.login()
    h.cmd("A2", "SELECT Archive")
    h.cmd("A3", "IDLE")
    h.pipe.feed(b"DONE\r\n")
    h.finish()
    await h.run()
    self.assertNotIn("wait_for_update", [c[0] for c in self.remote.calls])

  # --- Bug 5: seen-flag STORE after COPY/APPEND must target the source mailbox ---

  async def test_store_sets_flags_on_remote(self):
    mid = seed_mailbox(self.config, self.account, "INBOX", is_remote=True)
    seed_message(self.config, mid, b"Subject: x\r\n\r\nbody")
    h = self._h()
    h.login()
    h.cmd("A2", "SELECT INBOX")
    h.cmd("A3", "STORE 1 +FLAGS (\\Flagged)")
    h.finish()
    await h.run()
    self.assertTrue(any(c[0] == "uid_store" for c in self.remote.calls), self.remote.calls)

  # --- Bug 1: IDLE on remote drives a single-socket loop (no duplicate sync while idling) ---

  async def test_idle_on_remote_contacts_remote(self):
    seed_mailbox(self.config, self.account, "INBOX", is_remote=True)
    h = self._h()
    h.login()
    h.cmd("A2", "SELECT INBOX")
    h.cmd("A3", "IDLE")
    h.pipe.feed(b"DONE\r\n")
    h.finish()
    await h.run()
    self.assertIn(b"A3 OK IDLE completed", h.output())


def seed_account_remote(config, address):
  from tests.helpers import make_account
  return make_account(address)


if __name__ == "__main__":
  unittest.main()
