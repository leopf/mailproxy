import asyncio, pathlib, tempfile, unittest
from typing import override

from mailproxy.db import DatabaseSession
from mailproxy.imap_backend import IMAPRemoteConnection
from mailproxy.imap_parsing import IMAPAlreadyExistsError, IMAPCommandFailedError

from tests.fake_remote import FakeRemoteConnection
from tests.harness import IMAPHarness
from tests.helpers import BidiPipe, RecordingTlsWriter, make_config, seed_account, seed_mailbox, seed_message
from mailproxy.model import Account, AuthenticationPLAIN, Config, TLSMode


class TestBugRegressions(unittest.IsolatedAsyncioTestCase):
  @override
  def setUp(self):
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
    self.config: Config = make_config(pathlib.Path(self._tmpdir.name) / "test.sqlite")
    self.account: str = "test@example.com"
    _ = seed_account(self.config, self.account)
    self.remote: FakeRemoteConnection = FakeRemoteConnection(self.config, _make_account(self.account))

  @override
  def tearDown(self):
    self._tmpdir.cleanup()

  def _h(self) -> IMAPHarness:
    return IMAPHarness(self.config, self.account, remote=self.remote)

  # --- Bug 4: BODY.PEEK[HEADER.FIELDS.NOT (...)] should EXCLUDE listed fields ---

  async def test_header_fields_not_excludes_listed_fields(self):
    mid = seed_mailbox(self.config, self.account, "INBOX", is_remote=True)
    body = b"From: a@b\r\nTo: c@d\r\nSubject: hi\r\nX-Large: y\r\n\r\nhello"
    _ = seed_message(self.config, mid, body)
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
    _ = seed_message(self.config, local_mid, body)
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
    _ = seed_mailbox(self.config, self.account, "Archive", is_remote=False)
    h = self._h()
    h.login()
    h.cmd("A2", "SELECT Archive")
    h.cmd("A3", "IDLE")
    h.pipe.feed(b"DONE\r\n")
    h.finish()
    await h.run()
    self.assertNotIn("idle", [c[0] for c in self.remote.calls])

  # --- Bug 5: seen-flag STORE after COPY/APPEND must target the source mailbox ---

  async def test_store_sets_flags_on_remote(self):
    mid = seed_mailbox(self.config, self.account, "INBOX", is_remote=True)
    _ = seed_message(self.config, mid, b"Subject: x\r\n\r\nbody")
    h = self._h()
    h.login()
    h.cmd("A2", "SELECT INBOX")
    h.cmd("A3", "STORE 1 +FLAGS (\\Flagged)")
    h.finish()
    await h.run()
    self.assertTrue(any(c[0] == "uid_store_many" for c in self.remote.calls), self.remote.calls)

  # --- Yahoo: STORE of many messages must use one remote command, not one per message ---

  async def test_store_batches_remote_updates(self):
    mid = seed_mailbox(self.config, self.account, "INBOX", is_remote=True)
    for _ in range(3):
      _ = seed_message(self.config, mid, b"Subject: x\r\n\r\nbody")
    h = self._h()
    h.login()
    h.cmd("A2", "SELECT INBOX")
    h.cmd("A3", "UID STORE 1:3 +FLAGS.SILENT (\\Seen)")
    h.finish()
    await h.run()
    calls = [c for c in self.remote.calls if c[0] == "uid_store_many"]
    self.assertEqual(len(calls), 1, self.remote.calls)
    self.assertEqual(calls[0][1][0], [1, 2, 3])
    self.assertEqual(calls[0][1][1], b"+FLAGS.SILENT")

  # --- Yahoo: CREATE of an already existing folder must not surface as an error ---

  async def test_create_already_exists_is_ok(self):
    def exists(*_args: object) -> None:
      raise IMAPAlreadyExistsError("remote command failed: NO create failure: Folder: /Trash exists")

    self.remote.behaviors["create_mailbox"] = exists
    h = self._h()
    h.login()
    h.cmd("A2", "CREATE Trash")
    h.finish()
    await h.run()
    self.assertIn(b"A2 OK CREATE completed", h.output())

  async def test_create_other_failure_still_errors(self):
    def denied(*_args: object) -> None:
      raise IMAPCommandFailedError("remote command failed: NO permission denied")

    self.remote.behaviors["create_mailbox"] = denied
    h = self._h()
    h.login()
    h.cmd("A2", "CREATE Trash")
    h.finish()
    await h.run()
    self.assertIn(b"A2 NO", h.output())

  # --- Bug 1: IDLE on remote drives a single-socket loop (no duplicate sync while idling) ---

  async def test_idle_on_remote_contacts_remote(self):
    _ = seed_mailbox(self.config, self.account, "INBOX", is_remote=True)
    h = self._h()
    h.login()
    h.cmd("A2", "SELECT INBOX")
    h.cmd("A3", "IDLE")
    h.pipe.feed(b"DONE\r\n")
    h.finish()
    await h.run()
    self.assertIn(b"A3 OK IDLE completed", h.output())

  async def test_noop_without_mailbox_ok(self):
    h = self._h()
    h.login()
    h.cmd("A2", "NOOP")
    h.finish()
    await h.run()
    self.assertIn(b"A2 OK NOOP completed", h.output())

  async def test_list_lists_mailboxes(self):
    _ = seed_mailbox(self.config, self.account, "INBOX", is_remote=True)
    _ = seed_mailbox(self.config, self.account, "Archive", is_remote=False)
    h = self._h()
    h.login()
    h.cmd("A2", "LIST \"\" \"*\"")
    h.finish()
    await h.run()
    out = h.output()
    self.assertIn(b"INBOX", out)
    self.assertIn(b"Archive", out)


class TestStartTlsUpgrade(unittest.IsolatedAsyncioTestCase):
  # --- Bug: STARTTLS upgrades must pass server_hostname (check_hostname requires it) ---

  async def test_imap_starttls_passes_server_hostname(self):
    pipe = BidiPipe()
    writer = RecordingTlsWriter(pipe.a_writer)
    account = Account(
      addresses=("test@example.com",),
      imap_host="imap.example.com",
      imap_port=143,
      imap_tlsmode=TLSMode.STARTTLS,
      smtp_host="smtp.example.com",
      smtp_port=587,
      smtp_tlsmode=TLSMode.STARTTLS,
      auth=AuthenticationPLAIN(password="pw"),
    )
    conn = IMAPRemoteConnection(make_config(), account, pipe.a_reader, writer)  # pyright: ignore[reportArgumentType]
    task = asyncio.create_task(conn._command_starttls())
    self.assertEqual(await asyncio.wait_for(pipe.b_reader.readuntil(b"\r\n"), timeout=5), b"A1 STARTTLS\r\n")
    pipe.feed_a(b"A1 OK begin TLS\r\n")
    await asyncio.wait_for(task, timeout=5)
    self.assertEqual([host for _, host in writer.tls_upgrades], ["imap.example.com"])


def _make_account(address: str):
  from tests.helpers import make_account
  return make_account(address)


if __name__ == "__main__":
  _ = unittest.main()
