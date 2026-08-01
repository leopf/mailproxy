import pathlib, tempfile, unittest
from typing import override

from mailproxy.db import DatabaseSession, row_field
from tests.harness import IMAPHarness
from tests.fake_remote import FakeRemoteConnection
from tests.helpers import make_account, make_config, seed_account, seed_mailbox, seed_message
from mailproxy.model import Config


class TestFetchProbes(unittest.IsolatedAsyncioTestCase):
  @override
  def setUp(self):
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
    self.config: Config = make_config(pathlib.Path(self._tmpdir.name) / "test.sqlite")
    self.account: str = "test@example.com"
    _ = seed_account(self.config, self.account)
    self.remote: FakeRemoteConnection = FakeRemoteConnection(self.config, make_account(self.account))

  @override
  @override
  def tearDown(self):
    self._tmpdir.cleanup()

  def _h(self) -> IMAPHarness:
    return IMAPHarness(self.config, remote=self.remote)

  async def _select_local_inbox(self, h: IMAPHarness, bodies: list[bytes]) -> int:
    mid = seed_mailbox(self.config, self.account, "INBOX", is_remote=False)
    for b in bodies:
      _ = seed_message(self.config, mid, b)
    h.login_cmd()
    h.cmd("A2", "SELECT INBOX")
    return mid

  # --- FETCH UID mode: does it return the right sequence vs uid? ---

  async def test_fetch_uid_returns_uid_item(self):
    h = self._h()
    _ = await self._select_local_inbox(h, [b"Subject: one\r\n\r\n1", b"Subject: two\r\n\r\n2"])
    h.cmd("A3", "FETCH 1:* (UID FLAGS)")
    h.finish()
    await h.run()
    out = h.output()
    # In UID mode, responses must include UID item
    self.assertIn(b"UID 1", out)
    self.assertIn(b"UID 2", out)
    # FLAGS must be present (the \Seen default)
    self.assertIn(b"FLAGS", out)

  async def test_fetch_sequence_number_uses_seq_not_uid(self):
    h = self._h()
    _ = await self._select_local_inbox(h, [b"a", b"b", b"c"])
    h.cmd("A3", "FETCH 2 (RFC822.SIZE)")
    h.finish()
    await h.run()
    out = h.output()
    # "2 FETCH" is the seq number of message 2
    self.assertIn(b"* 2 FETCH (RFC822.SIZE", out)


  async def test_search_all_returns_all(self):
    h = self._h()
    _ = await self._select_local_inbox(h, [b"Subject: one\r\n\r\n1", b"Subject: two\r\n\r\n2"])
    h.cmd("A3", "SEARCH ALL")
    h.finish()
    await h.run()
    out = h.output()
    self.assertIn(b"* SEARCH 1 2", out)

  async def test_search_subject(self):
    h = self._h()
    _ = await self._select_local_inbox(h, [b"Subject: apple\r\n\r\n1", b"Subject: banana\r\n\r\n2"])
    h.cmd("A3", "SEARCH SUBJECT apple")
    h.finish()
    await h.run()
    out = h.output()
    self.assertIn(b"* SEARCH 1", out)

  async def test_status_messages_uidnext(self):
    h = self._h()
    _ = await self._select_local_inbox(h, [b"a", b"b"])
    h.cmd("A3", "STATUS INBOX (MESSAGES UIDNEXT)")
    h.finish()
    await h.run()
    out = h.output()
    self.assertIn(b"MESSAGES 2", out)
    self.assertIn(b"UIDNEXT 3", out)

  async def test_store_adds_flag(self):
    h = self._h()
    mid = await self._select_local_inbox(h, [b"subject x\r\n\r\nbody"])
    h.cmd("A3", "STORE 1 +FLAGS (\\Flagged)")
    h.finish()
    await h.run()
    out = h.output()
    self.assertIn(b"\\Flagged", out)
    with DatabaseSession(self.config) as d:
      row = d.fetchone("SELECT flags_s FROM messages WHERE mailbox_id=? AND uid=1", (mid,))
      assert row is not None
      self.assertIn("Flagged", row_field(row, "flags_s", str))

  async def test_expunge_removes_deleted(self):
    h = self._h()
    mid = await self._select_local_inbox(h, [b"a", b"b"])
    h.cmd("A3", "STORE 1 +FLAGS (\\Deleted)")
    h.cmd("A4", "EXPUNGE")
    h.finish()
    await h.run()
    with DatabaseSession(self.config) as d:
      row = d.fetchone("SELECT is_deleted FROM messages WHERE mailbox_id=? AND uid=1", (mid,))
      assert row is not None
      self.assertEqual(row["is_deleted"], 1)

  async def test_noop_syncs_remote_mailbox(self):
    _ = seed_mailbox(self.config, self.account, "INBOX", is_remote=True)
    h = self._h()
    h.login_cmd()
    h.cmd("A2", "SELECT INBOX")
    h.cmd("A3", "NOOP")
    h.finish()
    await h.run()
    # NOOP triggers a sync on remote mailbox
    self.assertIn("sync_mailbox", [c[0] for c in self.remote.calls])


class TestSearchProbes(unittest.IsolatedAsyncioTestCase):
  """Seed 3 messages with distinct flags/subjects and assert SEARCH results.
  msg1: \\Seen, 'Subject: one'; msg2: \\Answered, 'Subject: two'; msg3: unseen, 'Subject: three'."""

  @override
  def setUp(self):
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
    self.config: Config = make_config(pathlib.Path(self._tmpdir.name) / "test.sqlite")
    self.account: str = "test@example.com"
    _ = seed_account(self.config, self.account)
    self.remote: FakeRemoteConnection = FakeRemoteConnection(self.config, make_account(self.account))
    self.mid: int = seed_mailbox(self.config, self.account, "INBOX", is_remote=False)
    with DatabaseSession(self.config) as d:
      d.message_add(1, self.mid, 1700000000, "\\Seen\\", b"Subject: one\r\n\r\n1", "1")
      d.message_add(2, self.mid, 1700000000, "\\Answered\\", b"Subject: two\r\n\r\n2", "2")
      d.message_add(3, self.mid, 1700000000, "\\", b"Subject: three\r\n\r\n3", "3")
      d.mailbox_update_sync(self.mid, uid_next=4, last_synced_uid=3)

  @override
  def tearDown(self):
    self._tmpdir.cleanup()

  async def _search(self, criteria: str) -> bytes:
    h = IMAPHarness(self.config, remote=self.remote)
    h.login_cmd()
    h.cmd("A2", "SELECT INBOX")
    h.cmd("A3", "SEARCH %s" % criteria)
    h.finish()
    await h.run()
    line = [l for l in h.output().split(b"\r\n") if l.startswith(b"* SEARCH")]
    return line[0] if line else b"* SEARCH"

  async def test_seen(self):
    self.assertEqual(await self._search("SEEN"), b"* SEARCH 1")

  async def test_unseen(self):
    self.assertEqual(await self._search("UNSEEN"), b"* SEARCH 2 3")

  async def test_or_two(self):
    self.assertEqual(await self._search("OR SEEN UNSEEN"), b"* SEARCH 1 2 3")

  async def test_or_nested(self):
    self.assertEqual(await self._search("OR OR SEEN UNSEEN ANSWERED"), b"* SEARCH 1 2 3")

  async def test_not(self):
    self.assertEqual(await self._search("NOT SEEN"), b"* SEARCH 2 3")

  async def test_group(self):
    self.assertEqual(await self._search("(SEEN)"), b"* SEARCH 1")

  async def test_group_not(self):
    self.assertEqual(await self._search("(NOT SEEN)"), b"* SEARCH 2 3")

  async def test_not_group(self):
    self.assertEqual(await self._search("NOT (SEEN)"), b"* SEARCH 2 3")

  async def test_group_or(self):
    self.assertEqual(await self._search("(OR SEEN UNSEEN)"), b"* SEARCH 1 2 3")

  async def test_or_not(self):
    self.assertEqual(await self._search("OR NOT SEEN ANSWERED"), b"* SEARCH 2 3")

  async def test_subject(self):
    self.assertEqual(await self._search("SUBJECT one"), b"* SEARCH 1")

  async def test_or_subject(self):
    self.assertEqual(await self._search("OR SUBJECT one SUBJECT three"), b"* SEARCH 1 3")

  async def test_all(self):
    self.assertEqual(await self._search("ALL"), b"* SEARCH 1 2 3")


if __name__ == "__main__":
  _ = unittest.main()
