import pathlib, sqlite3, tempfile, typing, unittest
from typing import override
from mailproxy.db import DatabaseSession, db_open, row_field
from mailproxy.model import Account, AuthenticationPLAIN, Config, TLSMode


def _make_account() -> Account:
  return Account(
    addresses=("test@example.com",),
    imap_host="imap.example.com",
    imap_port=993,
    imap_tlsmode=TLSMode.DIRECT,
    smtp_host="smtp.example.com",
    smtp_port=465,
    smtp_tlsmode=TLSMode.DIRECT,
    auth=AuthenticationPLAIN(password="pass"),
  )


def _make_config(db_path: pathlib.Path) -> Config:
  return Config(
    domain="localhost",
    log_level=10,
    host="127.0.0.1",
    imap_port=0,
    smtp_port=0,
    db_path=db_path,
  )


class TestMessageSoftDelete(unittest.TestCase):
  @override
  def setUp(self):
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
    self.db_path: pathlib.Path = pathlib.Path(self._tmpdir.name) / "test.sqlite"
    self.db: DatabaseSession = DatabaseSession(_make_config(self.db_path))
    _ = self.db.__enter__()
    self.account: Account = _make_account()
    self.db.account_add(self.account)
    self.mailbox_id: int = self.db.mailbox_add(self.account.key, "INBOX", 12345, 1)

  @override
  def tearDown(self):
    _ = self.db.__exit__(None, None, None)
    self._tmpdir.cleanup()

  def _add_message(self, uid: int, flags_s: str = "\\Seen\\", data: bytes = b"Subject: test\r\n\r\nbody"):
    self.db.message_add(uid, self.mailbox_id, 1700000000, flags_s, data, str(uid))

  def test_delete_marks_soft_not_hard(self):
    self._add_message(1)
    self.db.message_delete_by_uid(self.mailbox_id, 1)
    row = self.db.fetchone("SELECT is_deleted FROM messages WHERE mailbox_id=? AND uid=?", (self.mailbox_id, 1))
    assert row is not None
    self.assertEqual(row_field(row, "is_deleted", int), 1)

  def test_size_derived_from_body(self):
    data = b"Subject: x\r\n\r\n" + b"y" * 123
    self._add_message(1, data=data)
    msg = self.db.message_get_by_uid(self.mailbox_id, 1)
    assert msg is not None
    self.assertEqual(msg.size, len(data))

  def test_deleted_not_in_message_list(self):
    self._add_message(1)
    self._add_message(2)
    self.db.message_delete_by_uid(self.mailbox_id, 1)
    uids = [m.uid for m in self.db.message_list(self.mailbox_id)]
    self.assertEqual(uids, [2])

  def test_deleted_not_in_count(self):
    self._add_message(1)
    self._add_message(2)
    self.db.message_delete_by_uid(self.mailbox_id, 1)
    self.assertEqual(self.db.message_count(self.mailbox_id), 1)
    self.assertEqual(self.db.mailbox_count_messages(self.mailbox_id), 1)

  def test_deleted_not_in_unseen_count(self):
    self._add_message(1, "\\\\")      # no flags = unseen
    self._add_message(2, "\\\\")      # no flags = unseen
    self._add_message(3, "\\Seen\\")  # seen, must not be counted as unseen
    self.db.message_delete_by_uid(self.mailbox_id, 1)
    self.assertEqual(self.db.mailbox_count_unseen(self.mailbox_id), 1)

  def test_deleted_not_in_deleted_flag_count(self):
    self._add_message(1, "\\Deleted\\")
    self._add_message(2, "\\Deleted\\")
    self.db.message_delete_by_uid(self.mailbox_id, 1)
    self.assertEqual(self.db.mailbox_count_deleted(self.mailbox_id), 1)

  def test_deleted_not_in_size(self):
    data1 = b"x" * 100
    data2 = b"y" * 200
    self._add_message(1, data=data1)
    self._add_message(2, data=data2)
    self.db.message_delete_by_uid(self.mailbox_id, 1)
    self.assertEqual(self.db.mailbox_size(self.mailbox_id), 200)

  def test_deleted_not_in_get_by_uid(self):
    self._add_message(1)
    self.db.message_delete_by_uid(self.mailbox_id, 1)
    self.assertIsNone(self.db.message_get_by_uid(self.mailbox_id, 1))

  def test_all_messages_includes_deleted(self):
    self._add_message(1)
    self._add_message(2)
    self.db.message_delete_by_uid(self.mailbox_id, 1)
    msgs = self.db.universe_messages(self.account.key)
    self.assertEqual(len(msgs), 2)
    self.assertEqual(sorted(m.uid for m in msgs), [1, 2])

  def test_max_uid_includes_deleted(self):
    self._add_message(1)
    self._add_message(5)
    self._add_message(10)
    self.db.message_delete_by_uid(self.mailbox_id, 10)
    self.assertEqual(self.db.mailbox_max_uid(self.mailbox_id), 10)

  def test_messages_clear_soft_deletes(self):
    self._add_message(1)
    self._add_message(2)
    self.db.messages_clear(self.mailbox_id)
    count = self.db.fetchone("SELECT COUNT(*) as c FROM messages WHERE mailbox_id=? AND is_deleted=0", (self.mailbox_id,))
    assert count is not None
    self.assertEqual(row_field(count, "c", int), 0)
    total = self.db.fetchone("SELECT COUNT(*) as c FROM messages WHERE mailbox_id=?", (self.mailbox_id,))
    assert total is not None
    self.assertEqual(row_field(total, "c", int), 2)

  def test_add_upsert_restores_deleted(self):
    self._add_message(1, "\\Seen\\", b"old data")
    self.db.message_delete_by_uid(self.mailbox_id, 1)
    self.assertIsNone(self.db.message_get_by_uid(self.mailbox_id, 1))
    self.db.message_add(1, self.mailbox_id, 1700000001, "\\Seen\\", b"new data", "1")
    msg = self.db.message_get_by_uid(self.mailbox_id, 1)
    assert msg is not None
    self.assertEqual(self.db.message_body_get(msg.body_hash), b"new data")

  def test_update_flags_skips_client_expunged(self):
    self._add_message(1, "\\Seen\\")
    self.db.message_delete_by_uid(self.mailbox_id, 1)
    self.db.message_update_flags(self.mailbox_id, 1, "\\Flagged\\")
    msg = self.db.message_get_by_uid(self.mailbox_id, 1)
    self.assertIsNone(msg)

  def test_update_flags_restores_remote_deleted(self):
    self._add_message(1, "\\Seen\\")
    _ = self.db.message_delete_except(self.mailbox_id, set(), 1)
    self.db.message_update_flags(self.mailbox_id, 1, "\\Flagged\\", restore=True)
    msg = self.db.message_get_by_uid(self.mailbox_id, 1)
    assert msg is not None
    self.assertEqual(msg.flags_s, "\\Flagged\\")
    self.assertFalse(msg.is_deleted)


class TestMailboxSoftDelete(unittest.TestCase):
  @override
  def setUp(self):
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
    self.db_path: pathlib.Path = pathlib.Path(self._tmpdir.name) / "test.sqlite"
    self.db: DatabaseSession = DatabaseSession(_make_config(self.db_path))
    _ = self.db.__enter__()
    self.account: Account = _make_account()
    self.db.account_add(self.account)
    self.mailbox_id: int = self.db.mailbox_add(self.account.key, "INBOX", 12345, 1)

  @override
  def tearDown(self):
    _ = self.db.__exit__(None, None, None)
    self._tmpdir.cleanup()

  def test_delete_marks_soft_not_hard(self):
    self.db.mailbox_delete(self.mailbox_id)
    row = self.db.fetchone("SELECT is_deleted FROM mailboxes WHERE id=?", (self.mailbox_id,))
    assert row is not None
    self.assertEqual(row_field(row, "is_deleted", int), 1)

  def test_delete_soft_deletes_messages(self):
    self.db.message_add(1, self.mailbox_id, 1700000000, "\\Seen\\", b"data", "1")
    self.db.message_add(2, self.mailbox_id, 1700000001, "\\Seen\\", b"data", "2")
    self.db.mailbox_delete(self.mailbox_id)
    count = self.db.fetchone("SELECT COUNT(*) as c FROM messages WHERE mailbox_id=? AND is_deleted=0", (self.mailbox_id,))
    assert count is not None
    self.assertEqual(row_field(count, "c", int), 0)
    total = self.db.fetchone("SELECT COUNT(*) as c FROM messages WHERE mailbox_id=?", (self.mailbox_id,))
    assert total is not None
    self.assertEqual(row_field(total, "c", int), 2)

  def test_deleted_not_in_mailbox_list(self):
    _ = self.db.mailbox_add(self.account.key, "Sent", 12345, 1)
    self.db.mailbox_delete(self.mailbox_id)
    names = [m.name for m in self.db.mailbox_list(self.account.key)]
    self.assertEqual(names, ["Sent"])

  def test_deleted_not_in_by_name(self):
    self.db.mailbox_delete(self.mailbox_id)
    self.assertIsNone(self.db.mailbox_by_name(self.account.key, "INBOX"))

  def test_deleted_not_in_get_by_id(self):
    self.db.mailbox_delete(self.mailbox_id)
    self.assertIsNone(self.db.mailbox_get_by_id(self.mailbox_id))

  def test_rename_still_works_on_non_deleted(self):
    self.db.mailbox_rename(self.mailbox_id, "Renamed")
    mb = self.db.mailbox_get_by_id(self.mailbox_id)
    assert mb is not None
    self.assertEqual(mb.name, "Renamed")


class TestMergeFlags(unittest.TestCase):
  @override
  def setUp(self):
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
    self.db_path: pathlib.Path = pathlib.Path(self._tmpdir.name) / "test.sqlite"
    self.db: DatabaseSession = DatabaseSession(_make_config(self.db_path))
    _ = self.db.__enter__()
    self.account: Account = _make_account()
    self.db.account_add(self.account)
    self.mailbox_id: int = self.db.mailbox_add(self.account.key, "INBOX", 12345, 1)

  @override
  def tearDown(self):
    _ = self.db.__exit__(None, None, None)
    self._tmpdir.cleanup()

  def _add_message(self, uid: int, flags_s: str = "\\Seen\\"):
    self.db.message_add(uid, self.mailbox_id, 1700000000, flags_s, b"data", str(uid))

  def test_local_keywords_preserved(self):
    self._add_message(1, "\\Seen\\MyTag\\")
    changed = self.db.messages_merge_flags(self.mailbox_id, [(1, "\\Answered\\")])
    self.assertEqual(changed, 1)
    msg = self.db.message_get_by_uid(self.mailbox_id, 1)
    assert msg is not None
    self.assertEqual(msg.flags_s, "\\Answered\\MyTag\\")

  def test_remote_keywords_kept(self):
    self._add_message(1, "\\Seen\\")
    changed = self.db.messages_merge_flags(self.mailbox_id, [(1, "\\Seen\\RemoteKw\\")])
    self.assertEqual(changed, 1)
    msg = self.db.message_get_by_uid(self.mailbox_id, 1)
    assert msg is not None
    self.assertEqual(msg.flags_s, "\\RemoteKw\\Seen\\")

  def test_system_flags_replaced_by_remote(self):
    self._add_message(1, "\\Seen\\Flagged\\")
    changed = self.db.messages_merge_flags(self.mailbox_id, [(1, "\\Answered\\")])
    self.assertEqual(changed, 1)
    msg = self.db.message_get_by_uid(self.mailbox_id, 1)
    assert msg is not None
    self.assertEqual(msg.flags_s, "\\Answered\\")

  def test_soft_deleted_restored(self):
    self._add_message(1, "\\Seen\\MyTag\\")
    _ = self.db.message_delete_except(self.mailbox_id, set(), 1)
    changed = self.db.messages_merge_flags(self.mailbox_id, [(1, "\\Seen\\")])
    self.assertEqual(changed, 1)
    msg = self.db.message_get_by_uid(self.mailbox_id, 1)
    assert msg is not None
    self.assertFalse(msg.is_deleted)
    self.assertEqual(msg.flags_s, "\\MyTag\\Seen\\")

  def test_unchanged_not_rewritten(self):
    self._add_message(1, "\\Seen\\")
    changed = self.db.messages_merge_flags(self.mailbox_id, [(1, "\\Seen\\"), (2, "\\Seen\\")])
    self.assertEqual(changed, 0)


class TestMessageCompression(unittest.TestCase):
  @override
  def setUp(self):
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
    self.db_path: pathlib.Path = pathlib.Path(self._tmpdir.name) / "test.sqlite"
    self.db: DatabaseSession = DatabaseSession(_make_config(self.db_path))
    _ = self.db.__enter__()
    self.account: Account = _make_account()
    self.db.account_add(self.account)
    self.mailbox_id: int = self.db.mailbox_add(self.account.key, "INBOX", 12345, 1)

  @override
  def tearDown(self):
    _ = self.db.__exit__(None, None, None)
    self._tmpdir.cleanup()

  def test_body_roundtrip_is_compressed_and_raw_size_kept(self):
    data = b"Subject: test\r\n\r\n" + b"x" * 5000
    self.db.message_add(1, self.mailbox_id, 1700000000, "\\Seen\\", data, "1")
    msg = self.db.message_get_by_uid(self.mailbox_id, 1)
    assert msg is not None
    self.assertEqual(msg.size, len(data))
    self.assertEqual(self.db.message_body_get(msg.body_hash), data)

  def test_blob_stored_compressed_on_disk(self):
    data = b"Subject: test\r\n\r\n" + b"y" * 10000
    self.db.message_add(1, self.mailbox_id, 1700000000, "\\Seen\\", data, "1")
    row = self.db.fetchone("SELECT data FROM message_bodies WHERE hash=(SELECT body_hash FROM messages WHERE mailbox_id=? AND uid=1)", (self.mailbox_id,))
    assert row is not None
    stored = typing.cast(bytes, row["data"])
    self.assertTrue(stored.startswith(b"\x1f\x8b"))
    self.assertLess(len(stored), len(data))

  def test_compression_level_is_changeable(self):
    data = b"Subject: test\r\n\r\n" + b"z" * 10000
    self.db.message_add(1, self.mailbox_id, 1700000000, "\\Seen\\", data, "1")
    msg = self.db.message_get_by_uid(self.mailbox_id, 1)
    assert msg is not None
    self.assertEqual(self.db.message_body_get(msg.body_hash), data)

  def test_empty_body_stored_as_empty(self):
    self.db.message_add(1, self.mailbox_id, 1700000000, "\\Seen\\", b"", "1")
    msg = self.db.message_get_by_uid(self.mailbox_id, 1)
    assert msg is not None
    self.assertEqual(self.db.message_body_get(msg.body_hash), b"")


class TestSchemaMigration(unittest.TestCase):
  def test_is_deleted_columns_exist(self):
    tmpdir = tempfile.TemporaryDirectory()
    db_path = pathlib.Path(tmpdir.name) / "test.sqlite"
    db = db_open(db_path)
    msg_rows = typing.cast(list[sqlite3.Row], db.execute("PRAGMA table_info(messages)").fetchall())
    msg_cols = [row_field(r, "name", str) for r in msg_rows]
    self.assertIn("is_deleted", msg_cols)
    mb_rows = typing.cast(list[sqlite3.Row], db.execute("PRAGMA table_info(mailboxes)").fetchall())
    mb_cols = [row_field(r, "name", str) for r in mb_rows]
    self.assertIn("is_deleted", mb_cols)
    db.close()
    tmpdir.cleanup()

  def test_migration_on_existing_db(self):
    tmpdir = tempfile.TemporaryDirectory()
    db_path = pathlib.Path(tmpdir.name) / "test.sqlite"
    db = db_open(db_path)
    db.close()
    db = db_open(db_path)
    msg_rows = typing.cast(list[sqlite3.Row], db.execute("PRAGMA table_info(messages)").fetchall())
    msg_cols = [row_field(r, "name", str) for r in msg_rows]
    self.assertIn("is_deleted", msg_cols)
    mb_rows = typing.cast(list[sqlite3.Row], db.execute("PRAGMA table_info(mailboxes)").fetchall())
    mb_cols = [row_field(r, "name", str) for r in mb_rows]
    self.assertIn("is_deleted", mb_cols)
    db.close()
    tmpdir.cleanup()


if __name__ == "__main__":
  _ = unittest.main()
