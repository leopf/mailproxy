import pathlib, sqlite3, tempfile, unittest
from typing import override
from mailproxy.db import db_open, db_account_add, db_mailbox_add, db_message_add, db_message_delete_by_uid, \
    db_message_delete_except, \
    db_message_list, db_message_get_by_uid, db_message_update_flags, db_message_count, db_messages_clear, \
    db_message_body_get, db_universe_messages, db_mailbox_count_messages, db_mailbox_count_unseen, db_mailbox_count_deleted, \
    db_mailbox_size, db_mailbox_max_uid, db_mailbox_delete, db_mailbox_list, db_mailbox_by_name, \
    db_mailbox_get_by_id, db_mailbox_rename, fetchone, iter_rows, row_field
from mailproxy.model import Account, AuthenticationPLAIN, TLSMode


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


class TestMessageSoftDelete(unittest.TestCase):
  @override
  def setUp(self):
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
    self.db_path: pathlib.Path = pathlib.Path(self._tmpdir.name) / "test.sqlite"
    self.db: sqlite3.Connection = db_open(self.db_path)
    self.account: Account = _make_account()
    db_account_add(self.db, self.account)
    self.mailbox_id: int = db_mailbox_add(self.db, self.account.key, "INBOX", 12345, 1)

  @override
  def tearDown(self):
    self.db.close()
    self._tmpdir.cleanup()

  def _add_message(self, uid: int, flags_s: str = "\\Seen\\", data: bytes = b"Subject: test\r\n\r\nbody"):
    db_message_add(self.db, uid, self.mailbox_id, 1700000000, flags_s, len(data), data, str(uid))

  def test_delete_marks_soft_not_hard(self):
    self._add_message(1)
    db_message_delete_by_uid(self.db, self.mailbox_id, 1)
    row = fetchone(self.db, "SELECT is_deleted FROM messages WHERE mailbox_id=? AND uid=?", (self.mailbox_id, 1))
    assert row is not None
    self.assertEqual(row_field(row, "is_deleted", int), 1)

  def test_deleted_not_in_message_list(self):
    self._add_message(1)
    self._add_message(2)
    db_message_delete_by_uid(self.db, self.mailbox_id, 1)
    uids = [m.uid for m in db_message_list(self.db, self.mailbox_id)]
    self.assertEqual(uids, [2])

  def test_deleted_not_in_count(self):
    self._add_message(1)
    self._add_message(2)
    db_message_delete_by_uid(self.db, self.mailbox_id, 1)
    self.assertEqual(db_message_count(self.db, self.mailbox_id), 1)
    self.assertEqual(db_mailbox_count_messages(self.db, self.mailbox_id), 1)

  def test_deleted_not_in_unseen_count(self):
    self._add_message(1, "\\\\")      # no flags = unseen
    self._add_message(2, "\\\\")      # no flags = unseen
    self._add_message(3, "\\Seen\\")  # seen, must not be counted as unseen
    db_message_delete_by_uid(self.db, self.mailbox_id, 1)
    self.assertEqual(db_mailbox_count_unseen(self.db, self.mailbox_id), 1)

  def test_deleted_not_in_deleted_flag_count(self):
    self._add_message(1, "\\Deleted\\")
    self._add_message(2, "\\Deleted\\")
    db_message_delete_by_uid(self.db, self.mailbox_id, 1)
    self.assertEqual(db_mailbox_count_deleted(self.db, self.mailbox_id), 1)

  def test_deleted_not_in_size(self):
    data1 = b"x" * 100
    data2 = b"y" * 200
    self._add_message(1, data=data1)
    self._add_message(2, data=data2)
    db_message_delete_by_uid(self.db, self.mailbox_id, 1)
    self.assertEqual(db_mailbox_size(self.db, self.mailbox_id), 200)

  def test_deleted_not_in_get_by_uid(self):
    self._add_message(1)
    db_message_delete_by_uid(self.db, self.mailbox_id, 1)
    self.assertIsNone(db_message_get_by_uid(self.db, self.mailbox_id, 1))

  def test_all_messages_includes_deleted(self):
    self._add_message(1)
    self._add_message(2)
    db_message_delete_by_uid(self.db, self.mailbox_id, 1)
    msgs = db_universe_messages(self.db, self.account.key)
    self.assertEqual(len(msgs), 2)
    self.assertEqual(sorted(m.uid for m in msgs), [1, 2])

  def test_max_uid_includes_deleted(self):
    self._add_message(1)
    self._add_message(5)
    self._add_message(10)
    db_message_delete_by_uid(self.db, self.mailbox_id, 10)
    self.assertEqual(db_mailbox_max_uid(self.db, self.mailbox_id), 10)

  def test_messages_clear_soft_deletes(self):
    self._add_message(1)
    self._add_message(2)
    db_messages_clear(self.db, self.mailbox_id)
    count = fetchone(self.db, "SELECT COUNT(*) as c FROM messages WHERE mailbox_id=? AND is_deleted=0", (self.mailbox_id,))
    assert count is not None
    self.assertEqual(row_field(count, "c", int), 0)
    total = fetchone(self.db, "SELECT COUNT(*) as c FROM messages WHERE mailbox_id=?", (self.mailbox_id,))
    assert total is not None
    self.assertEqual(row_field(total, "c", int), 2)

  def test_add_upsert_restores_deleted(self):
    self._add_message(1, "\\Seen\\", b"old data")
    db_message_delete_by_uid(self.db, self.mailbox_id, 1)
    self.assertIsNone(db_message_get_by_uid(self.db, self.mailbox_id, 1))
    db_message_add(self.db, 1, self.mailbox_id, 1700000001, "\\Seen\\", 8, b"new data", "1")
    msg = db_message_get_by_uid(self.db, self.mailbox_id, 1)
    assert msg is not None
    self.assertEqual(db_message_body_get(self.db, msg.body_hash), b"new data")

  def test_update_flags_skips_client_expunged(self):
    self._add_message(1, "\\Seen\\")
    db_message_delete_by_uid(self.db, self.mailbox_id, 1)
    db_message_update_flags(self.db, self.mailbox_id, 1, "\\Flagged\\")
    msg = db_message_get_by_uid(self.db, self.mailbox_id, 1)
    self.assertIsNone(msg)

  def test_update_flags_restores_remote_deleted(self):
    self._add_message(1, "\\Seen\\")
    _ = db_message_delete_except(self.db, self.mailbox_id, set(), 1)
    db_message_update_flags(self.db, self.mailbox_id, 1, "\\Flagged\\")
    msg = db_message_get_by_uid(self.db, self.mailbox_id, 1)
    assert msg is not None
    self.assertEqual(msg.flags_s, "\\Flagged\\")
    self.assertFalse(msg.is_deleted)


class TestMailboxSoftDelete(unittest.TestCase):
  @override
  def setUp(self):
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
    self.db_path: pathlib.Path = pathlib.Path(self._tmpdir.name) / "test.sqlite"
    self.db: sqlite3.Connection = db_open(self.db_path)
    self.account: Account = _make_account()
    db_account_add(self.db, self.account)
    self.mailbox_id: int = db_mailbox_add(self.db, self.account.key, "INBOX", 12345, 1)

  @override
  def tearDown(self):
    self.db.close()
    self._tmpdir.cleanup()

  def test_delete_marks_soft_not_hard(self):
    db_mailbox_delete(self.db, self.mailbox_id)
    row = fetchone(self.db, "SELECT is_deleted FROM mailboxes WHERE id=?", (self.mailbox_id,))
    assert row is not None
    self.assertEqual(row_field(row, "is_deleted", int), 1)

  def test_delete_soft_deletes_messages(self):
    db_message_add(self.db, 1, self.mailbox_id, 1700000000, "\\Seen\\", 4, b"data", "1")
    db_message_add(self.db, 2, self.mailbox_id, 1700000001, "\\Seen\\", 4, b"data", "2")
    db_mailbox_delete(self.db, self.mailbox_id)
    count = fetchone(self.db, "SELECT COUNT(*) as c FROM messages WHERE mailbox_id=? AND is_deleted=0", (self.mailbox_id,))
    assert count is not None
    self.assertEqual(row_field(count, "c", int), 0)
    total = fetchone(self.db, "SELECT COUNT(*) as c FROM messages WHERE mailbox_id=?", (self.mailbox_id,))
    assert total is not None
    self.assertEqual(row_field(total, "c", int), 2)

  def test_deleted_not_in_mailbox_list(self):
    _ = db_mailbox_add(self.db, self.account.key, "Sent", 12345, 1)
    db_mailbox_delete(self.db, self.mailbox_id)
    names = [m.name for m in db_mailbox_list(self.db, self.account.key)]
    self.assertEqual(names, ["Sent"])

  def test_deleted_not_in_by_name(self):
    db_mailbox_delete(self.db, self.mailbox_id)
    self.assertIsNone(db_mailbox_by_name(self.db, self.account.key, "INBOX"))

  def test_deleted_not_in_get_by_id(self):
    db_mailbox_delete(self.db, self.mailbox_id)
    self.assertIsNone(db_mailbox_get_by_id(self.db, self.mailbox_id))

  def test_rename_still_works_on_non_deleted(self):
    db_mailbox_rename(self.db, self.mailbox_id, "Renamed")
    mb = db_mailbox_get_by_id(self.db, self.mailbox_id)
    assert mb is not None
    self.assertEqual(mb.name, "Renamed")


class TestSchemaMigration(unittest.TestCase):
  def test_is_deleted_columns_exist(self):
    tmpdir = tempfile.TemporaryDirectory()
    db_path = pathlib.Path(tmpdir.name) / "test.sqlite"
    db = db_open(db_path)
    msg_cols = [row_field(r, "name", str) for r in iter_rows(db, "PRAGMA table_info(messages)")]
    self.assertIn("is_deleted", msg_cols)
    mb_cols = [row_field(r, "name", str) for r in iter_rows(db, "PRAGMA table_info(mailboxes)")]
    self.assertIn("is_deleted", mb_cols)
    db.close()
    tmpdir.cleanup()

  def test_migration_on_existing_db(self):
    tmpdir = tempfile.TemporaryDirectory()
    db_path = pathlib.Path(tmpdir.name) / "test.sqlite"
    db = db_open(db_path)
    db.close()
    db = db_open(db_path)
    msg_cols = [row_field(r, "name", str) for r in iter_rows(db, "PRAGMA table_info(messages)")]
    self.assertIn("is_deleted", msg_cols)
    mb_cols = [row_field(r, "name", str) for r in iter_rows(db, "PRAGMA table_info(mailboxes)")]
    self.assertIn("is_deleted", mb_cols)
    db.close()
    tmpdir.cleanup()


if __name__ == "__main__":
  _ = unittest.main()
