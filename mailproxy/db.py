import sqlite3, pathlib

from mailproxy.model import Mailbox

_DB_INIT_SCIPT = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS oauth2_data (
  account_key TEXT PRIMARY KEY,
  access_token TEXT NOT NULL,
  refresh_token TEXT NOT NULL,
  expries_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mailboxes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_key TEXT NOT NULL,
  uid_next INTEGER NOT NULL DEFAULT 1,
  uid_validity INTEGER NOT NULL DEFAULT (unixepoch('now')),
  name TEXT NOT NULL,
  attributes TEXT NOT NULL DEFAULT '',
  is_virtual INTEGER NOT NULL DEFAULT 0,
  is_remote INTEGER NOT NULL DEFAULT 0,
  UNIQUE(account_key, name)
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uid INTEGER NOT NULL,
  mailbox_id INTEGER,
  received_date INTEGER NOT NULL,

  flags TEXT NOT NULL DEFAULT '\\',

  size INTEGER NOT NULL,
  data BLOB NOT NULL,
  remote_uid TEXT,
  UNIQUE(mailbox_id, uid),
  FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id ON messages(mailbox_id);
"""

def db_open(db_path: pathlib.Path) -> sqlite3.Connection:
  conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
  conn.row_factory = sqlite3.Row

  with conn:
    conn.executescript(_DB_INIT_SCIPT)

  return conn

def _mailbox_from_row(row: sqlite3.Row):
  return Mailbox(id=row["id"], account_key=row["account_key"], uid_next=row["uid_next"], uid_validity=row["uid_validity"], \
    name=row["name"], is_virtual=bool(row["is_virtual"]), is_remote=bool(row["is_remote"]))

def db_mailbox_by_name(db: sqlite3.Connection, account_key: str, name: bytes):
  result = db.execute("SELECT * FROM mailboxes WHERE account_key=? AND name=?", (account_key, name)).fetchone()
  return None if result is None else _mailbox_from_row(result)

def db_mailbox_count_messages(db: sqlite3.Connection, mailbox_id: int):
  return db.execute("SELECT COUNT(*) FROM messages WHERE mailbox_id=?", (mailbox_id,)).fetchone()[0]

def db_mailbox_uid_next(db: sqlite3.Connection, account_key: str, mailbox_id: int):
  return db.execute("SELECT uid_next FROM mailboxes WHERE account_key=? AND id=?", (account_key, mailbox_id)).fetchone()["uid_next"]

def db_mailbox_uid_validity(db: sqlite3.Connection, account_key: str, mailbox_id: int):
  return db.execute("SELECT uid_validity FROM mailboxes WHERE account_key=? AND id=?", (account_key, mailbox_id)).fetchone()["uid_validity"]

def db_mailbox_count_unseen(db: sqlite3.Connection, mailbox_id: int):
  return db.execute("SELECT COUNT(*) FROM messages WHERE mailbox_id=? AND flags LIKE '%\\Unseen\\%'", (mailbox_id,)).fetchone()[0]

def db_mailbox_count_deleted(db: sqlite3.Connection, mailbox_id: int):
  return db.execute("SELECT COUNT(*) FROM messages WHERE mailbox_id=? AND flags LIKE '%\\Deleted\\%'", (mailbox_id,)).fetchone()[0]

def db_mailbox_size(db: sqlite3.Connection, mailbox_id: int):
  return db.execute("SELECT COALESCE(SUM(length(data)), 0) FROM messages WHERE mailbox_id=?", (mailbox_id,)).fetchone()[0]
