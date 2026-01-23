import sqlite3, pathlib

_DB_INIT_SCIPT = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY CHECK(length(key) <= 255),
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mailboxes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_key TEXT NOT NULL,
  uid_next INTEGER NOT NULL DEFAULT 1,
  uid_validity INTEGER NOT NULL DEFAULT (unixepoch('now')),
  name TEXT NOT NULL UNIQUE,
  attributes TEXT NOT NULL DEFAULT '',
  is_virtual INTEGER NOT NULL DEFAULT 0,
  is_remote INTEGER NOT NULL DEFAULT 0
  FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uid INTEGER NOT NULL UNIQUE,
  mailbox_id INTEGER,
  received_date INTEGER NOT NULL,

  flag_seen BOOLEAN NOT NULL DEFAULT FALSE,
  flag_answered BOOLEAN NOT NULL DEFAULT FALSE,
  flag_flagged BOOLEAN NOT NULL DEFAULT FALSE,
  flag_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  flag_draft BOOLEAN NOT NULL DEFAULT FALSE,
  flag_recent BOOLEAN NOT NULL DEFAULT FALSE,

  size INTEGER NOT NULL,
  data BLOB NOT NULL,
  remote_uid TEXT,
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

def db_mailbox_id(db: sqlite3.Connection, name: bytes):
  result = db.execute("SELECT id FROM mailboxes WHERE name=?", (name,)).fetchone()
  if result is None: return None
  return result[0]

def db_status_messages(db: sqlite3.Connection, account_key: str, mailbox_id: int):
  return db.execute("SELECT COUNT(*) FROM messages WHERE account_key=? AND mailbox_id=?", (account_key, mailbox_id)).fetchone()[0]

def db_status_uid_next(db: sqlite3.Connection, account_key: str, mailbox_id: int):
  return db.execute("SELECT uid_next FROM mailboxes WHERE account_key=? AND id=?", (account_key, mailbox_id)).fetchone()[0]

def db_status_uid_validity(db: sqlite3.Connection, account_key: str, mailbox_id: int):
  return db.execute("SELECT uid_validity FROM mailboxes WHERE account_key=? AND id=?", (account_key, mailbox_id)).fetchone()[0]

def db_status_unseen(db: sqlite3.Connection, account_key: str, mailbox_id: int):
  return db.execute("SELECT COUNT(*) FROM messages WHERE account_key=? AND mailbox_id=? AND flag_unseen=1", (account_key, mailbox_id)).fetchone()[0]

def db_status_deleted(db: sqlite3.Connection, account_key: str, mailbox_id: int):
  return db.execute("SELECT COUNT(*) FROM messages WHERE account_key=? AND mailbox_id=? AND flag_deleted=1", (account_key, mailbox_id)).fetchone()[0]

def db_status_size(db: sqlite3.Connection, account_key: str, mailbox_id: int):
  return db.execute("SELECT COALESCE(SUM(length(data)), 0) FROM messages WHERE account_key=? AND mailbox_id=?", \
      (account_key, mailbox_id)).fetchone()[0]
