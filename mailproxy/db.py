import sqlite3
from mailproxy.config import Account

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
  name TEXT NOT NULL UNIQUE,
  attributes TEXT NOT NULL DEFAULT '',
  is_virtual INTEGER NOT NULL DEFAULT 0,
  is_remote INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mailbox_id INTEGER,
  received_date INTEGER NOT NULL,
  flags TEXT NOT NULL DEFAULT '',
  size INTEGER NOT NULL,
  data BLOB NOT NULL,
  remote_uid TEXT,
  FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id ON messages(mailbox_id);
"""

def db_open(account: Account) -> sqlite3.Connection:
  account.db_path.parent.mkdir(parents=True, exist_ok=True)
  conn = sqlite3.connect(account.db_path, timeout=30, check_same_thread=False)
  conn.row_factory = sqlite3.Row

  with conn:
    conn.executescript(_DB_INIT_SCIPT)

  return conn

def db_message_uid_next(conn: sqlite3.Connection) -> int:
  row = conn.execute("SELECT seq FROM sqlite_sequence WHERE name=?", ("messages",)).fetchone()
  if row is not None:
    return int(row[0]) + 1

  fallback = conn.execute("SELECT COALESCE(MAX(id), 0) FROM messages").fetchone()
  return int(fallback[0]) + 1
