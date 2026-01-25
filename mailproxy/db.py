import sqlite3, pathlib, datetime, json
from mailproxy.auth import OAUTHAccessToken

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

def store_account_access_token(db: sqlite3.Connection, account_key: str, token: OAUTHAccessToken):
  token_data = json.dumps({
    "access_token": token.access_token,
    "expires_at": token.expires_at.isoformat(),
    "refresh_token": token.refresh_token,
  })

  db.execute("""
  INSERT INTO login_data (account_key, data) VALUES (?, ?)
  ON CONFLICT(account_key) DO UPDATE SET data = excluded.data;
  """, (account_key, token_data))

def load_account_access_token(db: sqlite3.Connection, account_key: str) -> OAUTHAccessToken | None:
  result = db.execute("SELECT data FROM login_data WHERE account_key=?", (account_key,)).fetchone()
  if result is None:
    return None

  token_data = json.loads(result[0])
  return OAUTHAccessToken(
    access_token=token_data["access_token"],
    expires_at=datetime.datetime.fromisoformat(token_data["expires_at"]),
    refresh_token=token_data["refresh_token"],
  )

def db_mailbox_id(db: sqlite3.Connection, account_key: str, name: bytes):
  result = db.execute("SELECT id FROM mailboxes WHERE account_key=? AND name=?", (account_key, name)).fetchone()
  if result is None: return None
  return result[0]

def db_status_messages(db: sqlite3.Connection, mailbox_id: int):
  return db.execute("SELECT COUNT(*) FROM messages WHERE mailbox_id=?", (mailbox_id,)).fetchone()[0]

def db_status_uid_next(db: sqlite3.Connection, account_key: str, mailbox_id: int):
  return db.execute("SELECT uid_next FROM mailboxes WHERE account_key=? AND id=?", (account_key, mailbox_id)).fetchone()[0]

def db_status_uid_validity(db: sqlite3.Connection, account_key: str, mailbox_id: int):
  return db.execute("SELECT uid_validity FROM mailboxes WHERE account_key=? AND id=?", (account_key, mailbox_id)).fetchone()[0]

def db_status_unseen(db: sqlite3.Connection, mailbox_id: int):
  return db.execute("SELECT COUNT(*) FROM messages WHERE mailbox_id=? AND flags LIKE '%\\Unseen\\%'", (mailbox_id,)).fetchone()[0]

def db_status_deleted(db: sqlite3.Connection, mailbox_id: int):
  return db.execute("SELECT COUNT(*) FROM messages WHERE mailbox_id=? AND flags LIKE '%\\Deleted\\%'", (mailbox_id,)).fetchone()[0]

def db_status_size(db: sqlite3.Connection, mailbox_id: int):
  return db.execute("SELECT COALESCE(SUM(length(data)), 0) FROM messages WHERE mailbox_id=?", (mailbox_id,)).fetchone()[0]
