import sqlite3, pathlib, datetime, json, typing
from collections.abc import Iterator
from typing import TypeVar
from mailproxy.model import Account, AuthenticationOAUTH2, AuthenticationPLAIN, Mailbox, Message, TLSMode
from mailproxy.utils import json_loads_object, is_object_list

T = TypeVar("T")

def row_field(row: sqlite3.Row, name: str, expected: type[T]) -> T:
  value: object = typing.cast(object, row[name])
  if not isinstance(value, expected):
    raise ValueError(f"field '{name}' must be {expected.__name__}, got {type(value).__name__}")
  return value

def row_optional(row: sqlite3.Row, name: str, expected: type[T]) -> T | None:
  value: object = typing.cast(object, row[name])
  if value is None:
    return None
  if not isinstance(value, expected):
    raise ValueError(f"field '{name}' must be {expected.__name__} or null, got {type(value).__name__}")
  return value

_DB_INIT_SCRIPT = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS accounts (
  account_key TEXT PRIMARY KEY,
  addresses TEXT NOT NULL,
  imap_host TEXT NOT NULL,
  imap_port INTEGER NOT NULL,
  imap_tlsmode TEXT NOT NULL,
  smtp_host TEXT NOT NULL,
  smtp_port INTEGER NOT NULL,
  smtp_tlsmode TEXT NOT NULL,
  auth_type TEXT NOT NULL,
  scope TEXT,
  client_id TEXT,
  client_secret TEXT,
  authorization_base_url TEXT,
  token_url TEXT,
  redirect_url TEXT,
  password TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS oauth2_data (
  account_key TEXT PRIMARY KEY REFERENCES accounts(account_key) ON DELETE CASCADE,
  access_token TEXT,
  refresh_token TEXT NOT NULL,
  expires_at TEXT
);

CREATE TABLE IF NOT EXISTS mailboxes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_key TEXT NOT NULL REFERENCES accounts(account_key) ON DELETE CASCADE,
  uid_next INTEGER NOT NULL DEFAULT 1,
  uid_validity INTEGER NOT NULL DEFAULT (unixepoch('now')),
  name TEXT NOT NULL,
  hierarchy_delimiter TEXT NOT NULL DEFAULT "/",
  flags_s TEXT NOT NULL DEFAULT '\\\\',
  is_virtual INTEGER NOT NULL DEFAULT 0,
  is_remote INTEGER NOT NULL DEFAULT 0,
  last_synced_uid INTEGER NOT NULL DEFAULT 0,
  UNIQUE(account_key, name)
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uid INTEGER NOT NULL,
  mailbox_id INTEGER,
  received_date INTEGER NOT NULL,
  flags_s TEXT NOT NULL DEFAULT '\\\\',
  size INTEGER NOT NULL,
  data BLOB NOT NULL,
  remote_uid TEXT,
  UNIQUE(mailbox_id, uid),
  FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id ON messages(mailbox_id);
CREATE INDEX IF NOT EXISTS idx_messages_remote_uid ON messages(remote_uid);
"""

def _migrate(db: sqlite3.Connection):
  msg_cols = [typing.cast(str, r[1]) for r in typing.cast(list[sqlite3.Row], db.execute("PRAGMA table_info(messages)").fetchall())]
  if "is_deleted" not in msg_cols:
    _ = db.execute("ALTER TABLE messages ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0")
  mb_cols = [typing.cast(str, r[1]) for r in typing.cast(list[sqlite3.Row], db.execute("PRAGMA table_info(mailboxes)").fetchall())]
  if "is_deleted" not in mb_cols:
    _ = db.execute("ALTER TABLE mailboxes ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0")

def db_open(db_path: pathlib.Path) -> sqlite3.Connection:
  conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
  conn.row_factory = sqlite3.Row
  _ = conn.execute("PRAGMA foreign_keys=ON")

  with conn:
    _ = conn.executescript(_DB_INIT_SCRIPT)
    _migrate(conn)

  return conn

def fetchone(db: sqlite3.Connection, query: str, params: tuple[object, ...] = ()) -> sqlite3.Row | None:
  cursor: sqlite3.Cursor = db.execute(query, params)
  result: sqlite3.Row | None = typing.cast(sqlite3.Row | None, cursor.fetchone())
  return result

def fetchone_required(db: sqlite3.Connection, query: str, params: tuple[object, ...] = ()) -> sqlite3.Row:
  row = fetchone(db, query, params)
  if row is None:
    raise ValueError("query returned no rows")
  return row

def iter_rows(db: sqlite3.Connection, query: str, params: tuple[object, ...] = ()) -> Iterator[sqlite3.Row]:
  cursor: sqlite3.Cursor = db.execute(query, params)
  while True:
    row: sqlite3.Row | None = typing.cast(sqlite3.Row | None, cursor.fetchone())
    if row is None:
      break
    yield row

def _account_from_row(row: sqlite3.Row) -> Account:
  addresses_raw: object = json_loads_object(row_field(row, "addresses", str))
  if not is_object_list(addresses_raw):
    raise ValueError("addresses must be a JSON array")
  addresses: list[str] = []
  i = 0
  while i < len(addresses_raw):
    addr: object = addresses_raw[i]
    if not isinstance(addr, str):
      raise ValueError("addresses must contain only strings")
    addresses.append(addr)
    i += 1

  auth_type = row_field(row, "auth_type", str)
  if auth_type == "OAUTH2":
    auth: AuthenticationOAUTH2 | AuthenticationPLAIN = AuthenticationOAUTH2(
      scope=row_field(row, "scope", str),
      client_id=row_field(row, "client_id", str),
      client_secret=row_optional(row, "client_secret", str),
      authorization_base_url=row_field(row, "authorization_base_url", str),
      token_url=row_field(row, "token_url", str),
      redirect_url=row_field(row, "redirect_url", str),
    )
  elif auth_type == "PLAIN":
    auth = AuthenticationPLAIN(password=row_field(row, "password", str))
  else:
    raise ValueError(f"unknown auth_type '{auth_type}' for account '{row_field(row, 'account_key', str)}'")

  created_at_raw = row_optional(row, "created_at", str)
  if created_at_raw is None:
    created_at = None
  else:
    try:
      created_at = datetime.datetime.fromisoformat(created_at_raw)
    except ValueError:
      created_at = datetime.datetime.fromtimestamp(int(created_at_raw))

  return Account(
    addresses=tuple(addresses),
    imap_host=row_field(row, "imap_host", str),
    imap_port=row_field(row, "imap_port", int),
    imap_tlsmode=TLSMode(row_field(row, "imap_tlsmode", str)),
    smtp_host=row_field(row, "smtp_host", str),
    smtp_port=row_field(row, "smtp_port", int),
    smtp_tlsmode=TLSMode(row_field(row, "smtp_tlsmode", str)),
    auth=auth,
    created_at=created_at,
  )

def db_account_add(db: sqlite3.Connection, account: Account, initial_refresh_token: str | None = None):
  auth = account.auth
  if isinstance(auth, AuthenticationOAUTH2):
    auth_type, scope, client_id, client_secret = "OAUTH2", auth.scope, auth.client_id, auth.client_secret
    authorization_base_url, token_url, redirect_url = auth.authorization_base_url, auth.token_url, auth.redirect_url
    password = None
  else:
    auth_type = "PLAIN"
    scope = client_id = client_secret = None
    authorization_base_url = token_url = redirect_url = None
    password = auth.password

  if isinstance(auth, AuthenticationOAUTH2) and initial_refresh_token is None:
    raise ValueError("initial_refresh_token required for OAUTH2 account")

  with db:
    _ = db.execute("""INSERT INTO accounts
      (account_key, addresses, imap_host, imap_port, imap_tlsmode, smtp_host, smtp_port, smtp_tlsmode,
       auth_type, scope, client_id, client_secret, authorization_base_url, token_url, redirect_url, password)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
      (account.key, json.dumps(list(account.addresses)), account.imap_host, account.imap_port, account.imap_tlsmode.value,
       account.smtp_host, account.smtp_port, account.smtp_tlsmode.value, auth_type, scope, client_id, client_secret,
       authorization_base_url, token_url, redirect_url, password))

    if isinstance(auth, AuthenticationOAUTH2):
      _ = db.execute("INSERT INTO oauth2_data (account_key, access_token, refresh_token, expires_at) VALUES (?,?,?,?)",
        (account.key, None, initial_refresh_token, None))

def db_account_list(db: sqlite3.Connection) -> list[Account]:
  return [ _account_from_row(row) for row in iter_rows(db, "SELECT * FROM accounts ORDER BY created_at") ]

def db_account_get(db: sqlite3.Connection, account_key: str) -> Account | None:
  row = fetchone(db, "SELECT * FROM accounts WHERE account_key=?", (account_key,))
  return None if row is None else _account_from_row(row)

def db_account_get_by_address(db: sqlite3.Connection, address: str) -> Account | None:
  row = fetchone(db, "SELECT * FROM accounts WHERE EXISTS (SELECT 1 FROM json_each(addresses) WHERE value=?)", (address,))
  return None if row is None else _account_from_row(row)

def db_account_remove(db: sqlite3.Connection, account_key: str):
  with db:
    _ = db.execute("DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE account_key=?)", (account_key,))
    _ = db.execute("DELETE FROM mailboxes WHERE account_key=?", (account_key,))
    _ = db.execute("DELETE FROM oauth2_data WHERE account_key=?", (account_key,))
    _ = db.execute("DELETE FROM accounts WHERE account_key=?", (account_key,))

def _mailbox_from_row(row: sqlite3.Row) -> Mailbox:
  return Mailbox(
    id=row_field(row, "id", int),
    account_key=row_field(row, "account_key", str),
    uid_next=row_field(row, "uid_next", int),
    uid_validity=row_field(row, "uid_validity", int),
    name=row_field(row, "name", str),
    hierarchy_delimiter=row_field(row, "hierarchy_delimiter", str),
    flags_s=row_field(row, "flags_s", str),
    is_virtual=bool(row_field(row, "is_virtual", int)),
    is_remote=bool(row_field(row, "is_remote", int)),
    last_synced_uid=row_field(row, "last_synced_uid", int),
    is_deleted=bool(row_field(row, "is_deleted", int)),
  )

def db_mailbox_by_name(db: sqlite3.Connection, account_key: str, name: str) -> Mailbox | None:
  result = fetchone(db, "SELECT * FROM mailboxes WHERE account_key=? AND name=? AND is_deleted=0", (account_key, name))
  return None if result is None else _mailbox_from_row(result)

def db_mailbox_list(db: sqlite3.Connection, account_key: str):
  for item in iter_rows(db, "SELECT * FROM mailboxes WHERE account_key=? AND is_deleted=0 ORDER BY name", (account_key,)):
    yield _mailbox_from_row(item)

def db_mailbox_count_messages(db: sqlite3.Connection, mailbox_id: int) -> int:
  return row_field(fetchone_required(db, "SELECT COUNT(*) FROM messages WHERE mailbox_id=? AND is_deleted=0", (mailbox_id,)), "COUNT(*)", int)

def db_mailbox_uid_next(db: sqlite3.Connection, account_key: str, mailbox_id: int) -> int:
  return row_field(fetchone_required(db, "SELECT uid_next FROM mailboxes WHERE account_key=? AND id=?", (account_key, mailbox_id)), "uid_next", int)

def db_mailbox_uid_validity(db: sqlite3.Connection, account_key: str, mailbox_id: int) -> int:
  return row_field(fetchone_required(db, "SELECT uid_validity FROM mailboxes WHERE account_key=? AND id=?", (account_key, mailbox_id)), "uid_validity", int)

def db_mailbox_count_unseen(db: sqlite3.Connection, mailbox_id: int) -> int:
  return row_field(fetchone_required(db, "SELECT COUNT(*) FROM messages WHERE mailbox_id=? AND is_deleted=0 AND flags_s NOT LIKE '%\\Seen\\%'", (mailbox_id,)), "COUNT(*)", int)

def db_mailbox_count_deleted(db: sqlite3.Connection, mailbox_id: int) -> int:
  return row_field(fetchone_required(db, "SELECT COUNT(*) FROM messages WHERE mailbox_id=? AND is_deleted=0 AND flags_s LIKE '%\\Deleted\\%'", (mailbox_id,)), "COUNT(*)", int)

def db_mailbox_size(db: sqlite3.Connection, mailbox_id: int) -> int:
  return row_field(fetchone_required(db, "SELECT COALESCE(SUM(length(data)), 0) FROM messages WHERE mailbox_id=? AND is_deleted=0", (mailbox_id,)), "COALESCE(SUM(length(data)), 0)", int)

def db_mailbox_add(db: sqlite3.Connection, account_key: str, name: str, uid_validity: int, uid_next: int = 1, \
    flags_s: str = "\\\\", hierarchy_delimiter: str = "/", is_remote: bool = True, is_virtual: bool = False) -> int:
  cur = db.execute("INSERT INTO mailboxes (account_key, uid_next, uid_validity, name, hierarchy_delimiter, flags_s, is_virtual, is_remote, last_synced_uid) " +
    "VALUES (?,?,?,?,?,?,?,?,0) " +
    "ON CONFLICT(account_key, name) DO UPDATE SET is_deleted=0, uid_validity=excluded.uid_validity, uid_next=excluded.uid_next, " +
    "flags_s=excluded.flags_s, hierarchy_delimiter=excluded.hierarchy_delimiter, is_virtual=excluded.is_virtual, is_remote=excluded.is_remote " +
    "RETURNING id", (account_key, uid_next, uid_validity, name, hierarchy_delimiter, flags_s, 1 if is_virtual else 0, 1 if is_remote else 0))
  row = typing.cast(sqlite3.Row | None, cur.fetchone())
  assert row is not None
  row_id = row_field(row, "id", int)
  _ = db.execute("UPDATE messages SET is_deleted=0 WHERE mailbox_id=?", (row_id,))
  return row_id

def db_mailbox_update_sync(db: sqlite3.Connection, mailbox_id: int, *, uid_next: int | None = None, \
    uid_validity: int | None = None, last_synced_uid: int | None = None, flags_s: str | None = None):
  sets: list[str] = []
  params: list[int | str] = []
  if uid_next is not None: sets.append("uid_next=?"); params.append(uid_next)
  if uid_validity is not None: sets.append("uid_validity=?"); params.append(uid_validity)
  if last_synced_uid is not None: sets.append("last_synced_uid=?"); params.append(last_synced_uid)
  if flags_s is not None: sets.append("flags_s=?"); params.append(flags_s)
  if sets:
    params.append(mailbox_id)
    _ = db.execute("UPDATE mailboxes SET %s WHERE id=?" % (", ".join(sets),), params)

def db_messages_clear(db: sqlite3.Connection, mailbox_id: int):
  _ = db.execute("UPDATE messages SET is_deleted=1 WHERE mailbox_id=?", (mailbox_id,))

def db_message_add(db: sqlite3.Connection, uid: int, mailbox_id: int, received_date: int, flags_s: str, size: int, data: bytes, remote_uid: str | None):
  _ = db.execute("INSERT INTO messages (uid, mailbox_id, received_date, flags_s, size, data, remote_uid) VALUES (?,?,?,?,?,?,?) " +
    "ON CONFLICT(mailbox_id, uid) DO UPDATE SET received_date=excluded.received_date, flags_s=excluded.flags_s, size=excluded.size, data=excluded.data, remote_uid=excluded.remote_uid, is_deleted=0",
    (uid, mailbox_id, received_date, flags_s, size, data, remote_uid))

def _message_from_row(row: sqlite3.Row) -> Message:
  return Message(
    uid=row_field(row, "uid", int),
    mailbox_id=row_field(row, "mailbox_id", int),
    received_date=row_field(row, "received_date", int),
    flags_s=row_field(row, "flags_s", str),
    size=row_field(row, "size", int),
    data=row_field(row, "data", bytes),
    remote_uid=row_optional(row, "remote_uid", str),
    is_deleted=bool(row_field(row, "is_deleted", int)),
  )

def db_message_list(db: sqlite3.Connection, mailbox_id: int):
  for row in iter_rows(db, "SELECT * FROM messages WHERE mailbox_id=? AND is_deleted=0 ORDER BY uid", (mailbox_id,)):
    yield _message_from_row(row)

def db_message_get_by_uid(db: sqlite3.Connection, mailbox_id: int, uid: int) -> Message | None:
  result = fetchone(db, "SELECT * FROM messages WHERE mailbox_id=? AND uid=? AND is_deleted=0", (mailbox_id, uid))
  return None if result is None else _message_from_row(result)

def db_mailbox_max_uid(db: sqlite3.Connection, mailbox_id: int) -> int:
  row = fetchone_required(db, "SELECT MAX(uid) FROM messages WHERE mailbox_id=?", (mailbox_id,))
  value = row_optional(row, "MAX(uid)", int)
  return value if value is not None else 0

def db_message_update_flags(db: sqlite3.Connection, mailbox_id: int, uid: int, flags_s: str):
  _ = db.execute("UPDATE messages SET flags_s=?, is_deleted=0 WHERE mailbox_id=? AND uid=? AND remote_uid IS NOT NULL", (flags_s, mailbox_id, uid))

def db_message_delete_by_uid(db: sqlite3.Connection, mailbox_id: int, uid: int):
  _ = db.execute("UPDATE messages SET is_deleted=1, remote_uid=NULL WHERE mailbox_id=? AND uid=?", (mailbox_id, uid))

def db_message_delete_except(db: sqlite3.Connection, mailbox_id: int, uids: set[int], max_uid: int) -> int:
  if not uids:
    cursor = db.execute("UPDATE messages SET is_deleted=1 WHERE mailbox_id=? AND is_deleted=0 AND uid<=? AND remote_uid IS NOT NULL", (mailbox_id, max_uid))
    return cursor.rowcount
  placeholders = ",".join("?" for _ in uids)
  params = [mailbox_id, max_uid] + list(uids)
  cursor = db.execute(f"UPDATE messages SET is_deleted=1 WHERE mailbox_id=? AND is_deleted=0 AND uid<=? AND remote_uid IS NOT NULL AND uid NOT IN ({placeholders})", params)
  return cursor.rowcount

def db_mailbox_delete(db: sqlite3.Connection, mailbox_id: int):
  with db:
    _ = db.execute("UPDATE messages SET is_deleted=1 WHERE mailbox_id=?", (mailbox_id,))
    _ = db.execute("UPDATE mailboxes SET is_deleted=1 WHERE id=?", (mailbox_id,))

def db_mailbox_rename(db: sqlite3.Connection, mailbox_id: int, new_name: str):
  _ = db.execute("UPDATE mailboxes SET name=? WHERE id=?", (new_name, mailbox_id))

def db_mailbox_get_by_id(db: sqlite3.Connection, mailbox_id: int) -> Mailbox | None:
  result = fetchone(db, "SELECT * FROM mailboxes WHERE id=? AND is_deleted=0", (mailbox_id,))
  return None if result is None else _mailbox_from_row(result)

def db_message_count(db: sqlite3.Connection, mailbox_id: int) -> int:
  return row_field(fetchone_required(db, "SELECT COUNT(*) FROM messages WHERE mailbox_id=? AND is_deleted=0", (mailbox_id,)), "COUNT(*)", int)

def db_messages_for_account(db: sqlite3.Connection, account_key: str, flags_filter: str | None = None, flags_exclude: str | None = None) -> list[Message]:
  query = "SELECT messages.* FROM messages JOIN mailboxes ON messages.mailbox_id=mailboxes.id WHERE mailboxes.account_key=? AND mailboxes.is_virtual=0 AND messages.is_deleted=0"
  params: list[object] = [account_key]
  if flags_filter is not None:
    query += " AND messages.flags_s LIKE ?"
    params.append(f"%{flags_filter}%")
  if flags_exclude is not None:
    query += " AND messages.flags_s NOT LIKE ?"
    params.append(f"%{flags_exclude}%")
  query += " ORDER BY messages.received_date DESC"
  return [_message_from_row(row) for row in iter_rows(db, query, tuple(params))]
