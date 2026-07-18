import asyncio, base64, datetime, logging, ssl
from dataclasses import dataclass
from typing import TypeGuard, cast
from mailproxy.auth import account_get_oauth_access_token
from mailproxy.db import db_message_add, db_message_delete_except, db_message_update_flags, db_mailbox_add, db_mailbox_by_name, db_mailbox_update_sync, db_messages_clear, db_open
from mailproxy.imap_parsing import IMAPCommandFailedError, IMAPReadError, IMAPReader, flags_to_s, format_internal_date, imap_to_quoted_string, parse_internal_date
from mailproxy.model import Account, AuthenticationOAUTH2, Config, TLSMode
from mailproxy.utils import encode_7bit_mailbox_name


def _is_fetch_items(value: object) -> TypeGuard[dict[bytes, object]]:
  return isinstance(value, dict)

def _is_bytes_list(value: object) -> TypeGuard[list[bytes]]:
  if not isinstance(value, list):
    return False
  return all(isinstance(v, bytes) for v in cast(list[object], value))

@dataclass(frozen=True)
class SelectResult:
  uid_validity: int
  uid_next: int
  exists: int
  flags_s: str
  read_only: bool

@dataclass
class ImapResponse:
  kind: bytes
  args: list[object]

class IMAPRemoteConnection:
  _tls_context: ssl.SSLContext = ssl.create_default_context()

  def __init__(self, config: Config, account: Account, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    self.account: Account = account
    self.config: Config = config
    self._imap: IMAPReader = IMAPReader(reader)
    self._writer: asyncio.StreamWriter = writer
    self._command_counter: int = 0
    self._use_ascii_mailbox_encoding: bool = True
    self._capabilities: list[bytes] = []

  async def shutdown(self):
    logging.debug("IMAP: shutting down remote connection")
    try:
      self._start_command(b"LOGOUT")
      await self._read_until_response()
    except Exception: pass
    finally:
      try: self._writer.close()
      except Exception: pass

  async def sync_mailbox(self, mailbox_name: str):
    logging.debug("sync_mailbox: '%s'", mailbox_name)
    select_result = await self._command_select(mailbox_name)
    uid_validity = select_result.uid_validity
    uid_next = select_result.uid_next
    flags_s = select_result.flags_s
    logging.debug("sync_mailbox: '%s' uid_validity=%d uid_next=%d exists=%d", mailbox_name, uid_validity, uid_next, select_result.exists)

    with db_open(self.config.db_path) as db:
      mailbox = db_mailbox_by_name(db, self.account.key, mailbox_name)
      if mailbox is None:
        mailbox_id = db_mailbox_add(db, self.account.key, mailbox_name, uid_validity, uid_next, flags_s)
        last_synced = 0
      else:
        mailbox_id = mailbox.id
        last_synced = mailbox.last_synced_uid
        if uid_validity != 0 and mailbox.uid_validity != uid_validity:
          db_messages_clear(db, mailbox.id)
          db_mailbox_update_sync(db, mailbox.id, uid_validity=uid_validity, uid_next=uid_next, last_synced_uid=0, flags_s=flags_s)
          last_synced = 0
        else:
          db_mailbox_update_sync(db, mailbox.id, uid_next=uid_next, flags_s=flags_s)

    if uid_next > last_synced + 1:
      self._start_command(b"UID FETCH %d:* (UID FLAGS INTERNALDATE RFC822.SIZE BODY[])" % (last_synced + 1,))
      max_uid = 0
      count = 0
      with db_open(self.config.db_path) as db:
        async for resp in self._read_responses():
          if resp.kind != b"FETCH": continue
          items = resp.args[1]
          if not _is_fetch_items(items): continue
          uid = items.get(b"UID")
          if not isinstance(uid, int): continue
          uid_int = uid
          if uid_int <= last_synced:
            logging.debug("sync_mailbox: '%s' skipping uid %d (<= last_synced %d)", mailbox_name, uid_int, last_synced)
            continue
          flags = items.get(b"FLAGS", b"")
          internal_date = items.get(b"INTERNALDATE", b"")
          size = items.get(b"RFC822.SIZE", 0)
          body = items.get(b"BODY[]", b"")
          msg_flags_s = flags_to_s(flags) if isinstance(flags, bytes) else "\\\\"
          received_date = parse_internal_date(internal_date) if isinstance(internal_date, bytes) and internal_date else int(datetime.datetime.now().timestamp())
          db_message_add(db, uid_int, mailbox_id, received_date, msg_flags_s, int(size) if isinstance(size, int) else 0, bytes(body) if isinstance(body, (bytes, bytearray)) else b"", str(uid_int))
          db.commit()
          if uid_int > max_uid: max_uid = uid_int
          count += 1
        if count > 0:
          db_mailbox_update_sync(db, mailbox_id, last_synced_uid=max_uid)
          db.commit()
      if count > 0:
        logging.debug("sync_mailbox: '%s' fetched %d new messages (up to uid %d)", mailbox_name, count, max_uid)
      else:
        logging.debug("sync_mailbox: '%s' no new messages", mailbox_name)

    if last_synced > 0:
      self._start_command(b"UID FETCH 1:%d (UID FLAGS)" % (last_synced,))
      flag_updates: list[tuple[int, str]] = []
      seen_uids: set[int] = set()
      async for resp in self._read_responses():
        if resp.kind != b"FETCH": continue
        items = resp.args[1]
        if not _is_fetch_items(items): continue
        uid = items.get(b"UID")
        if not isinstance(uid, int): continue
        uid_int = uid
        seen_uids.add(uid_int)
        flags = items.get(b"FLAGS", b"")
        msg_flags_s = flags_to_s(flags) if isinstance(flags, bytes) else "\\\\"
        flag_updates.append((uid_int, msg_flags_s))

      with db_open(self.config.db_path) as db:
        if flag_updates:
          for uid, f_s in flag_updates:
            db_message_update_flags(db, mailbox_id, uid, f_s, restore=True)
          logging.debug("sync_mailbox: '%s' updated flags for %d messages", mailbox_name, len(flag_updates))
        deleted_count = db_message_delete_except(db, mailbox_id, seen_uids, last_synced)
        if deleted_count > 0:
          logging.debug("sync_mailbox: '%s' soft-deleted %d messages (removed on remote)", mailbox_name, deleted_count)

  async def sync_mailbox_list(self):
    logging.debug("sync_mailbox_list: listing remote mailboxes")
    self._start_command(b"LIST \"\" \"*\"")
    remote_mailboxes: list[tuple[bytes, bytes, bytes]] = []
    async for resp in self._read_responses():
      if resp.kind != b"LIST": continue
      flags_raw = resp.args[0]
      delim = resp.args[1]
      name = resp.args[2]
      if isinstance(flags_raw, bytes) and isinstance(delim, bytes) and isinstance(name, bytes):
        remote_mailboxes.append((flags_raw, delim, name))

    with db_open(self.config.db_path) as db:
      added = 0
      for flags, delim, name_b in remote_mailboxes:
        name_s = name_b.decode("utf-8")
        if db_mailbox_by_name(db, self.account.key, name_s) is None:
          _ = db_mailbox_add(db, self.account.key, name_s, 0, 1, flags_to_s(flags), delim.decode("ascii") if delim else "/")
          added += 1
    logging.debug("sync_mailbox_list: %d remote mailboxes, %d new", len(remote_mailboxes), added)

  async def uid_store(self, uid: int, op: bytes, flags_s: str):
    flags_b = b" ".join(b"\\" + f.encode("ascii") for f in flags_s.strip("\\").split("\\") if f) if flags_s != "\\" else b""
    self._start_command(b"UID STORE %d %s (%s)" % (uid, op, flags_b))
    await self._read_until_response()

  async def uid_append(self, mailbox_name: str, flags_s: str, internal_date: int | None, data: bytes):
    flags_b = b"" if flags_s == "\\" else b" (" + b" ".join(b"\\" + f.encode("ascii") for f in flags_s.strip("\\").split("\\") if f) + b")"
    date_b = b" \"" + format_internal_date(internal_date) + b"\"" if internal_date is not None else b""
    self._start_command(b"APPEND %s%s%s {%d}" % (self._encode_mailbox(mailbox_name), flags_b, date_b, len(data)))
    if await self._imap.peek(1) != b"+":
      await self._read_until_response()
      raise IMAPCommandFailedError("remote did not accept APPEND literal")
    await self._imap.read_const(b"+")
    _ = await self._imap.read_text_line()
    self._writer.write(data)
    self._writer.write(b"\r\n")
    await self._read_until_response()

  async def create_mailbox(self, mailbox_name: str):
    self._start_command(b"CREATE %s" % (self._encode_mailbox(mailbox_name),))
    await self._read_until_response()
    await self.sync_mailbox_list()

  async def delete_mailbox(self, mailbox_name: str):
    self._start_command(b"DELETE %s" % (self._encode_mailbox(mailbox_name),))
    await self._read_until_response()

  async def rename_mailbox(self, old_name: str, new_name: str):
    self._start_command(b"RENAME %s %s" % (self._encode_mailbox(old_name), self._encode_mailbox(new_name)))
    await self._read_until_response()
    await self.sync_mailbox_list()

  async def uid_expunge(self, uids: list[int]):
    if uids:
      self._start_command(b"UID EXPUNGE %s" % (b",".join(b"%d" % (u,) for u in uids),))
      await self._read_until_response()

  async def uid_copy(self, uids: list[int], dest_mailbox: str):
    self._start_command(b"UID COPY %s %s" % (b",".join(b"%d" % (u,) for u in uids), self._encode_mailbox(dest_mailbox)))
    await self._read_until_response()

  async def wait_for_update(self, mailbox_name: str, update_event: asyncio.Event):
    logging.debug("wait_for_update: '%s' entering IDLE", mailbox_name)
    try:
      _ = await self._command_select(mailbox_name)
      self._start_command(b"IDLE")
      if await self._imap.peek(1) != b"+":
        raise RuntimeError("server didnt respond with + in idle!")
      await self._imap.read_const(b"+")
      _ = await self._imap.read_text_line()
      while True:
        tag = await self._imap.read_tag()
        await self._imap.skip_sp()
        if tag != b"*":
          raise IMAPReadError(f"unexpected tag during IDLE: {tag!r}")
        resp = await self._read_untagged()
        if resp.kind in (b"EXISTS", b"EXPUNGE", b"FETCH"):
          logging.debug("wait_for_update: '%s' got %s", mailbox_name, resp.kind)
          update_event.set()
    finally:
      self._writer.write(b"DONE\r\n")
      await self._read_until_response()
      logging.debug("wait_for_update: '%s' IDLE done", mailbox_name)

  async def _init(self):
    logging.debug("IMAP init: " + (await self._imap.read_text_line()).decode())
    self._capabilities = await self._command_capabilities()
    logging.debug("IMAP capabilities: %s", b" ".join(self._capabilities).decode(errors="replace"))
    if self.account.imap_tlsmode == TLSMode.STARTTLS:
      if b"STARTTLS" not in self._capabilities:
        raise IMAPCommandFailedError("STARTTLS required by account but not supported by remote!")
      logging.debug("IMAP: upgrading to TLS (STARTTLS)")
      await self._command_starttls()
      self._capabilities = await self._command_capabilities()

    enable_imap4_rev2 = b"IMAP4rev2" in self._capabilities
    self._use_ascii_mailbox_encoding = not enable_imap4_rev2
    if enable_imap4_rev2:
      logging.debug("IMAP: enabling IMAP4rev2")
      self._start_command(b"ENABLE IMAP4rev2")
      await self._read_until_response()

    if isinstance(self.account.auth, AuthenticationOAUTH2):
      logging.debug("IMAP: authenticating as OAUTH2 (XOAUTH2)")
      with db_open(self.config.db_path) as db:
        access_token = account_get_oauth_access_token(db, self.account)
      await self._command_authenticate(b"XOAUTH2", f"user={self.account.addresses[0]}\1auth=Bearer {access_token}\1\1".encode())
    else:
      logging.debug("IMAP: authenticating as PLAIN (LOGIN)")
      await self._command_login_backend(self.account.addresses[0], self.account.auth.password)

    logging.debug("IMAP: authenticated, syncing mailbox list")
    await self.sync_mailbox_list()
    logging.debug("IMAP: init complete")

  async def _command_select(self, mailbox_name: str) -> SelectResult:
    self._start_command(b"SELECT %s" % (self._encode_mailbox(mailbox_name),))
    uid_validity, uid_next, exists, flags_s, read_only = 0, 0, 0, "\\", False
    async for resp in self._read_responses():
      if resp.kind == b"OK":
        code = resp.args[0]
        if code is not None and isinstance(code, bytes):
          if code.startswith(b"UIDVALIDITY"):
            uid_validity = int(code.split(b" ")[1])
          elif code.startswith(b"UIDNEXT"):
            uid_next = int(code.split(b" ")[1])
          elif code == b"READ-ONLY":
            read_only = True
      elif resp.kind == b"EXISTS":
        n = resp.args[0]
        if isinstance(n, int): exists = n
      elif resp.kind == b"FLAGS":
        flags_raw = resp.args[0]
        if isinstance(flags_raw, bytes): flags_s = flags_to_s(flags_raw)
    return SelectResult(uid_validity=uid_validity, uid_next=uid_next, exists=exists, flags_s=flags_s, read_only=read_only)

  async def _command_authenticate(self, auth_type: bytes, auth_data: bytes):
    if (b"AUTH=%s" % (auth_type,)) not in self._capabilities:
      raise IMAPCommandFailedError(f"Auth type '{auth_type.decode()}' not supported!")
    self._start_command(b"AUTHENTICATE %s" % (auth_type,))
    if await self._imap.peek(1) != b"+":
      await self._read_until_response()
      raise IMAPCommandFailedError("Invalid response from server!")
    await self._imap.read_const(b"+")
    _ = await self._imap.read_text_line()
    self._writer.write(base64.b64encode(auth_data))
    self._writer.write(b"\r\n")
    await self._read_until_response()

  async def _command_login_backend(self, userid: str, password: str):
    self._start_command(b"LOGIN %s %s" % (imap_to_quoted_string(userid.encode()), imap_to_quoted_string(password.encode())))
    await self._read_until_response()

  async def _command_capabilities(self):
    self._start_command(b"CAPABILITY")
    capabilities: list[bytes] = []
    async for resp in self._read_responses():
      if resp.kind == b"CAPABILITY":
        caps = resp.args[0]
        if _is_bytes_list(caps):
          capabilities.extend(caps)
    return capabilities

  async def _command_starttls(self):
    self._start_command(b"STARTTLS")
    await self._read_until_response()
    await self._writer.start_tls(IMAPRemoteConnection._tls_context)

  def _start_command(self, command: bytes):
    self._command_counter += 1
    self._writer.write(b"A%d %s\r\n" % (self._command_counter, command))

  def _encode_mailbox(self, s: str) -> bytes:
    if self._use_ascii_mailbox_encoding and not s.isascii():
      return imap_to_quoted_string(encode_7bit_mailbox_name(s).encode("ascii"))
    return imap_to_quoted_string(s.encode("utf-8"))

  async def _read_until_response(self):
    async for _ in self._read_responses(): pass

  async def _read_responses(self):
    """Yield ImapResponse for untagged responses until the tagged completion."""
    expected = b"A%d" % (self._command_counter,)
    while True:
      tag = await self._imap.read_tag()
      await self._imap.skip_sp()
      if tag == b"*":
        yield await self._read_untagged()
      elif tag == expected:
        state = (await self._imap.read_atom()).upper()
        _code, text = await self._read_resp_text()
        if state != b"OK":
          raise IMAPCommandFailedError(f"remote command failed: {state.decode()} {text.decode()}")
        return
      else:
        raise IMAPReadError(f"unexpected tag {tag!r}, expected {expected!r}")

  async def _read_untagged(self) -> ImapResponse:
    """Read one untagged response (after '* SP' consumed)."""
    first = await self._imap.peek(1)
    if first and first[0:1].isdigit():
      n = await self._imap.read_number()
      await self._imap.skip_sp()
      kind = (await self._imap.read_atom()).upper()
      if kind == b"FETCH":
        await self._imap.skip_wsp()
        items = await self._read_fetch_items()
        await self._imap.read_crlf()
        return ImapResponse(b"FETCH", [n, items])
      await self._imap.read_crlf()
      return ImapResponse(kind, [n])
    kind = (await self._imap.read_atom()).upper()
    if kind in (b"OK", b"BYE"):
      code, text = await self._read_resp_text()
      return ImapResponse(kind, [code, text])
    if kind == b"FLAGS":
      await self._imap.skip_wsp()
      await self._imap.read_const(b"(")
      flags_raw = await self._imap.read_until(b")")
      await self._imap.read_crlf()
      return ImapResponse(b"FLAGS", [flags_raw.strip()])
    if kind == b"LIST":
      await self._imap.skip_wsp()
      await self._imap.read_const(b"(")
      flags_raw = await self._imap.read_until(b")")
      await self._imap.skip_wsp()
      delim = await self._imap.read_nstring()
      await self._imap.skip_wsp()
      name = await self._imap.read_astring()
      await self._imap.read_crlf()
      return ImapResponse(b"LIST", [flags_raw.strip(), delim or b"/", name])
    if kind == b"CAPABILITY":
      await self._imap.skip_wsp()
      caps_line = await self._imap.read_text_line()
      return ImapResponse(b"CAPABILITY", [[c for c in caps_line.split(b" ") if c]])
    text = await self._imap.read_text_line()
    return ImapResponse(kind, [text])

  async def _read_fetch_items(self) -> dict[bytes, object]:
    await self._imap.read_const(b"(")
    result: dict[bytes, object] = {}
    while True:
      c = await self._imap.peek(1)
      if c == b")" or not c:
        break
      await self._imap.skip_wsp()
      c = await self._imap.peek(1)
      if c == b")" or not c:
        break
      key = (await self._imap.read_token()).upper()
      await self._imap.skip_sp()
      if key == b"UID":
        result[b"UID"] = await self._imap.read_number()
      elif key == b"FLAGS":
        await self._imap.read_const(b"(")
        flags_raw = await self._imap.read_until(b")")
        result[b"FLAGS"] = flags_raw.strip()
      elif key == b"INTERNALDATE":
        result[b"INTERNALDATE"] = await self._imap.read_quoted()
      elif key == b"RFC822.SIZE":
        result[b"RFC822.SIZE"] = await self._imap.read_number()
      elif key.startswith(b"BODY") or key.startswith(b"RFC822"):
        c2 = await self._imap.peek(1)
        if c2 == b"{":
          result[b"BODY[]"] = await self._imap.read_literal()
        elif c2 == b'"':
          result[b"BODY[]"] = await self._imap.read_quoted()
        elif c2[:1].upper() == b"N":
          _ = await self._imap.read_atom()
        else:
          result[b"BODY[]"] = await self._imap.read_token()
      else:
        _ = await self._imap.read_token()
    await self._imap.read_const(b")")
    return result

  async def _read_resp_text(self) -> tuple[bytes | None, bytes]:
    """Read [code] text after OK/NO/BAD/BYE. Return (code, text)."""
    if await self._imap.peek(1) == b" ":
      await self._imap.skip_sp()
    code = None
    if await self._imap.peek(1) == b"[":
      await self._imap.read_const(b"[")
      code = await self._imap.read_until(b"]")
      if await self._imap.peek(1) == b" ":
        await self._imap.skip_sp()
    text = await self._imap.read_text_line()
    return code, text

  @staticmethod
  async def open(config: Config, account: Account):
    ssl_param = ssl.create_default_context() if account.imap_tlsmode == TLSMode.DIRECT else None
    logging.debug("IMAP: connecting to %s:%d (tls=%s)", account.imap_host, account.imap_port, account.imap_tlsmode)
    reader, writer = await asyncio.open_connection(account.imap_host, account.imap_port, ssl=ssl_param)
    connection = IMAPRemoteConnection(config, account, reader, writer)
    await connection._init()
    return connection
