import asyncio, base64, contextlib, datetime, logging, ssl
from dataclasses import dataclass
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable
from typing import TypeGuard, cast
from mailproxy.auth import account_get_oauth_access_token
from mailproxy.db import DatabaseSession
from mailproxy.imap_parsing import IMAPCommandFailedError, IMAPConnectionLostError, IMAPReadError, IMAPReader, flags_to_b, flags_to_s, format_internal_date, imap_to_quoted_string, parse_internal_date
from mailproxy.model import Account, AuthenticationOAUTH2, Config, TLSMode
from mailproxy.utils import KeyedLock, encode_7bit_mailbox_name


def _is_fetch_items(value: object) -> TypeGuard[dict[bytes, object]]:
  return isinstance(value, dict)

def _is_bytes_list(value: object) -> TypeGuard[list[bytes]]:
  if not isinstance(value, list):
    return False
  return all(isinstance(v, bytes) for v in cast(list[object], value))

FETCH_BATCH_SIZE = 500

_sync_locks: KeyedLock[tuple[str, str]] = KeyedLock()
_mailbox_list_locks: KeyedLock[str] = KeyedLock()

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

@dataclass
class _MessageRecord:
  uid: int
  flags_s: str
  internal_date: bytes
  body: bytes

@dataclass
class _FlagRecord:
  uid: int
  flags_s: str

@dataclass
class _SyncState:
  mailbox_id: int
  last_synced_uid: int
  uid_next: int

@dataclass
class CommandResult:
  untagged: list[ImapResponse]
  state: bytes
  code: bytes | None
  text: bytes

class CommandContext:
  def __init__(self, imap: IMAPReader, read_untagged: Callable[[], Awaitable[ImapResponse]],
      read_resp_text: Callable[[], Awaitable[tuple[bytes | None, bytes]]], tag: bytes) -> None:
    self._imap: IMAPReader = imap
    self._read_untagged_response: Callable[[], Awaitable[ImapResponse]] = read_untagged
    self._read_resp_text_response: Callable[[], Awaitable[tuple[bytes | None, bytes]]] = read_resp_text
    self._tag: bytes = tag
    self._finished: bool = False
    self.state: bytes | None = None
    self.code: bytes | None = None
    self.text: bytes = b""

  @property
  def finished(self) -> bool:
    return self._finished

  async def responses(self) -> AsyncIterator[ImapResponse]:
    while not self._finished:
      tag = await self._imap.read_tag()
      await self._imap.skip_sp()
      if tag == b"*":
        yield await self._read_untagged_response()
      elif tag == self._tag:
        await self._read_completion()
        return
      else:
        raise IMAPReadError(f"unexpected tag {tag!r}, expected {self._tag!r}")

  async def read_continuation(self) -> None:
    if await self._imap.peek(1) != b"+":
      await self.wait_completion()
      raise IMAPCommandFailedError("expected continuation response")
    await self._imap.read_const(b"+")
    _ = await self._imap.read_text_line()

  async def wait_completion(self) -> None:
    if not self._finished:
      async for _ in self.responses(): pass
    if self.state != b"OK":
      raise IMAPCommandFailedError(
        f"remote command failed: {(self.state or b'').decode(errors='replace')} {self.text.decode(errors='replace')}")

  async def _read_completion(self) -> None:
    self.state = (await self._imap.read_atom()).upper()
    self.code, self.text = await self._read_resp_text_response()
    self._finished = True

class IdleSession:
  def __init__(self, ctx: CommandContext, writer: asyncio.StreamWriter) -> None:
    self._ctx: CommandContext = ctx
    self._writer: asyncio.StreamWriter = writer
    self._done_sent: bool = False
    self.finished: bool = False

  def request_exit(self) -> None:
    if not self._done_sent and not self._ctx.finished:
      self._done_sent = True
      try:
        self._writer.write(b"DONE\r\n")
      except Exception:
        pass

  async def wait(self) -> bool:
    async for resp in self._ctx.responses():
      if resp.kind in (b"EXISTS", b"EXPUNGE", b"FETCH"):
        return True
    self.finished = True
    return False

  async def close(self) -> None:
    if not self._ctx.finished:
      self.request_exit()
      await self._ctx.wait_completion()
    self.finished = True

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
    self._command_lock: asyncio.Lock = asyncio.Lock()
    self._broken: bool = False
    self._closed: bool = False

  @property
  def broken(self) -> bool:
    return self._broken or self._closed

  def _ensure_usable(self) -> None:
    if self._broken:
      raise IMAPConnectionLostError("remote connection was lost")
    if self._closed:
      raise IMAPConnectionLostError("remote connection is closed")

  def _invalidate(self) -> None:
    if self._broken:
      return
    self._broken = True
    try:
      self._writer.close()
    except Exception:
      pass

  @contextlib.asynccontextmanager
  async def command(self, command: bytes) -> AsyncGenerator[CommandContext, None]:
    async with self._command_lock:
      self._ensure_usable()
      tag = self._start_command(command)
      ctx = CommandContext(self._imap, self._read_untagged, self._read_resp_text, tag)
      try:
        yield ctx
        await ctx.wait_completion()
      except IMAPCommandFailedError:
        raise
      except BaseException as e:
        if not ctx.finished:
          self._invalidate()
        if isinstance(e, (IMAPReadError, asyncio.IncompleteReadError, ConnectionError, OSError)):
          if isinstance(e, IMAPConnectionLostError):
            raise
          raise IMAPConnectionLostError(str(e)) from e
        raise

  async def execute(self, command: bytes) -> CommandResult:
    async with self.command(command) as ctx:
      untagged = [resp async for resp in ctx.responses()]
      state, code, text = ctx.state, ctx.code, ctx.text
    assert state is not None
    return CommandResult(untagged=untagged, state=state, code=code, text=text)

  @contextlib.asynccontextmanager
  async def idle(self, mailbox_name: str) -> AsyncGenerator[IdleSession, None]:
    _ = await self._command_select(mailbox_name)
    async with self.command(b"IDLE") as ctx:
      await ctx.read_continuation()
      session = IdleSession(ctx, self._writer)
      try:
        yield session
      finally:
        await session.close()

  async def shutdown(self):
    logging.debug("IMAP: shutting down remote connection")
    if not self.broken:
      try:
        async with self.command(b"LOGOUT"):
          pass
      except Exception:
        pass
    self._closed = True
    try:
      self._writer.close()
    except Exception:
      pass

  async def sync_mailbox(self, mailbox_name: str) -> None:
    async with _sync_locks.acquire((self.account.key, mailbox_name)):
      logging.debug("sync_mailbox: '%s'", mailbox_name)
      select_result = await self._command_select(mailbox_name)
      state = await self._apply_mailbox_state(mailbox_name, select_result)
      await self._fetch_new_messages(mailbox_name, state)
      if state.last_synced_uid > 0:
        await self._sync_flag_changes_and_deletions(mailbox_name, state.mailbox_id, state.last_synced_uid)

  async def _apply_mailbox_state(self, mailbox_name: str, select_result: SelectResult) -> _SyncState:
    uid_validity = select_result.uid_validity
    uid_next = select_result.uid_next
    flags_s = select_result.flags_s
    logging.debug("sync_mailbox: '%s' uid_validity=%d uid_next=%d exists=%d", mailbox_name, uid_validity, uid_next, select_result.exists)
    with DatabaseSession(self.config) as db:
      mailbox = db.mailbox_by_name(self.account.key, mailbox_name)
      if mailbox is None:
        mailbox_id = db.mailbox_add(self.account.key, mailbox_name, uid_validity, uid_next, flags_s)
        last_synced = 0
      else:
        mailbox_id = mailbox.id
        last_synced = mailbox.last_synced_uid
        if uid_validity != 0 and mailbox.uid_validity != uid_validity:
          db.messages_clear(mailbox.id)
          db.mailbox_update_sync(mailbox.id, uid_validity=uid_validity, uid_next=uid_next, last_synced_uid=0, flags_s=flags_s)
          last_synced = 0
        else:
          db.mailbox_update_sync(mailbox.id, uid_next=uid_next, flags_s=flags_s)
    return _SyncState(mailbox_id=mailbox_id, last_synced_uid=last_synced, uid_next=uid_next)

  async def _search_uids(self, min_uid: int) -> set[int]:
    uids: set[int] = set()
    async with self.command(b"UID SEARCH UID %d:*" % (min_uid,)) as ctx:
      async for resp in ctx.responses():
        if resp.kind != b"SEARCH":
          continue
        text = resp.args[0]
        if isinstance(text, bytes):
          for tok in text.split():
            try:
              uids.add(int(tok))
            except ValueError:
              pass
    return uids

  async def _fetch_new_messages(self, mailbox_name: str, state: _SyncState) -> None:
    existing = await self._search_uids(state.last_synced_uid + 1)
    new_uids = sorted(existing)
    if not new_uids:
      return
    with DatabaseSession(self.config) as db:
      for i in range(0, len(new_uids), FETCH_BATCH_SIZE):
        batch = new_uids[i:i + FETCH_BATCH_SIZE]
        batch_uids = set(batch)
        uid_list = b",".join(b"%d" % (u,) for u in batch)
        count = 0
        async with self.command(b"UID FETCH %s (UID FLAGS INTERNALDATE BODY.PEEK[])" % (uid_list,)) as ctx:
          async for rec in self._iter_message_records(ctx, uids=batch_uids):
            received_date = parse_internal_date(rec.internal_date) if rec.internal_date else int(datetime.datetime.now().timestamp())
            db.message_add(rec.uid, state.mailbox_id, received_date, rec.flags_s, rec.body, str(rec.uid))
            db.mailbox_update_sync(state.mailbox_id, last_synced_uid=rec.uid)
            db.conn.commit()
            count += 1
        logging.debug("sync_mailbox: '%s' batch %s done (%d messages, %d remaining)",
          mailbox_name, uid_list.decode(), count, len(new_uids) - (i + len(batch)))

  async def _sync_flag_changes_and_deletions(self, mailbox_name: str, mailbox_id: int, last_synced_uid: int) -> None:
    flag_updates: list[tuple[int, str]] = []
    seen_uids: set[int] = set()
    async with self.command(b"UID FETCH 1:%d (UID FLAGS)" % (last_synced_uid,)) as ctx:
      async for rec in self._iter_flag_records(ctx):
        seen_uids.add(rec.uid)
        flag_updates.append((rec.uid, rec.flags_s))
    with DatabaseSession(self.config) as db:
      if flag_updates:
        changed = db.messages_merge_flags(mailbox_id, flag_updates)
        logging.debug("sync_mailbox: '%s' updated flags for %d messages", mailbox_name, changed)
      deleted_count = db.message_delete_except(mailbox_id, seen_uids, last_synced_uid)
      if deleted_count > 0:
        logging.debug("sync_mailbox: '%s' soft-deleted %d messages (removed on remote)", mailbox_name, deleted_count)

  async def _iter_message_records(self, ctx: CommandContext, uids: set[int] | None = None) -> AsyncIterator[_MessageRecord]:
    async for resp in ctx.responses():
      if resp.kind != b"FETCH": continue
      items = resp.args[1]
      if not _is_fetch_items(items): continue
      uid = items.get(b"UID")
      if not isinstance(uid, int): continue
      if uids is not None and uid not in uids: continue
      flags = items.get(b"FLAGS", b"")
      internal_date = items.get(b"INTERNALDATE")
      body = items.get(b"BODY[]")
      yield _MessageRecord(
        uid=uid,
        flags_s=flags_to_s(flags if isinstance(flags, bytes) else b""),
        internal_date=internal_date if isinstance(internal_date, bytes) and internal_date else b"",
        body=body if isinstance(body, bytes) else b"",
      )

  async def _iter_flag_records(self, ctx: CommandContext) -> AsyncIterator[_FlagRecord]:
    async for resp in ctx.responses():
      if resp.kind != b"FETCH": continue
      items = resp.args[1]
      if not _is_fetch_items(items): continue
      uid = items.get(b"UID")
      if not isinstance(uid, int): continue
      flags = items.get(b"FLAGS", b"")
      yield _FlagRecord(
        uid=uid,
        flags_s=flags_to_s(flags if isinstance(flags, bytes) else b""),
      )

  async def sync_mailbox_list(self):
    async with _mailbox_list_locks.acquire(self.account.key):
      logging.debug("sync_mailbox_list: listing remote mailboxes")
      result = await self.execute(b"LIST \"\" \"*\"")
      remote_mailboxes: list[tuple[bytes, bytes, bytes]] = []
      for resp in result.untagged:
        if resp.kind != b"LIST": continue
        flags_raw = resp.args[0]
        delim = resp.args[1]
        name = resp.args[2]
        if isinstance(flags_raw, bytes) and isinstance(delim, bytes) and isinstance(name, bytes):
          remote_mailboxes.append((flags_raw, delim, name))

      with DatabaseSession(self.config) as db:
        added = 0
        for flags, delim, name_b in remote_mailboxes:
          name_s = name_b.decode("utf-8")
          if db.mailbox_by_name(self.account.key, name_s) is None:
            _ = db.mailbox_add(self.account.key, name_s, 0, 1, flags_to_s(flags), delim.decode("ascii") if delim else "/")
            added += 1
      logging.debug("sync_mailbox_list: %d remote mailboxes, %d new", len(remote_mailboxes), added)

  async def uid_store(self, uid: int, op: bytes, flags_s: str):
    flags_b = flags_to_b(flags_s) if flags_s != "\\" else b""
    _ = await self.execute(b"UID STORE %d %s (%s)" % (uid, op, flags_b))

  async def uid_append(self, mailbox_name: str, flags_s: str, internal_date: int | None, data: bytes):
    flags_b = b"" if flags_s == "\\" else b" (" + flags_to_b(flags_s) + b")"
    date_b = b" \"" + format_internal_date(internal_date) + b"\"" if internal_date is not None else b""
    async with self.command(b"APPEND %s%s%s {%d}" % (self._encode_mailbox(mailbox_name), flags_b, date_b, len(data))) as ctx:
      await ctx.read_continuation()
      self._writer.write(data)
      self._writer.write(b"\r\n")

  async def create_mailbox(self, mailbox_name: str):
    async with self.command(b"CREATE %s" % (self._encode_mailbox(mailbox_name),)):
      pass
    await self.sync_mailbox_list()

  async def delete_mailbox(self, mailbox_name: str):
    async with self.command(b"DELETE %s" % (self._encode_mailbox(mailbox_name),)):
      pass

  async def rename_mailbox(self, old_name: str, new_name: str):
    async with self.command(b"RENAME %s %s" % (self._encode_mailbox(old_name), self._encode_mailbox(new_name))):
      pass
    await self.sync_mailbox_list()

  async def uid_expunge(self, uids: list[int], mailbox_name: str):
    if not uids:
      return
    if b"UIDPLUS" in self._capabilities:
      _ = await self.execute(b"UID EXPUNGE %s" % (b",".join(b"%d" % (u,) for u in uids),))
    else:
      logging.debug("uid_expunge: remote lacks UIDPLUS, falling back to SELECT + EXPUNGE")
      _ = await self._command_select(mailbox_name)
      _ = await self.execute(b"EXPUNGE")

  async def uid_copy(self, uids: list[int], dest_mailbox: str):
    _ = await self.execute(b"UID COPY %s %s" % (b",".join(b"%d" % (u,) for u in uids), self._encode_mailbox(dest_mailbox)))

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
      _ = await self.execute(b"ENABLE IMAP4rev2")

    if isinstance(self.account.auth, AuthenticationOAUTH2):
      logging.debug("IMAP: authenticating as OAUTH2 (XOAUTH2)")
      with DatabaseSession(self.config) as db:
        access_token = await account_get_oauth_access_token(db, self.account)
      await self._command_authenticate(b"XOAUTH2", f"user={self.account.addresses[0]}\1auth=Bearer {access_token}\1\1".encode())
    else:
      logging.debug("IMAP: authenticating as PLAIN (LOGIN)")
      await self._command_login_backend(self.account.addresses[0], self.account.auth.password)

    logging.debug("IMAP: authenticated, syncing mailbox list")
    await self.sync_mailbox_list()
    logging.debug("IMAP: init complete")

  async def _command_select(self, mailbox_name: str) -> SelectResult:
    result = await self.execute(b"SELECT %s" % (self._encode_mailbox(mailbox_name),))
    uid_validity, uid_next, exists, flags_s = 0, 0, 0, "\\"
    for resp in result.untagged:
      if resp.kind == b"OK":
        code = resp.args[0]
        if code is not None and isinstance(code, bytes):
          if code.startswith(b"UIDVALIDITY"):
            uid_validity = int(code.split(b" ")[1])
          elif code.startswith(b"UIDNEXT"):
            uid_next = int(code.split(b" ")[1])
      elif resp.kind == b"EXISTS":
        n = resp.args[0]
        if isinstance(n, int): exists = n
      elif resp.kind == b"FLAGS":
        flags_raw = resp.args[0]
        if isinstance(flags_raw, bytes): flags_s = flags_to_s(flags_raw)
    read_only = result.code == b"READ-ONLY"
    return SelectResult(uid_validity=uid_validity, uid_next=uid_next, exists=exists, flags_s=flags_s, read_only=read_only)

  async def _command_authenticate(self, auth_type: bytes, auth_data: bytes):
    if (b"AUTH=%s" % (auth_type,)) not in self._capabilities:
      raise IMAPCommandFailedError(f"Auth type '{auth_type.decode()}' not supported!")
    async with self.command(b"AUTHENTICATE %s" % (auth_type,)) as ctx:
      await ctx.read_continuation()
      self._writer.write(base64.b64encode(auth_data))
      self._writer.write(b"\r\n")

  async def _command_login_backend(self, userid: str, password: str):
    _ = await self.execute(b"LOGIN %s %s" % (imap_to_quoted_string(userid.encode()), imap_to_quoted_string(password.encode())))

  async def _command_capabilities(self):
    result = await self.execute(b"CAPABILITY")
    capabilities: list[bytes] = []
    for resp in result.untagged:
      if resp.kind == b"CAPABILITY":
        caps = resp.args[0]
        if _is_bytes_list(caps):
          capabilities.extend(caps)
    return capabilities

  async def _command_starttls(self):
    async with self.command(b"STARTTLS"):
      pass
    await self._writer.start_tls(IMAPRemoteConnection._tls_context)

  def _start_command(self, command: bytes) -> bytes:
    self._command_counter += 1
    tag = b"A%d" % (self._command_counter,)
    self._writer.write(tag + b" " + command + b"\r\n")
    return tag

  def _encode_mailbox(self, s: str) -> bytes:
    if self._use_ascii_mailbox_encoding and not s.isascii():
      return imap_to_quoted_string(encode_7bit_mailbox_name(s).encode("ascii"))
    return imap_to_quoted_string(s.encode("utf-8"))

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
