import asyncio, dataclasses, datetime, logging, re, ssl, importlib.resources
from typing import Literal
from mailproxy.auth import authenticate, authenticate_sasl
from mailproxy.db import db_mailbox_by_name, db_mailbox_count_deleted, db_mailbox_count_messages, db_mailbox_count_unseen, db_mailbox_delete, \
    db_mailbox_list, db_mailbox_max_uid, db_mailbox_rename, db_mailbox_size, db_mailbox_uid_next, db_mailbox_uid_validity, db_mailbox_update_sync, \
    db_message_add, db_message_delete_by_uid, db_message_list, db_message_update_flags, db_messages_for_account, db_open
from mailproxy.imap_backend import IMAPRemoteConnection
from mailproxy.imap_parsing import IMAPCommandFailedError, list_match, flags_set_to_s, flags_s_to_set, flags_to_b, \
    filter_headers, flags_to_s, format_internal_date, header_contains, body_contains, text_contains, parse_search_date, \
    imap_to_quoted_string, parse_internal_date, parse_sequence_set, split_message, split_fetch_items, tokenize_search_criteria
from mailproxy.model import Account, Config, Mailbox, Message
from mailproxy.utils import ScopedStreamReader, ReadValidationError

_SEARCH_FLAGS = {
  b"SEEN": b"\\Seen", b"UNSEEN": b"\\Seen",
  b"DELETED": b"\\Deleted", b"UNDELETED": b"\\Deleted",
  b"FLAGGED": b"\\Flagged", b"UNFLAGGED": b"\\Flagged",
  b"ANSWERED": b"\\Answered", b"UNANSWERED": b"\\Answered",
  b"DRAFT": b"\\Draft", b"UNDRAFT": b"\\Draft",
  b"RECENT": b"\\Recent", b"OLD": b"\\Recent",
}

_FETCH_ITEM_EXPANSION = {
  b"ALL": (b"FLAGS", b"INTERNALDATE", b"RFC822.SIZE"),
  b"FAST": (b"FLAGS", b"INTERNALDATE", b"RFC822.SIZE"),
  b"FULL": (b"FLAGS", b"INTERNALDATE", b"RFC822.SIZE", b"BODY[]"),
}

class IMAPServerConnection:
  def __init__(self, config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    self._config: Config = config
    self._reader: ScopedStreamReader = ScopedStreamReader(reader)
    self._writer: asyncio.StreamWriter = writer
    self._last_tag: bytes | None = None
    self._remote_connection: IMAPRemoteConnection | None = None
    self._mailbox: Mailbox | None = None
    self._mailbox_read_only: bool = False
    self._virtual_messages: list[Message] | None = None
    self._virtual_uid_map: dict[int, tuple[int, int]] | None = None
    self._capabilities: list[bytes] = [b"IMAP4rev1", b"AUTH=PLAIN", b"STARTTLS"]
    self._tls_active: bool = False

  def _write_response(self, code: Literal[b"OK"] | Literal[b"NO"] | Literal[b"BAD"], message: bytes):
    assert self._last_tag is not None
    self._writer.write(b"%s %s %s\r\n" % (self._last_tag, code, message))
    self._last_tag = None

  def _write_line(self, line: bytes):
    self._writer.write(line)
    self._writer.write(b"\r\n")

  def _require_remote(self) -> IMAPRemoteConnection:
    if self._remote_connection is None:
      raise IMAPCommandFailedError("must be logged in")
    return self._remote_connection

  def _require_mailbox(self) -> Mailbox:
    if self._mailbox is None:
      raise IMAPCommandFailedError("No mailbox selected!")
    return self._mailbox

  async def _read_nstring(self, until: bytes) -> bytes | None:
    self._reader.open_scope()
    first = await self._reader.readexactly(1)
    self._reader.close_scope(False)

    if first == b'"' or first == b'{':
      return await self._read_astring(until)

    atom = await self._reader.readuntil(until)
    return None if atom.upper() == b"NIL" else atom

  async def _read_astring(self, until: bytes) -> bytes:
    self._reader.open_scope()
    first = await self._reader.readexactly(1)
    self._reader.close_scope(False)

    if first == b'"':
      _ = await self._reader.readexactly(1)
      result = bytearray()
      while True:
        ch = await self._reader.readexactly(1)
        if ch == b'\\':
          result.extend(await self._reader.readexactly(1))
        elif ch == b'"':
          break
        else:
          result.extend(ch)
      _ = await self._reader.read_const(until)
      return bytes(result)
    elif first == b'{':
      _ = await self._reader.readexactly(1)
      count_s = await self._reader.readuntil(b"}")
      _ = await self._reader.read_crlf()
      data = await self._reader.readexactly(int(count_s))
      _ = await self._reader.read_const(until)
      return data
    else:
      return await self._reader.readuntil(until)

  def _write_mailbox_update(self):
    if self._mailbox is None:
      return
    if self._mailbox.is_virtual:
      n_messages = len(self._virtual_messages) if self._virtual_messages is not None else 0
    else:
      with db_open(self._config.db_path) as db:
        n_messages = db_mailbox_count_messages(db, self._mailbox.id)
    self._write_line(b"* %d EXISTS" % (n_messages,))

  def _write_mailbox_list_response(self, mailbox: Mailbox):
    flags = " ".join(mailbox.flags).encode("ascii")
    hierarchy_delimiter_s = imap_to_quoted_string(mailbox.hierarchy_delimiter.encode("ascii"))
    name_s = imap_to_quoted_string(mailbox.name.encode())
    self._write_line(b"* LIST (%s) %s %s" % (flags, hierarchy_delimiter_s, name_s))

  async def _sync_mailbox(self):
    mailbox = self._require_mailbox()
    remote = self._require_remote()
    if mailbox.is_remote:
      await remote.sync_mailbox(mailbox.name)

  async def _command_capability(self):
    self._write_line(b"* CAPABILITY %s" % (b" ".join(self._capabilities),))
    self._write_response(b"OK", b"CAPABILITY completed")

  async def _command_noop(self):
    if self._mailbox is not None:
      mailbox = self._mailbox
      remote = self._require_remote()
      if mailbox.is_remote:
        await remote.sync_mailbox(mailbox.name)
      elif mailbox.is_virtual:
        self._build_virtual_mailbox(remote.account.key, mailbox.name)
      self._write_mailbox_update()
    self._write_response(b"OK", b"NOOP completed")

  async def _command_enable(self):
    caps_str = await self._reader.read_line()
    caps = caps_str.split(b" ")
    if all(c in self._capabilities for c in caps):
      self._write_response(b"OK", b"ENABLE completed")
    else:
      self._write_response(b"NO", b"not supported")

  async def _command_starttls(self):
    if self._tls_active:
      self._write_response(b"NO", b"TLS already active")
      return
    self._write_response(b"OK", b"Begin TLS negotiation now")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with importlib.resources.path("mailproxy.assets", "dummy-cert.pem") as cert_path, importlib.resources.path("mailproxy.assets", "dummy-key.pem") as key_path:
      ctx.load_cert_chain(cert_path, key_path)
    await self._writer.start_tls(ctx)
    self._tls_active = True
    self._capabilities = [c for c in self._capabilities if c != b"STARTTLS"]
    logging.debug("STARTTLS: TLS upgrade complete")

  async def _command_logout(self):
    self._write_line(b"* BYE Server logging out")
    self._write_response(b"OK", b"LOGOUT completed")

  async def _command_login(self):
    userid = await self._read_astring(b" ")
    password = await self._read_astring(b"\r\n")
    with db_open(self._config.db_path) as db:
      login_account = authenticate(self._config, db, userid, password)
    if login_account is None:
      self._write_response(b"NO", b"login failed")
    else:
      try:
        await self._open_remote(login_account)
        self._write_response(b"OK", b"login completed")
      except IMAPCommandFailedError:
        self._write_response(b"NO", b"login failed")

  async def _command_authenticate(self):
    try: _ = await self._reader.read_const(b"PLAIN", case_sensitive=False)
    except ReadValidationError: raise IMAPCommandFailedError("Only PLAIN auth supported!")
    _ = await self._reader.read_crlf()
    self._write_line(b"+ ")
    auth_line = await self._reader.read_line()
    with db_open(self._config.db_path) as db:
      login_account = authenticate_sasl(self._config, db, auth_line)
    if login_account is None:
      self._write_response(b"NO", b"auth failed")
    else:
      try:
        await self._open_remote(login_account)
        self._write_response(b"OK", b"auth completed")
      except IMAPCommandFailedError:
        self._write_response(b"NO", b"auth failed")

  async def _command_subscribe(self):
    _ = await self._reader.read_line()
    self._write_response(b"OK", b"SUBSCRIBE completed")

  async def _command_unsubscribe(self):
    _ = await self._reader.read_line()
    self._write_response(b"NO", b"UNSUBSCRIBE not allowed")

  async def _command_idle(self):
    self._write_line(b"+ idling")
    tasks: list[asyncio.Task[None]] = []
    if self._mailbox is not None:
      mailbox = self._mailbox
      remote = self._require_remote()
      update_event = asyncio.Event()
      async def _update_on_event():
        while True:
          _ = await update_event.wait()
          if self._mailbox is not None and self._mailbox.is_remote:
            await remote.sync_mailbox(self._mailbox.name)
          self._write_mailbox_update()
          update_event.clear()
      tasks.extend((asyncio.Task(remote.wait_for_update(mailbox.name, update_event)), asyncio.Task(_update_on_event())))
    try:
      _ = await self._reader.read_const(b"DONE\r\n", case_sensitive=False)
      self._write_response(b"OK", b"IDLE completed")
    finally:
      for task in tasks: _ = task.cancel()
      _ = await asyncio.wait(tasks)

  async def _command_status(self):
    mailbox_name_raw = await self._read_nstring(b" ")
    mailbox_name = None if mailbox_name_raw is None else mailbox_name_raw.decode()
    _ = await self._reader.read_const(b"(")
    attrs_res = await self._reader.readuntil_re(b")", rb"(?P<attrs>[A-Z ]+)\)")
    attrs = attrs_res["attrs"].split(b" ")
    _ = await self._reader.read_crlf()

    remote = self._require_remote()
    account = remote.account
    with db_open(self._config.db_path) as db:
      mailbox = self._mailbox if mailbox_name is None else db_mailbox_by_name(db, account.key, mailbox_name)
      needs_sync = mailbox is not None and mailbox.is_remote

    if needs_sync and mailbox is not None:
      await remote.sync_mailbox(mailbox.name)

    with db_open(self._config.db_path) as db:
      mailbox = self._mailbox if mailbox_name is None else db_mailbox_by_name(db, account.key, mailbox_name)
      if mailbox is None:
        return self._write_response(b"NO", b"invalid mailbox name")

      response: dict[bytes, int] = {}
      if b"MESSAGES" in attrs: response[b"MESSAGES"] = db_mailbox_count_messages(db, mailbox.id)
      if b"UIDNEXT" in attrs: response[b"UIDNEXT"] = db_mailbox_uid_next(db, account.key, mailbox.id)
      if b"UIDVALIDITY" in attrs: response[b"UIDVALIDITY"] = db_mailbox_uid_validity(db, account.key, mailbox.id)
      if b"UNSEEN" in attrs: response[b"UNSEEN"] = db_mailbox_count_unseen(db, mailbox.id)
      if b"DELETED" in attrs: response[b"DELETED"] = db_mailbox_count_deleted(db, mailbox.id)
      if b"SIZE" in attrs: response[b"SIZE"] = db_mailbox_size(db, mailbox.id)

      status_str = b" ".join(b"%s %d" % (k, v) for k, v in response.items())
      mailbox_name_s = imap_to_quoted_string(mailbox.name.encode())
      self._write_line(b"* STATUS %s (%s)" % (mailbox_name_s, status_str))
    self._write_response(b"OK", b"status completed")

  async def _command_select(self, read_only: bool = False):
    mailbox_name = (await self._read_astring(b"\r\n")).decode()
    remote = self._require_remote()
    account = remote.account

    with db_open(self._config.db_path) as db:
      mailbox = db_mailbox_by_name(db, account.key, mailbox_name)
      needs_sync = mailbox is None or mailbox.is_remote
      logging.debug("SELECT: '%s' mailbox_in_db=%s needs_sync=%s is_virtual=%s", mailbox_name, mailbox is not None, needs_sync, mailbox.is_virtual if mailbox else False)

    if mailbox is not None and mailbox.is_virtual:
      self._build_virtual_mailbox(account.key, mailbox.name)

    if needs_sync and (mailbox is None or mailbox.is_remote):
      await remote.sync_mailbox(mailbox_name)

    with db_open(self._config.db_path) as db:
      mailbox = db_mailbox_by_name(db, account.key, mailbox_name)
      if mailbox is None:
        raise IMAPCommandFailedError("mailbox unknown")

      if self._mailbox is not None:
        self._write_line(b"* OK [CLOSED] Previous mailbox is now closed")

      self._write_line(b"* FLAGS (%s)" % (" ".join(mailbox.flags).encode("ascii"),))
      if mailbox.is_virtual:
        n_messages = len(self._virtual_messages) if self._virtual_messages is not None else 0
      else:
        n_messages = db_mailbox_count_messages(db, mailbox.id)
      self._write_line(b"* %d EXISTS" % (n_messages,))
      self._write_mailbox_list_response(mailbox)
      self._write_line(b"* OK [PERMANENTFLAGS (\\Deleted \\Seen \\Answered \\Flagged \\Draft \\*)]")
      self._write_line(b"* OK [UIDNEXT %d]" % (mailbox.uid_next,))
      self._write_line(b"* OK [UIDVALIDITY %d]" % (mailbox.uid_validity,))
      self._mailbox = mailbox
      self._mailbox_read_only = read_only
      logging.debug("SELECT: '%s' selected, %d messages read_only=%s", mailbox.name, n_messages, read_only)

    access = b"[READ-ONLY]" if read_only else b"[READ-WRITE]"
    self._write_response(b"OK", access + b" SELECT completed")

  def _build_virtual_mailbox(self, account_key: str, mailbox_name: str):
    flags_filter: str | None = None
    if mailbox_name == "Virtual/Unseen":
      flags_filter = "\\Unseen"
    elif mailbox_name == "Virtual/Flagged":
      flags_filter = "\\Flagged"
    with db_open(self._config.db_path) as db:
      messages = db_messages_for_account(db, account_key, flags_filter)
    self._virtual_messages = messages
    self._virtual_uid_map = {}
    for i, msg in enumerate(messages):
      self._virtual_uid_map[i + 1] = (msg.mailbox_id, msg.uid)

  async def _command_list(self):
    reference_name_raw = await self._read_astring(b" ")
    pattern_raw = await self._read_astring(b"\r\n")
    remote = self._require_remote()

    reference_name = reference_name_raw.decode()
    pattern = pattern_raw.decode()

    if pattern == "":
      self._write_line(b"* LIST (\\Noselect) \"/\" \"\"")
      self._write_response(b"OK", b"list completed")
      return

    await remote.sync_mailbox_list()

    with db_open(self._config.db_path) as db:
      for mailbox in db_mailbox_list(db, remote.account.key):
        full_name = reference_name + mailbox.name if reference_name else mailbox.name
        if list_match(full_name, pattern):
          self._write_mailbox_list_response(mailbox)

    self._write_response(b"OK", b"list completed")

  async def _command_examine(self):
    await self._command_select(read_only=True)

  async def _command_close(self):
    mailbox = self._mailbox
    if mailbox is not None and not self._mailbox_read_only and not mailbox.is_virtual:
      remote = self._require_remote()
      with db_open(self._config.db_path) as db:
        deleted = [m.uid for m in db_message_list(db, mailbox.id) if "\\Deleted" in m.flags_s]
      if deleted and mailbox.is_remote:
        await remote.uid_expunge(deleted)
      with db_open(self._config.db_path) as db:
        for uid in deleted:
          db_message_delete_by_uid(db, mailbox.id, uid)
    self._mailbox = None
    self._mailbox_read_only = False
    self._virtual_messages = None
    self._virtual_uid_map = None
    self._write_response(b"OK", b"CLOSE completed")

  def _match_messages(self, seq_set_s: bytes, uid_mode: bool, messages: list[Message]) -> list[tuple[int, Message]]:
    n = len(messages)
    if uid_mode:
      max_uid = max(m.uid for m in messages) if messages else 0
      uids = set(parse_sequence_set(seq_set_s, max_uid))
      result = [(i + 1, m) for i, m in enumerate(messages) if m.uid in uids]
      logging.debug("_match_messages: uid_mode seq_set=%s max_uid=%d matched=%d", seq_set_s.decode(), max_uid, len(result))
      return result
    seqs = parse_sequence_set(seq_set_s, n)
    result = [(seq, messages[seq - 1]) for seq in seqs if 1 <= seq <= n]
    logging.debug("_match_messages: seq_mode seq_set=%s n=%d matched=%d", seq_set_s.decode(), n, len(result))
    return result

  async def _command_fetch(self, uid_mode: bool):
    seq_set_s = await self._reader.readuntil(b" ")
    items_s = (await self._reader.read_line()).strip()
    if items_s.startswith(b"(") and items_s.endswith(b")"):
      items_s = items_s[1:-1]

    mailbox = self._require_mailbox()
    _ = self._require_remote()

    raw_items = split_fetch_items(items_s)
    items: list[bytes] = []
    for item in raw_items:
      items.extend(_FETCH_ITEM_EXPANSION.get(item.upper(), (item,)))

    if uid_mode and b"UID" not in [i.upper() for i in items]:
      items.insert(0, b"UID")

    logging.debug("FETCH: seq_set=%s items=%s uid_mode=%s", seq_set_s.decode(), [i.decode(errors="replace") for i in items], uid_mode)

    if mailbox.is_virtual:
      messages = self._virtual_messages if self._virtual_messages is not None else []
    else:
      with db_open(self._config.db_path) as db:
        messages = list(db_message_list(db, mailbox.id))

    if not messages:
      logging.debug("FETCH: no messages in mailbox %s", mailbox.name)
      self._write_response(b"OK", b"FETCH completed")
      return

    matching = self._match_messages(seq_set_s, uid_mode, messages)
    logging.debug("FETCH: %d messages, %d matched", len(messages), len(matching))

    seen_uids_to_update: list[tuple[int, int]] = []

    for seq, msg in matching:
      parts: list[bytes] = []
      body_data: bytes | None = None
      body_tag = b"BODY[]"
      should_set_seen = False

      for item in items:
        item_u = item.upper()
        if item_u == b"UID": parts.append(b"UID %d" % (msg.uid,))
        elif item_u == b"FLAGS": parts.append(b"FLAGS (%s)" % (flags_to_b(msg.flags_s),))
        elif item_u == b"INTERNALDATE": parts.append(b"INTERNALDATE \"%s\"" % (format_internal_date(msg.received_date),))
        elif item_u == b"RFC822.SIZE": parts.append(b"RFC822.SIZE %d" % (msg.size,))
        elif item_u in (b"BODY[]", b"RFC822"):
          data = msg.data
          body_data = data
          body_tag = b"BODY[]"
          parts.append(b"%s {%d}" % (body_tag, len(data),))
          should_set_seen = True
        elif item_u == b"BODY.PEEK[]":
          data = msg.data
          body_data = data
          body_tag = b"BODY[]"
          parts.append(b"%s {%d}" % (body_tag, len(data),))
        elif item_u in (b"BODY[HEADER]", b"BODY.PEEK[HEADER]", b"RFC822.HEADER"):
          header, _ = split_message(msg.data)
          body_data = header
          body_tag = b"BODY[HEADER]"
          parts.append(b"%s {%d}" % (body_tag, len(header),))
        elif item_u in (b"BODY[TEXT]", b"BODY.PEEK[TEXT]", b"RFC822.TEXT"):
          _, text = split_message(msg.data)
          body_data = text
          body_tag = b"BODY[TEXT]"
          parts.append(b"%s {%d}" % (body_tag, len(text),))
          if not item_u.startswith(b"BODY.PEEK"):
            should_set_seen = True
        elif item_u.startswith(b"BODY") or item_u.startswith(b"RFC822"):
          is_peek = item_u.startswith(b"BODY.PEEK")
          if b"HEADER.FIELDS" in item_u:
            field_list = self._parse_header_fields(item)
            header, _ = split_message(msg.data)
            filtered = filter_headers(msg.data, field_list)
            body_data = filtered
            body_tag = b"BODY[HEADER.FIELDS (%s)]" % (b" ".join(field_list),) if not is_peek else b"BODY[HEADER.FIELDS (%s)]" % (b" ".join(field_list),)
            parts.append(b"%s {%d}" % (body_tag, len(filtered),))
          elif b"HEADER" in item_u:
            header, _ = split_message(msg.data)
            body_data = header
            body_tag = item.replace(b"PEEK", b"") if is_peek else item
            parts.append(b"%s {%d}" % (body_tag, len(header),))
          elif b"TEXT" in item_u:
            _, text = split_message(msg.data)
            body_data = text
            body_tag = item.replace(b"PEEK", b"") if is_peek else item
            parts.append(b"%s {%d}" % (body_tag, len(text),))
            if not is_peek:
              should_set_seen = True
          else:
            data = msg.data
            body_data = data
            body_tag = item.replace(b"PEEK", b"") if is_peek else item
            parts.append(b"%s {%d}" % (body_tag, len(data),))
            if not is_peek:
              should_set_seen = True
        elif item_u in (b"BODYSTRUCTURE", b"BODY"):
          parts.append(b"BODYSTRUCTURE NIL")

      if should_set_seen and "\\Seen" not in msg.flags_s:
        new_flags = msg.flags_s.rstrip("\\") + "\\Seen\\" if msg.flags_s != "\\\\" else "\\Seen\\"
        msg = dataclasses.replace(msg, flags_s=new_flags)
        seen_uids_to_update.append((msg.mailbox_id, msg.uid))

      items_str = b" ".join(parts)
      if body_data is not None:
        self._writer.write(b"* %d FETCH (%s\r\n" % (seq, items_str))
        self._writer.write(body_data)
        self._writer.write(b")\r\n")
      else:
        self._write_line(b"* %d FETCH (%s)" % (seq, items_str))

    if seen_uids_to_update:
      remote = self._require_remote()
      with db_open(self._config.db_path) as db:
        for mb_id, uid in seen_uids_to_update:
          db_message_update_flags(db, mb_id, uid, "\\Seen\\")
      if mailbox.is_remote:
        for _, uid in seen_uids_to_update:
          await remote.uid_store(uid, b"+FLAGS", "\\Seen\\")

    self._write_response(b"OK", b"FETCH completed")

  def _parse_header_fields(self, item: bytes) -> list[bytes]:
    m = re.search(rb'\((?P<fields>[^)]*)\)', item)
    if m is None:
      return []
    return [f.strip() for f in m.group("fields").split(b" ") if f.strip()]

  async def _command_search(self, uid_mode: bool):
    criteria_s = await self._reader.read_line()
    mailbox = self._require_mailbox()
    _ = self._require_remote()

    if mailbox.is_virtual:
      messages = self._virtual_messages if self._virtual_messages is not None else []
    else:
      with db_open(self._config.db_path) as db:
        messages = list(db_message_list(db, mailbox.id))

    tokens = tokenize_search_criteria(criteria_s.strip())
    if tokens:
      tokens[0] = tokens[0].upper()
    results: list[int] = []

    for i, msg in enumerate(messages):
      matched = self._evaluate_search_criteria(tokens, msg, messages)
      if matched:
        results.append(msg.uid if uid_mode else i + 1)

    self._write_line(b"* SEARCH %s" % (b" ".join(b"%d" % (r,) for r in results),))
    self._write_response(b"OK", b"SEARCH completed")

  def _evaluate_search_criteria(self, tokens: list[bytes], msg: Message, all_messages: list[Message]) -> bool:
    j = 0
    matched = True
    while j < len(tokens):
      c = tokens[j].upper()
      if c in _SEARCH_FLAGS:
        flag = _SEARCH_FLAGS[c].decode("ascii")
        present = flag in msg.flags_s
        matched = matched and (not present if c.startswith(b"UN") else present)
      elif c == b"NEW":
        matched = matched and "\\Recent" not in msg.flags_s and "\\Seen" not in msg.flags_s
      elif c == b"ALL":
        pass
      elif c == b"UID" and j + 1 < len(tokens):
        j += 1
        uid_set = set(parse_sequence_set(tokens[j], max(m.uid for m in all_messages) if all_messages else 0))
        matched = matched and msg.uid in uid_set
      elif c == b"CHARSET":
        j += 1
      elif c in (b"SUBJECT", b"FROM", b"TO", b"CC", b"BCC") and j + 1 < len(tokens):
        j += 1
        matched = matched and header_contains(msg.data, c.decode("ascii"), tokens[j])
      elif c == b"HEADER" and j + 2 < len(tokens):
        j += 2
        matched = matched and header_contains(msg.data, tokens[j-1].decode("ascii"), tokens[j])
      elif c == b"BODY" and j + 1 < len(tokens):
        j += 1
        matched = matched and body_contains(msg.data, tokens[j])
      elif c == b"TEXT" and j + 1 < len(tokens):
        j += 1
        matched = matched and text_contains(msg.data, tokens[j])
      elif c in (b"SINCE", b"BEFORE", b"ON") and j + 1 < len(tokens):
        j += 1
        try:
          target_ts = parse_search_date(tokens[j])
          msg_date = datetime.datetime.fromtimestamp(msg.received_date, tz=datetime.timezone.utc)
          target_date = datetime.datetime.fromtimestamp(target_ts, tz=datetime.timezone.utc)
          if c == b"SINCE":
            matched = matched and msg_date.date() >= target_date.date()
          elif c == b"BEFORE":
            matched = matched and msg_date.date() < target_date.date()
          else:
            matched = matched and msg_date.date() == target_date.date()
        except (ValueError, OverflowError):
          matched = False
      elif c == b"LARGER" and j + 1 < len(tokens):
        j += 1
        try: matched = matched and msg.size > int(tokens[j])
        except ValueError: matched = False
      elif c == b"SMALLER" and j + 1 < len(tokens):
        j += 1
        try: matched = matched and msg.size < int(tokens[j])
        except ValueError: matched = False
      elif c == b"NOT" and j + 1 < len(tokens):
        j += 1
        sub_tokens = [tokens[j]]
        matched = matched and not self._evaluate_search_criteria(sub_tokens, msg, all_messages)
      elif c == b"OR" and j + 2 < len(tokens):
        j += 2
        left = self._evaluate_search_criteria([tokens[j-1]], msg, all_messages)
        right = self._evaluate_search_criteria([tokens[j]], msg, all_messages)
        matched = matched and (left or right)
      else:
        matched = False
      j += 1
      if not matched: break
    return matched

  async def _command_store(self, uid_mode: bool):
    seq_set_s = await self._reader.readuntil(b" ")
    op_s = (await self._reader.readuntil(b" ")).upper()
    _ = await self._reader.read_const(b"(")
    flags_s_raw = await self._reader.readuntil(b")")
    _ = await self._reader.read_crlf()

    mailbox = self._require_mailbox()
    remote = self._require_remote()

    new_flags = set(f.decode("ascii") for f in flags_s_raw.strip().split(b" ") if f)
    silent = op_s.endswith(b".SILENT")
    if silent: op_s = op_s[:-len(b".SILENT")]

    op_mode = op_s[0:1] if op_s[:1] in (b"+", b"-") else b"="

    if mailbox.is_virtual:
      messages = self._virtual_messages if self._virtual_messages is not None else []
    else:
      with db_open(self._config.db_path) as db:
        messages = list(db_message_list(db, mailbox.id))
    matching = self._match_messages(seq_set_s, uid_mode, messages)

    for seq, msg in matching:
      current = flags_s_to_set(msg.flags_s)
      match op_mode:
        case b"+": result_flags = current | new_flags
        case b"-": result_flags = current - new_flags
        case _: result_flags = new_flags
      flags_s = flags_set_to_s(result_flags)

      if mailbox.is_remote:
        await remote.uid_store(msg.uid, op_s if not silent else op_s + b".SILENT", flags_s)

      with db_open(self._config.db_path) as db:
        db_message_update_flags(db, msg.mailbox_id, msg.uid, flags_s)

      if not silent:
        self._write_line(b"* %d FETCH (FLAGS (%s))" % (seq, b" ".join(b"\\" + f.encode("ascii") for f in sorted(result_flags)),))

    self._write_response(b"OK", b"STORE completed")

  async def _command_append(self):
    mailbox_name_raw = await self._read_astring(b" ")
    mailbox_name = mailbox_name_raw.decode()
    flags_s = "\\"
    internal_date: int | None = None

    self._reader.open_scope()
    peek = await self._reader.readexactly(1)
    self._reader.close_scope(False)

    if peek == b"(":
      _ = await self._reader.read_const(b"(")
      flags_raw = await self._reader.readuntil(b")")
      _ = await self._reader.read_const(b" ")
      flags_s = flags_to_s(flags_raw.strip().split(b" "))
      self._reader.open_scope()
      peek = await self._reader.readexactly(1)
      self._reader.close_scope(False)

    if peek == b'"':
      date_raw = await self._read_astring(b" ")
      internal_date = parse_internal_date(date_raw)

    _ = await self._reader.read_const(b"{")
    count_s = await self._reader.readuntil(b"}")
    _ = await self._reader.read_crlf()
    data = await self._reader.readexactly(int(count_s))
    _ = await self._reader.read_crlf()

    remote = self._require_remote()
    account = remote.account
    with db_open(self._config.db_path) as db:
      mailbox = db_mailbox_by_name(db, account.key, mailbox_name)
    if mailbox is None or mailbox.is_remote:
      await remote.uid_append(mailbox_name, flags_s, internal_date, data)
      if mailbox is not None and mailbox.is_remote:
        await remote.sync_mailbox(mailbox_name)
    else:
      with db_open(self._config.db_path) as db:
        uid = db_mailbox_max_uid(db, mailbox.id) + 1
        db_message_add(db, uid, mailbox.id, int(datetime.datetime.now().timestamp()), flags_s, len(data), data, str(uid))
        db_mailbox_update_sync(db, mailbox.id, uid_next=uid + 1, last_synced_uid=uid)

    self._write_response(b"OK", b"APPEND completed")

  async def _command_create(self):
    mailbox_name = (await self._read_astring(b"\r\n")).decode()
    remote = self._require_remote()
    await remote.create_mailbox(mailbox_name)
    self._write_response(b"OK", b"CREATE completed")

  async def _command_delete(self):
    mailbox_name = (await self._read_astring(b"\r\n")).decode()
    remote = self._require_remote()
    account = remote.account
    with db_open(self._config.db_path) as db:
      mailbox = db_mailbox_by_name(db, account.key, mailbox_name)
    if mailbox is None:
      return self._write_response(b"NO", b"mailbox not found")
    if mailbox.is_virtual:
      return self._write_response(b"NO", b"cannot delete virtual mailbox")
    if mailbox.is_remote:
      await remote.delete_mailbox(mailbox_name)
    with db_open(self._config.db_path) as db:
      db_mailbox_delete(db, mailbox.id)
    self._write_response(b"OK", b"DELETE completed")

  async def _command_rename(self):
    old_name = (await self._read_astring(b" ")).decode()
    new_name = (await self._read_astring(b"\r\n")).decode()
    remote = self._require_remote()
    account = remote.account
    with db_open(self._config.db_path) as db:
      mailbox = db_mailbox_by_name(db, account.key, old_name)
    if mailbox is None:
      return self._write_response(b"NO", b"mailbox not found")
    if mailbox.is_remote:
      await remote.rename_mailbox(old_name, new_name)
    with db_open(self._config.db_path) as db:
      db_mailbox_rename(db, mailbox.id, new_name)
    self._write_response(b"OK", b"RENAME completed")

  async def _command_copy(self, uid_mode: bool):
    seq_set_s = await self._reader.readuntil(b" ")
    dest_name = (await self._read_astring(b"\r\n")).decode()
    mailbox = self._require_mailbox()
    remote = self._require_remote()

    if mailbox.is_virtual:
      messages = self._virtual_messages if self._virtual_messages is not None else []
    else:
      with db_open(self._config.db_path) as db:
        messages = list(db_message_list(db, mailbox.id))
    matching = self._match_messages(seq_set_s, uid_mode, messages)

    if matching and mailbox.is_remote:
      await remote.uid_copy([msg.uid for _, msg in matching], dest_name)
    self._write_response(b"OK", b"COPY completed")

  async def _command_expunge(self, uid_mode: bool):
    seq_set_s = await self._reader.readuntil(b"\r\n") if uid_mode else b""

    mailbox = self._require_mailbox()
    remote = self._require_remote()

    if mailbox.is_virtual:
      messages = self._virtual_messages if self._virtual_messages is not None else []
      if uid_mode:
        max_uid = max(m.uid for m in messages) if messages else 0
        uids = set(parse_sequence_set(seq_set_s.strip(), max_uid))
        deleted = [(i + 1, m) for i, m in enumerate(messages) if "\\Deleted" in m.flags_s and m.uid in uids]
      else:
        deleted = [(i + 1, m) for i, m in enumerate(messages) if "\\Deleted" in m.flags_s]
    else:
      with db_open(self._config.db_path) as db:
        all_msgs = list(db_message_list(db, mailbox.id))
        if uid_mode:
          max_uid = db_mailbox_max_uid(db, mailbox.id)
          uids = set(parse_sequence_set(seq_set_s.strip(), max_uid))
          deleted = [(i + 1, m) for i, m in enumerate(all_msgs) if "\\Deleted" in m.flags_s and m.uid in uids]
        else:
          deleted = [(i + 1, m) for i, m in enumerate(all_msgs) if "\\Deleted" in m.flags_s]

    deleted.sort(key=lambda x: x[0])

    if mailbox.is_remote:
      await remote.uid_expunge([m.uid for _, m in deleted])

    offset = 0
    for seq, msg in deleted:
      actual_seq = seq - offset
      with db_open(self._config.db_path) as db:
        db_message_delete_by_uid(db, msg.mailbox_id, msg.uid)
      self._write_line(b"* %d EXPUNGE" % (actual_seq,))
      offset += 1

    self._write_response(b"OK", b"EXPUNGE completed")

  async def _open_remote(self, account: Account):
    if self._remote_connection is not None:
      await self._remote_connection.shutdown()
    self._remote_connection = await IMAPRemoteConnection.open(self._config, account)

  async def _handle_command(self):
    self._last_tag = await self._reader.readuntil(b" ") # TODO better validation
    command_raw = await self._reader.readuntil((b" ", b"\r\n")) # TODO better validation
    command = command_raw.upper()
    full_cmd = b"%s %s" % (self._last_tag, command)
    logging.debug("Client: %s", full_cmd.decode(errors="replace"))

    match command:
      case b"CAPABILITY": await self._command_capability()
      case b"NOOP": await self._command_noop()
      case b"ENABLE": await self._command_enable()
      case b"LOGOUT": await self._command_logout()
      case b"LOGIN": await self._command_login()
      case b"AUTHENTICATE": await self._command_authenticate()
      case b"SUBSCRIBE": await self._command_subscribe()
      case b"UNSUBSCRIBE": await self._command_unsubscribe()
      case b"IDLE": await self._command_idle()
      case b"STATUS": await self._command_status()
      case b"SELECT": await self._command_select(read_only=False)
      case b"EXAMINE": await self._command_select(read_only=True)
      case b"CLOSE": await self._command_close()
      case b"LIST": await self._command_list()
      case b"FETCH": await self._command_fetch(uid_mode=False)
      case b"SEARCH": await self._command_search(uid_mode=False)
      case b"STORE": await self._command_store(uid_mode=False)
      case b"APPEND": await self._command_append()
      case b"CREATE": await self._command_create()
      case b"DELETE": await self._command_delete()
      case b"RENAME": await self._command_rename()
      case b"COPY": await self._command_copy(uid_mode=False)
      case b"EXPUNGE": await self._command_expunge(uid_mode=False)
      case b"UID":
        sub_raw = await self._reader.readuntil((b" ", b"\r\n"))
        sub = sub_raw.upper()
        match sub:
          case b"FETCH": await self._command_fetch(uid_mode=True)
          case b"SEARCH": await self._command_search(uid_mode=True)
          case b"STORE": await self._command_store(uid_mode=True)
          case b"COPY": await self._command_copy(uid_mode=True)
          case b"EXPUNGE": await self._command_expunge(uid_mode=True)
          case _: self._write_response(b"BAD", b"unknown UID command")
      case b"STARTTLS": await self._command_starttls()
      case _: self._write_response(b"BAD", b"unknown command")

  async def run(self):
    self._write_line(b"* OK %s IMAP4rev1 proxy ready" % (self._config.domain.encode("ascii"),))
    logging.debug("IMAP frontend: client connected")
    try:
      while not self._reader.at_eof:
        try:
          self._reader.open_scope()
          await self._handle_command()
        except IMAPCommandFailedError as e:
          logging.debug("command failed: %s", e)
          if self._last_tag is not None:
            self._write_response(b"NO", b"command failed with internal error")
        finally:
          self._reader.close_scope(True)
    except Exception as e:
      logging.error("connection closing because of an error: %s", e)
    finally:
      logging.debug("IMAP frontend: connection closed")
      self._writer.close()
      if self._remote_connection is not None:
        try: await asyncio.wait_for(self._remote_connection.shutdown(), 1)
        except Exception: pass

async def handle_imap(config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
  connection = IMAPServerConnection(config, reader, writer)
  await connection.run()
