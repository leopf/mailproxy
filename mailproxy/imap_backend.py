import asyncio, base64, datetime, logging, re, ssl
from dataclasses import dataclass
from mailproxy.auth import account_get_oauth_access_token
from mailproxy.db import db_message_add, db_message_update_flags, db_mailbox_add, db_mailbox_by_name, db_mailbox_update_sync, db_messages_clear, db_open
from mailproxy.imap_parsing import IMAPCommandFailedError, flags_to_s, imap_to_quoted_string, parse_fetch_line, parse_internal_date
from mailproxy.model import Account, AuthenticationOAUTH2, Config, TLSMode
from mailproxy.utils import match_lineb, encode_7bit_mailbox_name

@dataclass(frozen=True)
class SelectResult:
  uid_validity: int
  uid_next: int
  exists: int
  flags_s: str
  read_only: bool

class IMAPRemoteConnection:
  _tls_context: ssl.SSLContext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

  def __init__(self, config: Config, account: Account, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    self.account: Account = account
    self.config: Config = config
    self._reader: asyncio.StreamReader = reader
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
      new_messages: list[tuple[int, int, int, str, int, bytes, str]] = []
      async for line in self._read_response_lines():
        parsed = parse_fetch_line(line)
        if parsed is None: continue
        uid = parsed.get(b"UID")
        if uid is None: continue
        flags = parsed.get(b"FLAGS", b"")
        internal_date = parsed.get(b"INTERNALDATE", b"")
        size = parsed.get(b"RFC822.SIZE", 0)
        body = parsed.get(b"BODY[]", b"")
        msg_flags_s = flags_to_s(flags) if isinstance(flags, bytes) else "\\\\"
        received_date = parse_internal_date(internal_date) if isinstance(internal_date, bytes) and internal_date else int(datetime.datetime.now().timestamp())
        new_messages.append((int(uid), mailbox_id, received_date, msg_flags_s, int(size), bytes(body), str(uid)))

      if new_messages:
        with db_open(self.config.db_path) as db:
          for msg in new_messages:
            db_message_add(db, *msg)
          max_uid = max(m[0] for m in new_messages)
          db_mailbox_update_sync(db, mailbox_id, last_synced_uid=max_uid)
        logging.debug("sync_mailbox: '%s' fetched %d new messages (up to uid %d)", mailbox_name, len(new_messages), max_uid)
      else:
        logging.debug("sync_mailbox: '%s' no new messages", mailbox_name)

    if last_synced > 0:
      self._start_command(b"UID FETCH 1:%d (UID FLAGS)" % (last_synced,))
      flag_updates: list[tuple[int, str]] = []
      async for line in self._read_response_lines():
        parsed = parse_fetch_line(line)
        if parsed is None: continue
        uid = parsed.get(b"UID")
        if uid is None: continue
        flags = parsed.get(b"FLAGS", b"")
        msg_flags_s = flags_to_s(flags) if isinstance(flags, bytes) else "\\\\"
        flag_updates.append((int(uid), msg_flags_s))

      if flag_updates:
        with db_open(self.config.db_path) as db:
          for uid, flags_s in flag_updates:
            db_message_update_flags(db, mailbox_id, uid, flags_s)
        logging.debug("sync_mailbox: '%s' updated flags for %d messages", mailbox_name, len(flag_updates))

  async def sync_mailbox_list(self):
    logging.debug("sync_mailbox_list: listing remote mailboxes")
    self._start_command(b"LIST \"\" \"*\"")
    remote_mailboxes: list[tuple[bytes, bytes, bytes]] = []
    async for line in self._read_response_lines():
      m = re.fullmatch(rb'\* LIST \((?P<flags>.*)\) (?P<delim>\S+) (?P<name>.*)', line, re.DOTALL)
      if m is None: continue
      name = m.group("name")
      if name.startswith(b'"') and name.endswith(b'"'): name = name[1:-1]
      lit_m = re.fullmatch(rb'\{(\d+)\}(.*)', name, re.DOTALL)
      if lit_m is not None:
        n = int(lit_m.group(1))
        name = lit_m.group(2)[:n]
      delim = m.group("delim")
      if delim.startswith(b'"') and delim.endswith(b'"'): delim = delim[1:-1]
      remote_mailboxes.append((m.group("flags"), delim, name))

    with db_open(self.config.db_path) as db:
      added = 0
      for flags, delim, name_b in remote_mailboxes:
        name_s = name_b.decode("utf-8")
        if db_mailbox_by_name(db, self.account.key, name_s) is None:
          _ = db_mailbox_add(db, self.account.key, name_s, 0, 1, flags_to_s(flags), delim.decode("ascii") if delim else "/")
          added += 1
      for vname in ("Virtual/All", "Virtual/Unseen", "Virtual/Flagged"):
        if db_mailbox_by_name(db, self.account.key, vname) is None:
          _ = db_mailbox_add(db, self.account.key, vname, 0, 1, "\\\\", "/", is_remote=False, is_virtual=True)
          added += 1
    logging.debug("sync_mailbox_list: %d remote mailboxes, %d new", len(remote_mailboxes), added)

  async def uid_store(self, uid: int, op: bytes, flags_s: str):
    flags_b = b" ".join(b"\\" + f.encode("ascii") for f in flags_s.strip("\\").split("\\") if f) if flags_s != "\\" else b""
    self._start_command(b"UID STORE %d %s (%s)" % (uid, op, flags_b))
    await self._read_until_response()

  async def uid_append(self, mailbox_name: str, flags_s: str, internal_date: int | None, data: bytes):
    flags_b = b"" if flags_s == "\\" else b" (" + b" ".join(b"\\" + f.encode("ascii") for f in flags_s.strip("\\").split("\\") if f) + b")"
    date_b = b" \"" + datetime.datetime.fromtimestamp(internal_date, tz=datetime.timezone.utc).strftime("%d-%b-%Y %H:%M:%S %z").encode("ascii") + b"\"" if internal_date is not None else b""
    self._start_command(b"APPEND %s%s%s {%d}" % (self._encode_mailbox(mailbox_name), flags_b, date_b, len(data)))
    if not (await self._read_line()).startswith(b"+"):
      raise IMAPCommandFailedError("remote did not accept APPEND literal")
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
      if not (await self._read_line()).startswith(b"+"):
        raise RuntimeError("server didnt respond with + in idle!")
      while True:
        line = await self._read_line()
        if match_lineb(br"\* \d+ (EXISTS|EXPUNGE|FETCH).*", line):
          logging.debug("wait_for_update: '%s' got update: %s", mailbox_name, line.decode(errors="replace"))
          update_event.set()
    finally:
      self._writer.write(b"DONE\r\n")
      await self._read_until_response()
      logging.debug("wait_for_update: '%s' IDLE done", mailbox_name)

  async def _init(self):
    logging.debug("IMAP init: " + (await self._read_line()).decode())
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
    async for line in self._read_response_lines():
      if (m := match_lineb(rb'\* OK \[UIDVALIDITY (?P<v>\d+)\].*', line)) is not None:
        uid_validity = int(m["v"])
      elif (m := match_lineb(rb'\* OK \[UIDNEXT (?P<v>\d+)\].*', line)) is not None:
        uid_next = int(m["v"])
      elif (m := match_lineb(rb'\* (?P<v>\d+) EXISTS', line)) is not None:
        exists = int(m["v"])
      elif (m := match_lineb(rb'\* FLAGS \((?P<v>.*)\)', line)) is not None:
        flags_s = flags_to_s(m["v"])
      elif (m := match_lineb(rb'\* OK \[READ-ONLY\].*', line)) is not None:
        read_only = True
    return SelectResult(uid_validity=uid_validity, uid_next=uid_next, exists=exists, flags_s=flags_s, read_only=read_only)

  async def _command_authenticate(self, auth_type: bytes, auth_data: bytes):
    if (b"AUTH=%s" % (auth_type,)) not in self._capabilities:
      raise IMAPCommandFailedError(f"Auth type '{auth_type.decode()}' not supported!")
    self._start_command(b"AUTHENTICATE %s" % (auth_type,))
    if not (await self._read_line()).startswith(b"+"):
      await self._read_until_response()
      raise IMAPCommandFailedError("Invalid response from server!")
    self._writer.write(base64.b64encode(auth_data))
    self._writer.write(b"\r\n")
    await self._read_until_response()

  async def _command_login_backend(self, userid: str, password: str):
    self._start_command(b"LOGIN %s %s" % (imap_to_quoted_string(userid.encode()), imap_to_quoted_string(password.encode())))
    await self._read_until_response()

  async def _command_capabilities(self):
    self._start_command(b"CAPABILITY")
    capabilities: list[bytes] = []
    async for line in self._read_response_lines():
      if (capdict := match_lineb(rb"\* CAPABILITY (?P<caps>.*)", line)) is not None:
        capabilities.extend(capdict["caps"].split(b" "))
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

  async def _read_line(self):
    return (await self._reader.readuntil(b"\r\n"))[:-2]

  async def _read_until_response(self):
    async for _ in self._read_response_lines(): pass

  async def _read_response_lines(self):
    expected_tag = b"A%d " % (self._command_counter,)
    while not (line := await self._read_line()).startswith(expected_tag):
      while (m := re.search(rb'\{(\d+)\}$', line)) is not None:
        n = int(m.group(1))
        line = line + (await self._reader.readexactly(n)) + (await self._read_line())
      yield line
    code, message = line[len(expected_tag):].split(b" ", maxsplit=1)
    if code.upper() != b"OK":
      raise IMAPCommandFailedError(f"remote command failed: {code.decode()} {message.decode()}")

  @staticmethod
  async def open(config: Config, account: Account):
    ssl_param = ssl.create_default_context() if account.imap_tlsmode == TLSMode.DIRECT else None
    logging.debug("IMAP: connecting to %s:%d (tls=%s)", account.imap_host, account.imap_port, account.imap_tlsmode)
    reader, writer = await asyncio.open_connection(account.imap_host, account.imap_port, ssl=ssl_param)
    connection = IMAPRemoteConnection(config, account, reader, writer)
    await connection._init()
    return connection
