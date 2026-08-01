import asyncio, logging, pathlib, re, tempfile, typing, unittest
from typing import override
from mailproxy import imap_backend
from mailproxy.db import DatabaseSession
from mailproxy.imap_backend import IMAPRemoteConnection
from mailproxy.model import Account, AuthenticationPLAIN, Config, TLSMode


def _make_account(port: int) -> Account:
  return Account(
    addresses=("test@example.com",),
    imap_host="127.0.0.1",
    imap_port=port,
    imap_tlsmode=TLSMode.NONE,
    smtp_host="127.0.0.1",
    smtp_port=25,
    smtp_tlsmode=TLSMode.NONE,
    auth=AuthenticationPLAIN(password="pw"),
  )


class _FakeIMAPServer:
  """Minimal fake remote IMAP server. Can drop the connection mid UID FETCH
  to simulate a timeout (drop_on_fetch = 1-based UID FETCH command index)."""

  def __init__(self, messages: dict[int, bytes], drop_on_fetch: int | None = None, drop_after_items: int = 0, idle_delay: float = 0):
    self._messages: dict[int, bytes] = messages
    self._drop_on_fetch: int | None = drop_on_fetch
    self._drop_after_items: int = drop_after_items
    self._idle_delay: float = idle_delay
    self._server: asyncio.Server | None = None
    self._body_fetch_count: int = 0

  @property
  def port(self) -> int:
    assert self._server is not None and self._server.sockets
    addr = typing.cast(tuple[str, int], self._server.sockets[0].getsockname())
    return addr[1]

  @property
  def body_fetch_count(self) -> int:
    return self._body_fetch_count

  async def start(self):
    self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)

  async def stop(self):
    assert self._server is not None
    self._server.close()
    await self._server.wait_closed()

  async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    fetch_cmd_count = 0
    try:
      writer.write(b"* OK fake ready\r\n")
      await writer.drain()
      while True:
        line = await reader.readuntil(b"\r\n")
        tag, _, rest = line[:-2].partition(b" ")
        cmd, _, args = rest.partition(b" ")
        cmd = cmd.upper()
        if cmd == b"CAPABILITY":
          writer.write(b"* CAPABILITY IMAP4rev1\r\n" + tag + b" OK\r\n")
        elif cmd == b"LOGIN":
          writer.write(tag + b" OK\r\n")
        elif cmd == b"LIST":
          writer.write(b'* LIST () "/" INBOX\r\n' + tag + b" OK\r\n")
        elif cmd == b"SELECT":
          writer.write(b"* FLAGS (\\Seen \\Answered)\r\n")
          writer.write(b"* %d EXISTS\r\n" % len(self._messages))
          writer.write(b"* OK [UIDVALIDITY 1]\r\n")
          writer.write(b"* OK [UIDNEXT %d]\r\n" % (max(self._messages) + 1 if self._messages else 1))
          writer.write(tag + b" OK [READ-WRITE]\r\n")
        elif cmd == b"UID" and args.upper().startswith(b"SEARCH UID "):
          m = re.match(rb"SEARCH UID (\d+):(\*)", args, re.I)
          assert m is not None
          min_uid = int(m.group(1))
          uids = [u for u in sorted(self._messages) if u >= min_uid]
          writer.write(b"* SEARCH %s\r\n" % (b" ".join(b"%d" % u for u in uids),))
          writer.write(tag + b" OK SEARCH completed\r\n")
        elif cmd == b"UID" and args.upper().startswith(b"FETCH"):
          fetch_cmd_count += 1
          m = re.match(rb"FETCH (\d+):(\d+)", args, re.I)
          if m is not None:
            lo, hi = int(m.group(1)), int(m.group(2))
            uids = [u for u in sorted(self._messages) if lo <= u <= hi]
          else:
            m2 = re.match(rb"FETCH ([0-9,]+)", args, re.I)
            assert m2 is not None
            want = set(int(x) for x in m2.group(1).split(b","))
            uids = [u for u in sorted(self._messages) if u in want]
          with_body = b"BODY" in args.upper()
          if self._drop_on_fetch is not None and fetch_cmd_count == self._drop_on_fetch:
            uids = uids[:self._drop_after_items]
            for u in uids:
              writer.write(self._fetch_item(u, with_body))
              if with_body: self._body_fetch_count += 1
            await writer.drain()
            break
          for u in uids:
            writer.write(self._fetch_item(u, with_body))
            if with_body: self._body_fetch_count += 1
          writer.write(tag + b" OK\r\n")
        elif cmd == b"IDLE":
          if self._idle_delay:
            await asyncio.sleep(self._idle_delay)
          writer.write(b"+ idling\r\n")
          await writer.drain()
          while True:
            idle_line = await reader.readuntil(b"\r\n")
            if idle_line.strip().upper() == b"DONE":
              writer.write(tag + b" OK IDLE terminated\r\n")
              await writer.drain()
              break
        elif cmd == b"LOGOUT":
          writer.write(tag + b" OK\r\n")
          await writer.drain()
          break
        else:
          writer.write(tag + b" BAD\r\n")
        await writer.drain()
    except Exception:
      pass
    finally:
      try: writer.close()
      except Exception: pass

  def _fetch_item(self, uid: int, with_body: bool) -> bytes:
    seq = sorted(self._messages).index(uid) + 1
    if with_body:
      body = self._messages[uid]
      return b'* %d FETCH (UID %d FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000" BODY[] {%d}\r\n%s)\r\n' % (seq, uid, len(body), body)
    return b'* %d FETCH (UID %d FLAGS (\\Seen))\r\n' % (seq, uid)


class TestSync(unittest.IsolatedAsyncioTestCase):
  @override
  def setUp(self):
    self._orig_batch_size: int = imap_backend.FETCH_BATCH_SIZE
    imap_backend.FETCH_BATCH_SIZE = 50
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
    self.config: Config = Config(
      domain="localhost", log_level=logging.CRITICAL, host="127.0.0.1",
      imap_port=0, smtp_port=0, db_path=pathlib.Path(self._tmpdir.name) / "test.sqlite",
    )
    with DatabaseSession(self.config) as db:
      db.account_add(_make_account(0))
    self._servers: list[_FakeIMAPServer] = []

  @override
  def tearDown(self):
    imap_backend.FETCH_BATCH_SIZE = self._orig_batch_size
    self._tmpdir.cleanup()

  @override
  async def asyncTearDown(self):
    for server in self._servers:
      await server.stop()

  async def _start_server(self, messages: dict[int, bytes], drop_on_fetch: int | None = None, drop_after_items: int = 0, idle_delay: float = 0) -> _FakeIMAPServer:
    server = _FakeIMAPServer(messages, drop_on_fetch, drop_after_items, idle_delay)
    await server.start()
    self._servers.append(server)
    return server

  def _last_synced_uid(self) -> int:
    with DatabaseSession(self.config) as db:
      mailbox = db.mailbox_by_name("test@example.com", "INBOX")
      assert mailbox is not None
      return mailbox.last_synced_uid

  def _message_count(self) -> int:
    with DatabaseSession(self.config) as db:
      mailbox = db.mailbox_by_name("test@example.com", "INBOX")
      assert mailbox is not None
      return len(list(db.message_list(mailbox.id)))

  async def test_batched_full_sync(self):
    messages = {u: b"Subject: msg %d\r\n\r\nbody %d" % (u, u) for u in range(1, 121)}
    server = await self._start_server(messages)
    conn = await IMAPRemoteConnection.open(self.config, _make_account(server.port))
    await conn.sync_mailbox("INBOX")
    await conn.shutdown()
    self.assertEqual(self._message_count(), 120)
    self.assertEqual(self._last_synced_uid(), 120)
    with DatabaseSession(self.config) as db:
      mailbox = db.mailbox_by_name("test@example.com", "INBOX")
      assert mailbox is not None
      msg = db.message_get_by_uid(mailbox.id, 77)
      assert msg is not None
      self.assertEqual(db.message_body_get(msg.body_hash), messages[77])
      self.assertEqual(msg.size, len(messages[77]))

  async def test_sync_resumes_after_connection_drop(self):
    messages = {u: b"Subject: msg %d\r\n\r\nbody %d" % (u, u) for u in range(1, 121)}
    server1 = await self._start_server(messages, drop_on_fetch=2, drop_after_items=30)
    conn = await IMAPRemoteConnection.open(self.config, _make_account(server1.port))
    with self.assertRaises(Exception):
      await conn.sync_mailbox("INBOX")
    await conn.shutdown()
    # Per-message commits + per-message pointer: the 30 messages written before
    # the drop survive and the sync pointer reflects the last stored uid.
    self.assertEqual(self._last_synced_uid(), 80)
    self.assertEqual(self._message_count(), 80)

    server2 = await self._start_server(messages)
    conn2 = await IMAPRemoteConnection.open(self.config, _make_account(server2.port))
    await conn2.sync_mailbox("INBOX")
    await conn2.shutdown()
    self.assertEqual(self._last_synced_uid(), 120)
    self.assertEqual(self._message_count(), 120)

  async def test_sparse_uids_no_infinite_loop(self):
    messages = {1: b"one", 2: b"two", 1000: b"thousand"}
    server = await self._start_server(messages)
    conn = await IMAPRemoteConnection.open(self.config, _make_account(server.port))
    await asyncio.wait_for(conn.sync_mailbox("INBOX"), timeout=10)
    await conn.shutdown()
    self.assertEqual(self._message_count(), 3)
    self.assertEqual(self._last_synced_uid(), 1000)
    self.assertEqual(server.body_fetch_count, 3)

  async def test_concurrent_sync_serializes_and_avoids_duplicate_fetch(self):
    messages = {u: b"Subject: msg %d\r\n\r\nbody %d" % (u, u) for u in range(1, 121)}
    server = await self._start_server(messages)
    account = _make_account(server.port)
    conn1 = await IMAPRemoteConnection.open(self.config, account)
    conn2 = await IMAPRemoteConnection.open(self.config, account)
    _ = await asyncio.gather(conn1.sync_mailbox("INBOX"), conn2.sync_mailbox("INBOX"))
    await conn1.shutdown()
    await conn2.shutdown()
    self.assertEqual(self._message_count(), 120)
    self.assertEqual(self._last_synced_uid(), 120)
    self.assertEqual(server.body_fetch_count, 120)

  async def test_idle_cancellation_during_plus_wait_recovers(self):
    messages = {1: b"one"}
    server = await self._start_server(messages, idle_delay=1.0)
    conn = await IMAPRemoteConnection.open(self.config, _make_account(server.port))
    update_event = asyncio.Event()
    task = asyncio.create_task(conn.wait_for_update("INBOX", update_event))
    await asyncio.sleep(0.2)
    _ = task.cancel()
    with self.assertRaises(asyncio.CancelledError):
      await task
    await conn.sync_mailbox("INBOX")
    await conn.shutdown()
    self.assertEqual(self._message_count(), 1)



if __name__ == "__main__":
  _ = unittest.main()
