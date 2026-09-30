import asyncio, grp, imaplib, logging, os, pathlib, pwd, shutil, signal, socket, subprocess, tempfile, typing, unittest
from typing import cast, override

from mailproxy.db import DatabaseSession
from mailproxy.imap_frontend import handle_imap
from mailproxy.model import Account, AuthenticationPLAIN, Config, TLSMode

DOVECOT = shutil.which("dovecot")


def _flatten(data: list[object]) -> bytes:
  out = bytearray()
  for item in data:
    if isinstance(item, tuple):
      for sub in cast(tuple[object, ...], item):
        if isinstance(sub, bytes):
          out += sub
    elif isinstance(item, bytes):
      out += item
  return bytes(out)


def _free_port() -> int:
  sock = socket.socket()
  sock.bind(("127.0.0.1", 0))
  port = cast(int, sock.getsockname()[1])
  sock.close()
  return port


def _dovecot_conf(base: pathlib.Path, port: int) -> str:
  user = pwd.getpwuid(os.getuid()).pw_name
  group = grp.getgrgid(os.getgid()).gr_name
  return f"""\
base_dir = {base}/run
state_dir = {base}/state
log_path = {base}/dovecot.log
ssl = no
protocols = imap
listen = 127.0.0.1
disable_plaintext_auth = no
auth_mechanisms = plain login
mail_location = maildir:{base}/mail/%u
default_internal_user = {user}
default_login_user = {user}
default_internal_group = {group}
passdb {{
  driver = static
  args = password=demopass
}}
userdb {{
  driver = static
  args = uid={os.getuid()} gid={os.getgid()} home={base}/home/%u
}}
service imap-login {{
  chroot =
  inet_listener imap {{
    port = {port}
  }}
}}
service anvil {{
  chroot =
}}
"""


@unittest.skipUnless(DOVECOT, "dovecot not on PATH (run inside nix-shell)")
class TestDovecotEndToEnd(unittest.IsolatedAsyncioTestCase):
  _ADDRESS: str = "user@example.com"

  @override
  async def asyncSetUp(self):
    assert DOVECOT is not None
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    base = pathlib.Path(self._tmpdir.name)
    self.config: Config = Config(
      domain="localhost", log_level=logging.CRITICAL, host="127.0.0.1",
      imap_port=0, smtp_port=0, db_path=base / "test.sqlite", proxy_password="pw",
    )
    self.dovecot_port: int = _free_port()
    _ = (base / "dovecot.conf").write_text(_dovecot_conf(base, self.dovecot_port))
    self._dovecot_log: typing.BinaryIO = (base / "dovecot-stdout.log").open("wb")
    self._dovecot: subprocess.Popen[bytes] = subprocess.Popen(
      [DOVECOT, "-F", "-c", str(base / "dovecot.conf")],
      stdout=self._dovecot_log, stderr=subprocess.STDOUT, start_new_session=True,
    )
    await self._wait_for_port(self.dovecot_port)
    await asyncio.to_thread(self._seed_remote_messages)
    account = Account(
      addresses=(self._ADDRESS,), imap_host="127.0.0.1", imap_port=self.dovecot_port,
      imap_tlsmode=TLSMode.NONE, smtp_host="127.0.0.1", smtp_port=0, smtp_tlsmode=TLSMode.NONE,
      auth=AuthenticationPLAIN(password="demopass"),
    )
    with DatabaseSession(self.config) as db:
      db.account_add(account)
    self._proxy: asyncio.Server = await asyncio.start_server(lambda r, w: handle_imap(self.config, r, w), "127.0.0.1", 0)
    assert self._proxy.sockets
    addr = cast(tuple[str, int], self._proxy.sockets[0].getsockname())
    self.proxy_port: int = addr[1]

  @override
  async def asyncTearDown(self):
    if getattr(self, "_proxy", None) is not None:
      self._proxy.close()
      await self._proxy.wait_closed()
    if getattr(self, "_dovecot", None) is not None:
      try:
        os.killpg(os.getpgid(self._dovecot.pid), signal.SIGKILL)
      except (ProcessLookupError, PermissionError):
        pass
      _ = self._dovecot.poll()
    if getattr(self, "_dovecot_log", None) is not None:
      self._dovecot_log.close()
    self._tmpdir.cleanup()

  async def _wait_for_port(self, port: int) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 10
    while loop.time() < deadline:
      try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.close()
        return
      except OSError:
        await asyncio.sleep(0.05)
    raise RuntimeError("dovecot did not start:\n" + self._read_dovecot_log())

  def _read_dovecot_log(self) -> str:
    log = pathlib.Path(self._tmpdir.name) / "dovecot.log"
    return log.read_text() if log.exists() else "(no dovecot log)"

  def _connect_remote(self) -> imaplib.IMAP4:
    imap = imaplib.IMAP4("127.0.0.1", self.dovecot_port)
    _ = imap.login(self._ADDRESS, "demopass")
    return imap

  def _seed_remote_messages(self) -> None:
    imap = self._connect_remote()
    _ = imap.append("INBOX", None, None, b"Subject: one\r\n\r\nbody one")
    _ = imap.append("INBOX", None, None, b"Subject: two\r\n\r\nbody two")
    _ = imap.logout()

  async def test_full_session_via_imaplib(self):
    await asyncio.to_thread(self._imaplib_full_session)

  def _imaplib_full_session(self) -> None:
    imap = imaplib.IMAP4("127.0.0.1", self.proxy_port)
    typ, data = imap.capability()
    self.assertEqual(typ, "OK")
    self.assertIn(b"IMAP4rev1", cast(bytes, data[0]))

    typ, _ = imap.login(self._ADDRESS, "pw")
    self.assertEqual(typ, "OK")

    typ, data = imap.list()
    self.assertEqual(typ, "OK")
    self.assertTrue(any(b"INBOX" in (d if isinstance(d, bytes) else b"") for d in data), data)

    typ, data = imap.select("INBOX")
    self.assertEqual(typ, "OK")
    self.assertEqual(int(cast(bytes, data[0])), 2)

    typ, data = imap.uid("SEARCH", "ALL")
    self.assertEqual(typ, "OK")
    self.assertEqual(len(cast(bytes, data[0]).split()), 2)

    typ, data = imap.uid("FETCH", "1:*", "(UID FLAGS INTERNALDATE BODY.PEEK[])")
    self.assertEqual(typ, "OK")
    self.assertIn(b"body one", _flatten(cast(list[object], data)))

    typ, _ = imap.uid("STORE", "1", "+FLAGS", "(\\Flagged)")
    self.assertEqual(typ, "OK")

    typ, _ = imap.noop()
    self.assertEqual(typ, "OK")

    typ, _ = imap.logout()
    self.assertEqual(typ, "BYE")

  async def test_idle_receives_new_message(self):
    reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
    _ = await reader.readuntil(b"\r\n")
    await self._send(writer, b"A1 LOGIN " + self._ADDRESS.encode() + b" pw")
    self.assertTrue((await self._read_until(reader, b"A1 "))[-1].startswith(b"A1 OK"))
    await self._send(writer, b"A2 SELECT INBOX")
    self.assertTrue((await self._read_until(reader, b"A2 "))[-1].startswith(b"A2 OK"))

    await self._send(writer, b"A3 IDLE")
    self.assertEqual((await reader.readuntil(b"\r\n")).rstrip(b"\r\n"), b"+ idling")

    await asyncio.to_thread(self._append_remote_message)

    line = await asyncio.wait_for(reader.readuntil(b"\r\n"), 10)
    while not line.rstrip(b"\r\n").endswith(b"EXISTS"):
      line = await asyncio.wait_for(reader.readuntil(b"\r\n"), 10)

    await self._send(writer, b"DONE")
    self.assertTrue((await self._read_until(reader, b"A3 "))[-1].startswith(b"A3 OK"))

    await self._send(writer, b"A4 NOOP")
    self.assertTrue((await self._read_until(reader, b"A4 "))[-1].startswith(b"A4 OK"))
    writer.close()

  def _append_remote_message(self) -> None:
    imap = self._connect_remote()
    _ = imap.append("INBOX", None, None, b"Subject: pushed\r\n\r\npushed body")
    _ = imap.logout()

  @staticmethod
  async def _send(writer: asyncio.StreamWriter, line: bytes) -> None:
    writer.write(line + b"\r\n")
    await writer.drain()

  @staticmethod
  async def _read_until(reader: asyncio.StreamReader, tag: bytes) -> list[bytes]:
    lines: list[bytes] = []
    while True:
      line = await asyncio.wait_for(reader.readuntil(b"\r\n"), 10)
      lines.append(line)
      if line.startswith(tag):
        return lines


if __name__ == "__main__":
  _ = unittest.main()
