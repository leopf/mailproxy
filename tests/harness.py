from mailproxy.imap_frontend import IMAPServerConnection
from mailproxy.model import Account, Config

from tests.fake_remote import FakeRemoteConnection
from tests.helpers import MemoryPipe


class IMAPHarness:
  """Runs a single IMAPServerConnection against an in-memory pipe and a fake
  remote. Feed client commands via ``cmd``/``pipe``, EOF via ``finish``, then
  ``await run()``. The remote can be injected per-test via ``remote``."""

  def __init__(self, config: Config, address: str = "test@example.com",
      remote: FakeRemoteConnection | None = None) -> None:
    self.config: Config = config
    self.address: str = address
    self.pipe: MemoryPipe = MemoryPipe()
    self.remote: FakeRemoteConnection | None = remote
    self.conn: IMAPServerConnection = IMAPServerConnection(
      config, self.pipe.reader, self.pipe.writer, remote_factory=self._factory)  # pyright: ignore[reportArgumentType]

  async def _factory(self, config: Config, account: Account) -> FakeRemoteConnection:
    if self.remote is None:
      self.remote = FakeRemoteConnection(config, account)
    return self.remote

  def login_cmd(self) -> None:
    self.pipe.feed(("A1 LOGIN %s pw\r\n" % self.address).encode())

  def login(self) -> None:
    self.login_cmd()

  def cmd(self, tag: str, line: str) -> None:
    self.pipe.feed(("%s %s\r\n" % (tag, line)).encode())

  def finish(self) -> None:
    self.pipe.feed_eof()

  async def run(self) -> None:
    await self.conn.run()

  def output(self) -> bytes:
    return self.pipe.output()
