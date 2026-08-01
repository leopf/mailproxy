import asyncio, pathlib, tempfile
from collections.abc import Iterable
from mailproxy.db import DatabaseSession
from mailproxy.model import Account, AuthenticationPLAIN, Config, TLSMode


class MemoryPipe:
  """Pair of an in-memory StreamReader and a fake StreamWriter, so tests drive
  the server coroutines without a real socket.

  Client bytes are fed via ``feed()``; everything the server writes is captured
  in ``written`` (a bytearray).
  """

  def __init__(self) -> None:
    self.reader: asyncio.StreamReader = asyncio.StreamReader()
    self.written: bytearray = bytearray()

  def feed(self, data: bytes) -> None:
    self.reader.feed_data(data)

  def feed_eof(self) -> None:
    self.reader.feed_eof()

  @property
  def writer(self) -> "MemoryWriter":
    return MemoryWriter(self.written)

  def output(self) -> bytes:
    return bytes(self.written)


class MemoryWriter:
  def __init__(self, buffer: bytearray) -> None:
    self._buf: bytearray = buffer
    self._closed: bool = False

  def write(self, data: bytes) -> None:
    if self._closed:
      raise BrokenPipeError("write on closed writer")
    self._buf.extend(data)

  def writelines(self, lines: Iterable[bytes]) -> None:
    for line in lines:
      self.write(line)

  async def drain(self) -> None:
    return None

  def close(self) -> None:
    self._closed = True

  def is_closing(self) -> bool:
    return self._closed

  def get_extra_info(self, _name: str, default: object | None = None) -> object | None:
    return default


class BidiPipe:
  """Bidirectional in-memory pair for a client<->server conversation.

  Side A (code under test) and side B (fake peer) connect to each other:
  - A reads what B wrote via ``a_reader``; A's writes go to ``a_writer``.
  - B reads A's writes via ``b_reader``; B's writes go to ``b_writer``.
  A's writes are automatically delivered to B's reader and vice versa.
  """

  def __init__(self) -> None:
    self._a_r: asyncio.StreamReader = asyncio.StreamReader()  # buffer of B's writes -> A reads
    self._b_r: asyncio.StreamReader = asyncio.StreamReader()  # buffer of A's writes -> B reads

  @property
  def a_reader(self) -> asyncio.StreamReader:
    return self._a_r

  @property
  def a_writer(self) -> "LinkedWriter":
    return LinkedWriter(self._b_r)

  @property
  def b_reader(self) -> asyncio.StreamReader:
    return self._b_r

  @property
  def b_writer(self) -> "LinkedWriter":
    return LinkedWriter(self._a_r)

  def feed_a(self, data: bytes) -> None:
    self._a_r.feed_data(data)

  def a_eof(self) -> None:
    self._a_r.feed_eof()

  def feed_b(self, data: bytes) -> None:
    self._b_r.feed_data(data)

  def b_eof(self) -> None:
    self._b_r.feed_eof()


class LinkedWriter:
  """A writer that delivers every write to a given StreamReader."""

  def __init__(self, target: asyncio.StreamReader) -> None:
    self._target: asyncio.StreamReader = target

  def write(self, data: bytes) -> None:
    self._target.feed_data(data)

  def writelines(self, lines: Iterable[bytes]) -> None:
    for line in lines:
      self.write(line)

  async def drain(self) -> None:
    return None

  def close(self) -> None:
    return None

  def is_closing(self) -> bool:
    return False

  def get_extra_info(self, _name: str, default: object | None = None) -> object | None:
    return default



def make_config(db_path: pathlib.Path | None = None, *, proxy_password: str = "pw") -> Config:
  return Config(
    domain="localhost",
    log_level=10,
    host="127.0.0.1",
    imap_port=0,
    smtp_port=0,
    db_path=db_path if db_path is not None else pathlib.Path(tempfile.mkdtemp()) / "test.sqlite",
    proxy_password=proxy_password,
  )


def make_account(address: str = "test@example.com") -> Account:
  return Account(
    addresses=(address,),
    imap_host="imap.example.com",
    imap_port=993,
    imap_tlsmode=TLSMode.DIRECT,
    smtp_host="smtp.example.com",
    smtp_port=465,
    smtp_tlsmode=TLSMode.DIRECT,
    auth=AuthenticationPLAIN(password="pw"),
  )


def seed_account(config: Config, address: str = "test@example.com") -> str:
  with DatabaseSession(config) as db:
    db.account_add(make_account(address))
  return address


def seed_mailbox(config: Config, account: str, name: str, *, is_remote: bool = True) -> int:
  with DatabaseSession(config) as db:
    return db.mailbox_add(account, name, 1, 1, is_remote=is_remote)


def seed_message(config: Config, mailbox_id: int, body: bytes) -> int:
  with DatabaseSession(config) as db:
    uid = db.mailbox_max_uid(mailbox_id) + 1
    db.message_add(uid, mailbox_id, 1700000000, "\\", body, str(uid))
    db.mailbox_update_sync(mailbox_id, uid_next=uid + 1, last_synced_uid=uid)
  return uid
