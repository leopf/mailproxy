import asyncio
from typing import Any, Callable, override
from mailproxy.imap_backend import IMAPRemoteConnection
from mailproxy.model import Account, Config
from .helpers import MemoryWriter


class _DummyReader(asyncio.StreamReader):
  def __init__(self) -> None:
    asyncio.StreamReader.__init__(self)
    self.feed_eof()


class FakeRemoteConnection(IMAPRemoteConnection):
  """A remote connection whose high-level operations are scripted.

  The socket is never used: every method the frontend invokes is logged in
  ``calls`` (as ``(name, *args)``) and any per-test ``behaviors[name]``
  callable is invoked instead of network I/O.
  """

  def __init__(self, config: Config, account: Account) -> None:
    super().__init__(config, account, _DummyReader(), MemoryWriter(bytearray()))  # pyright: ignore[reportArgumentType]
    self.calls: list[tuple[str, tuple[Any, ...]]] = []
    self.behaviors: dict[str, Callable[..., Any]] = {}

  def _record(self, name: str, *args) -> None:
    self.calls.append((name, args))
    behavior = self.behaviors.get(name)
    if behavior is not None:
      return behavior(*args)
    return None

  @override
  async def sync_mailbox(self, mailbox_name: str) -> None:
    sync_behavior = self.behaviors.get("sync_mailbox")
    if sync_behavior is not None:
      await sync_behavior(mailbox_name)
    self.calls.append(("sync_mailbox", (mailbox_name,)))

  @override
  async def sync_mailbox_list(self):
    self._record("sync_mailbox_list")

  @override
  async def wait_for_update(self, mailbox_name: str, update_event: asyncio.Event):
    self._record("wait_for_update", mailbox_name)
    update_event.set()

  @override
  async def shutdown(self):
    self._record("shutdown")

  @override
  async def uid_store(self, uid: int, op: bytes, flags_s: str):
    self._record("uid_store", uid, op, flags_s)

  @override
  async def uid_append(self, mailbox_name: str, flags_s: str, internal_date, data: bytes):
    self._record("uid_append", mailbox_name, flags_s, data)

  @override
  async def uid_expunge(self, uids: list[int], mailbox_name: str):
    self._record("uid_expunge", uids, mailbox_name)

  @override
  async def uid_copy(self, uids: list[int], dest_mailbox: str):
    self._record("uid_copy", uids, dest_mailbox)

  @override
  async def create_mailbox(self, mailbox_name: str):
    self._record("create_mailbox", mailbox_name)

  @override
  async def delete_mailbox(self, mailbox_name: str):
    self._record("delete_mailbox", mailbox_name)

  @override
  async def rename_mailbox(self, old_name: str, new_name: str):
    self._record("rename_mailbox", old_name, new_name)
