import logging, pathlib, sqlite3, tempfile, unittest
from typing import override
from mailproxy.auth import authenticate
from mailproxy.db import db_account_add, db_open
from mailproxy.model import Account, AuthenticationPLAIN, Config, TLSMode

PASSWORD = "proxy-pw"


def _make_account(address: str) -> Account:
  return Account(
    addresses=(address,),
    imap_host="imap.example.com",
    imap_port=993,
    imap_tlsmode=TLSMode.DIRECT,
    smtp_host="smtp.example.com",
    smtp_port=465,
    smtp_tlsmode=TLSMode.DIRECT,
    auth=AuthenticationPLAIN(password="pass"),
  )


class TestAuthenticate(unittest.TestCase):
  @override
  def setUp(self):
    self._tmpdir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
    self.db_path: pathlib.Path = pathlib.Path(self._tmpdir.name) / "test.sqlite"
    self.db: sqlite3.Connection = db_open(self.db_path)
    self.config = Config(
      domain="example.com", log_level=logging.DEBUG, host="127.0.0.1",
      imap_port=143, smtp_port=587, db_path=self.db_path, proxy_password=PASSWORD,
    )

  @override
  def tearDown(self):
    self.db.close()
    self._tmpdir.cleanup()

  def test_matching_address(self):
    db_account_add(self.db, _make_account("a@example.com"))
    account = authenticate(self.config, self.db, b"a@example.com", PASSWORD.encode())
    self.assertIsNotNone(account)

  def test_unknown_username_rejected(self):
    db_account_add(self.db, _make_account("a@example.com"))
    self.assertIsNone(authenticate(self.config, self.db, b"anything", PASSWORD.encode()))

  def test_wrong_password_rejected(self):
    db_account_add(self.db, _make_account("a@example.com"))
    self.assertIsNone(authenticate(self.config, self.db, b"a@example.com", b"wrong"))
    self.assertIsNone(authenticate(self.config, self.db, b"anything", b"wrong"))

  def test_unknown_username_with_multiple_accounts(self):
    db_account_add(self.db, _make_account("a@example.com"))
    db_account_add(self.db, _make_account("b@example.com"))
    self.assertIsNone(authenticate(self.config, self.db, b"anything", PASSWORD.encode()))

  def test_address_selects_account_with_multiple_accounts(self):
    db_account_add(self.db, _make_account("a@example.com"))
    db_account_add(self.db, _make_account("b@example.com"))
    account = authenticate(self.config, self.db, b"b@example.com", PASSWORD.encode())
    assert account is not None
    self.assertEqual(account.key, "b@example.com")

  def test_no_proxy_password_rejects(self):
    db_account_add(self.db, _make_account("a@example.com"))
    config = Config(
      domain="example.com", log_level=logging.DEBUG, host="127.0.0.1",
      imap_port=143, smtp_port=587, db_path=self.db_path, proxy_password="",
    )
    self.assertIsNone(authenticate(config, self.db, b"a@example.com", b""))


if __name__ == "__main__":
  _ = unittest.main()
