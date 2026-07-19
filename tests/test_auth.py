import logging, pathlib, sqlite3, tempfile, unittest, base64, hashlib, urllib.parse
from typing import override
from mailproxy.auth import authenticate, oauth_get_authorization_url, pkce_generate
from mailproxy.db import db_account_add, db_open
from mailproxy.model import Account, AuthenticationOAUTH2, AuthenticationPLAIN, Config, TLSMode

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
    self.config: Config = Config(
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


class TestPkce(unittest.TestCase):
  def _oauth_auth(self) -> AuthenticationOAUTH2:
    return AuthenticationOAUTH2(
      scope="mail-w", client_id="cid", client_secret=None,
      authorization_base_url="https://auth.example/authorize", token_url="https://auth.example/token",
      redirect_url="http://localhost:8081",
    )

  def test_verifier_challenge_pair(self):
    verifier, challenge = pkce_generate()
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    self.assertEqual(challenge, expected)
    self.assertGreaterEqual(len(verifier), 43)

  def test_authorization_url_with_pkce(self):
    url = oauth_get_authorization_url(self._oauth_auth(), "CHALLENGE")
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    self.assertEqual(qs["code_challenge"], ["CHALLENGE"])
    self.assertEqual(qs["code_challenge_method"], ["S256"])

  def test_authorization_url_with_state(self):
    url = oauth_get_authorization_url(self._oauth_auth(), state="STATE123")
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    self.assertEqual(qs["state"], ["STATE123"])

  def test_authorization_url_without_pkce(self):
    url = oauth_get_authorization_url(self._oauth_auth())
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    self.assertNotIn("code_challenge", qs)
    self.assertNotIn("code_challenge_method", qs)
    self.assertNotIn("state", qs)


if __name__ == "__main__":
  _ = unittest.main()
