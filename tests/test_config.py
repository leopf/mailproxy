import pathlib, unittest
from mailproxy.config import config_from_dict, provider_config_from_dict


class TestConfigTls(unittest.TestCase):
  def _base(self) -> dict[str, object]:
    return {"domain": "example.com", "db_path": "test.sqlite"}

  def test_tls_defaults_to_none(self):
    config = config_from_dict(self._base())
    self.assertIsNone(config.tls_cert_path)
    self.assertIsNone(config.tls_key_path)

  def test_tls_cert_and_key_parsed(self):
    config = config_from_dict(self._base() | {"tls_cert_path": "cert.pem", "tls_key_path": "key.pem"})
    self.assertEqual(config.tls_cert_path, pathlib.Path("cert.pem"))
    self.assertEqual(config.tls_key_path, pathlib.Path("key.pem"))

  def test_tls_cert_without_key_rejected(self):
    with self.assertRaises(ValueError):
      _ = config_from_dict(self._base() | {"tls_cert_path": "cert.pem"})

  def test_tls_key_without_cert_rejected(self):
    with self.assertRaises(ValueError):
      _ = config_from_dict(self._base() | {"tls_key_path": "key.pem"})


class TestProviderConfig(unittest.TestCase):
  def _base(self) -> dict[str, object]:
    return {
      "imap_host": "imap.example.com", "imap_port": 993, "imap_tlsmode": "DIRECT",
      "smtp_host": "smtp.example.com", "smtp_port": 587, "smtp_tlsmode": "STARTTLS",
    }

  def test_use_pkce_defaults_to_false(self):
    self.assertFalse(provider_config_from_dict(self._base()).use_pkce)

  def test_use_pkce_parsed(self):
    self.assertTrue(provider_config_from_dict(self._base() | {"use_pkce": True}).use_pkce)


if __name__ == "__main__":
  _ = unittest.main()
