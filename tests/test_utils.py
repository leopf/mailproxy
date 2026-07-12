import unittest
from mailproxy.utils import match_line, match_lineb, encode_7bit_mailbox_name, decode_7bit_mailbox_name, is_str_object_dict, is_object_list, json_loads_object


class TestMatchLine(unittest.TestCase):
  def test_simple_match(self):
    result = match_line(r"OK \[(?P<code>[\w-]+)\]", "OK [READ-ONLY]")
    self.assertIsNotNone(result)
    self.assertEqual(result["code"], "READ-ONLY")

  def test_no_match(self):
    self.assertIsNone(match_line(r"OK", "NO"))

  def test_case_insensitive(self):
    self.assertIsNotNone(match_line(r"ok", "OK"))

  def test_case_sensitive(self):
    self.assertIsNone(match_line(r"ok", "OK", flags=0))

  def test_returns_empty_key(self):
    result = match_line(r"OK", "OK")
    self.assertIn("", result)


class TestMatchLineB(unittest.TestCase):
  def test_simple(self):
    result = match_lineb(rb"\* (?P<v>\d+) EXISTS", b"* 5 EXISTS")
    self.assertIsNotNone(result)
    self.assertEqual(result["v"], b"5")

  def test_no_match(self):
    self.assertIsNone(match_lineb(rb"EXISTS", b"* 5 EXPUNGE"))


class TestUtf7MailboxEncoding(unittest.TestCase):
  def test_ascii(self):
    self.assertEqual(encode_7bit_mailbox_name("INBOX"), "INBOX")

  def test_ampersand(self):
    self.assertEqual(encode_7bit_mailbox_name("A&B"), "A&-B")

  def test_non_ascii(self):
    self.assertEqual(encode_7bit_mailbox_name("Pruefung"), "Pruefung")

  def test_non_ascii_special(self):
    encoded = encode_7bit_mailbox_name("Pr\u00fcfung")
    self.assertEqual(encoded, "Pr&APw-fung")

  def test_round_trip_ascii(self):
    self.assertEqual(decode_7bit_mailbox_name(encode_7bit_mailbox_name("INBOX")), "INBOX")

  def test_round_trip_ampersand(self):
    self.assertEqual(decode_7bit_mailbox_name(encode_7bit_mailbox_name("A&B")), "A&B")

  def test_round_trip_umlaut(self):
    original = "Pr\u00fcfung"
    self.assertEqual(decode_7bit_mailbox_name(encode_7bit_mailbox_name(original)), original)

  def test_round_trip_hierarchy(self):
    original = "Testfolder/Unterordner"
    self.assertEqual(decode_7bit_mailbox_name(encode_7bit_mailbox_name(original)), original)

  def test_round_trip_multi_non_ascii(self):
    original = "\u00c4\u00d6\u00dc"
    self.assertEqual(decode_7bit_mailbox_name(encode_7bit_mailbox_name(original)), original)

  def test_round_trip_single_char(self):
    original = "\u00c4"
    self.assertEqual(decode_7bit_mailbox_name(encode_7bit_mailbox_name(original)), original)

  def test_decode_existing(self):
    self.assertEqual(decode_7bit_mailbox_name("Pr&APw-fung"), "Pr\u00fcfung")

  def test_decode_plain(self):
    self.assertEqual(decode_7bit_mailbox_name("INBOX"), "INBOX")

  def test_decode_ampersand(self):
    self.assertEqual(decode_7bit_mailbox_name("A&-B"), "A&B")


class TestTypeGuards(unittest.TestCase):
  def test_is_str_object_dict(self):
    self.assertTrue(is_str_object_dict({"a": 1}))
    self.assertFalse(is_str_object_dict({1: "a"}))
    self.assertFalse(is_str_object_dict([]))

  def test_is_object_list(self):
    self.assertTrue(is_object_list([1, 2]))
    self.assertFalse(is_object_list({}))

  def test_json_loads_object(self):
    result = json_loads_object('{"a": 1}')
    self.assertEqual(result, {"a": 1})


if __name__ == "__main__":
  unittest.main()
