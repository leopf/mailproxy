import unittest
from mailproxy.imap_parsing import (
  flags_to_s, flags_s_to_set, flags_set_to_s, flags_to_list_b, flags_to_b,
  parse_sequence_set, split_fetch_items, parse_fetch_line, tokenize_search_criteria,
  split_message, get_header, filter_headers, header_contains, body_contains, text_contains,
  parse_internal_date, format_internal_date, parse_search_date, list_match,
  imap_to_quoted_string,
)


class TestFlagsToS(unittest.TestCase):
  def test_bytes_with_flags(self):
    self.assertEqual(flags_to_s(b"\\Seen \\Flagged"), "\\Seen\\Flagged\\")

  def test_bytes_single_flag(self):
    self.assertEqual(flags_to_s(b"\\Seen"), "\\Seen\\")

  def test_bytes_empty(self):
    self.assertEqual(flags_to_s(b""), "\\\\")

  def test_list_with_backslash_prefix(self):
    self.assertEqual(flags_to_s([b"\\Seen", b"\\Flagged"]), "\\Seen\\Flagged\\")

  def test_list_without_backslash_prefix(self):
    self.assertEqual(flags_to_s([b"Seen", b"Flagged"]), "\\Seen\\Flagged\\")

  def test_list_empty(self):
    self.assertEqual(flags_to_s([]), "\\\\")

  def test_list_single(self):
    self.assertEqual(flags_to_s([b"\\Seen"]), "\\Seen\\")

  def test_bytes_no_leading_backslash(self):
    self.assertEqual(flags_to_s(b"Seen"), "\\Seen\\")


class TestFlagsRoundTrip(unittest.TestCase):
  def test_set_to_s_to_set(self):
    self.assertEqual(flags_s_to_set(flags_set_to_s({"Seen", "Flagged"})), {"Seen", "Flagged"})

  def test_empty_set(self):
    self.assertEqual(flags_set_to_s(set()), "\\\\")
    self.assertEqual(flags_s_to_set("\\\\"), set())

  def test_single(self):
    self.assertEqual(flags_s_to_set("\\Seen\\"), {"Seen"})

  def test_list_b(self):
    self.assertEqual(flags_to_list_b("\\Seen\\Flagged\\"), [b"\\Seen", b"\\Flagged"])

  def test_list_b_empty(self):
    self.assertEqual(flags_to_list_b("\\\\"), [])

  def test_to_b(self):
    self.assertEqual(flags_to_b("\\Seen\\Flagged\\"), b"\\Seen \\Flagged")

  def test_to_b_empty(self):
    self.assertEqual(flags_to_b("\\\\"), b"")


class TestParseSequenceSet(unittest.TestCase):
  def test_single(self):
    self.assertEqual(parse_sequence_set(b"5", 10), [5])

  def test_range(self):
    self.assertEqual(parse_sequence_set(b"1:5", 10), [1, 2, 3, 4, 5])

  def test_list(self):
    self.assertEqual(parse_sequence_set(b"1,3,5", 10), [1, 3, 5])

  def test_mixed(self):
    self.assertEqual(parse_sequence_set(b"1:3,7,9:10", 10), [1, 2, 3, 7, 9, 10])

  def test_star(self):
    self.assertEqual(parse_sequence_set(b"*", 5), [5])

  def test_star_range(self):
    self.assertEqual(parse_sequence_set(b"2:*", 5), [2, 3, 4, 5])

  def test_reverse_range(self):
    self.assertEqual(parse_sequence_set(b"5:1", 10), [1, 2, 3, 4, 5])

  def test_out_of_range_clamped(self):
    self.assertEqual(parse_sequence_set(b"1:100", 10), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

  def test_dedup(self):
    self.assertEqual(parse_sequence_set(b"1:3,2:4", 10), [1, 2, 3, 4])

  def test_empty(self):
    self.assertEqual(parse_sequence_set(b"", 10), [])

  def test_whitespace(self):
    self.assertEqual(parse_sequence_set(b" 1 , 2 ", 10), [1, 2])


class TestSplitFetchItems(unittest.TestCase):
  def test_simple(self):
    self.assertEqual(split_fetch_items(b"UID 123 FLAGS (\\Seen)"), [b"UID", b"123", b"FLAGS", b"(\\Seen)"])

  def test_brackets(self):
    self.assertEqual(split_fetch_items(b"BODY[HEADER] {5}"), [b"BODY[HEADER]", b"{5}"])

  def test_literal_with_spaces(self):
    items = split_fetch_items(b'BODY[] {13}hello world!) UID 5')
    self.assertEqual(items, [b"BODY[]", b"{13}hello world!)", b"UID", b"5"])

  def test_literal_in_parens(self):
    items = split_fetch_items(b"FLAGS (\\Seen) BODY[] {5}abcde UID 1")
    self.assertEqual(items, [b"FLAGS", b"(\\Seen)", b"BODY[]", b"{5}abcde", b"UID", b"1"])

  def test_quoted_string(self):
    items = split_fetch_items(b'INTERNALDATE "01-Jan-2024 00:00:00 +0000" UID 1')
    self.assertEqual(items, [b'INTERNALDATE', b'"01-Jan-2024 00:00:00 +0000"', b"UID", b"1"])

  def test_empty(self):
    self.assertEqual(split_fetch_items(b""), [])


class TestParseFetchLine(unittest.TestCase):
  def test_full_with_body(self):
    line = b'* 1 FETCH (UID 123 FLAGS (\\Seen \\Flagged) INTERNALDATE "01-Jan-2024 12:00:00 +0000" RFC822.SIZE 567 BODY[] {11}hello world)'
    result = parse_fetch_line(line)
    self.assertIsNotNone(result)
    self.assertEqual(result[b"UID"], 123)
    self.assertEqual(result[b"FLAGS"], b"\\Seen \\Flagged")
    self.assertEqual(result[b"INTERNALDATE"], b"01-Jan-2024 12:00:00 +0000")
    self.assertEqual(result[b"RFC822.SIZE"], 567)
    self.assertEqual(result[b"BODY[]"], b"hello world")

  def test_without_body(self):
    line = b"* 1 FETCH (UID 456 FLAGS (\\Seen) RFC822.SIZE 100)"
    result = parse_fetch_line(line)
    self.assertIsNotNone(result)
    self.assertEqual(result[b"UID"], 456)
    self.assertEqual(result[b"FLAGS"], b"\\Seen")
    self.assertEqual(result[b"RFC822.SIZE"], 100)
    self.assertNotIn(b"BODY[]", result)

  def test_body_containing_fetch_like_content(self):
    line = b"* 2 FETCH (UID 456 BODY[] {21}FLAGS (\\Seen) UID 999)"
    result = parse_fetch_line(line)
    self.assertIsNotNone(result)
    self.assertEqual(result[b"UID"], 456)
    self.assertEqual(result[b"BODY[]"], b"FLAGS (\\Seen) UID 999")

  def test_no_match(self):
    self.assertIsNone(parse_fetch_line(b"* 1 EXISTS"))

  def test_empty_flags(self):
    line = b"* 1 FETCH (UID 1 FLAGS () RFC822.SIZE 0)"
    result = parse_fetch_line(line)
    self.assertIsNotNone(result)
    self.assertEqual(result[b"UID"], 1)
    self.assertEqual(result[b"FLAGS"], b"")


class TestTokenizeSearchCriteria(unittest.TestCase):
  def test_simple(self):
    self.assertEqual(tokenize_search_criteria(b"SUBJECT hello"), [b"SUBJECT", b"hello"])

  def test_quoted(self):
    self.assertEqual(tokenize_search_criteria(b'SUBJECT "hello world"'), [b"SUBJECT", b"hello world"])

  def test_multiple(self):
    self.assertEqual(tokenize_search_criteria(b"UNSEEN FROM x"), [b"UNSEEN", b"FROM", b"x"])

  def test_escaped_quote(self):
    tokens = tokenize_search_criteria(b'SUBJECT "hello \\"world\\""')
    self.assertEqual(tokens, [b"SUBJECT", b'hello "world"'])

  def test_extra_whitespace(self):
    self.assertEqual(tokenize_search_criteria(b"  ALL  "), [b"ALL"])

  def test_empty(self):
    self.assertEqual(tokenize_search_criteria(b""), [])


class TestSplitMessage(unittest.TestCase):
  def test_crlf(self):
    header = b"From: x\r\nSubject: y"
    body = b"body text"
    self.assertEqual(split_message(header + b"\r\n\r\n" + body), (header, body))

  def test_lf_only(self):
    header = b"From: x\nSubject: y"
    body = b"body"
    self.assertEqual(split_message(header + b"\n\n" + body), (header, body))

  def test_no_body(self):
    self.assertEqual(split_message(b"From: x\r\nSubject: y"), (b"From: x\r\nSubject: y", b""))

  def test_prefers_crlf(self):
    header = b"From: x"
    body = b"\n\n body"
    self.assertEqual(split_message(header + b"\r\n\r\n" + body), (header, body))


class TestGetHeader(unittest.TestCase):
  def test_simple(self):
    data = b"From: sender@test\r\nSubject: test\r\n\r\nbody"
    self.assertEqual(get_header(data, "From"), b"sender@test")

  def test_case_insensitive(self):
    data = b"from: sender@test\r\n\r\nbody"
    self.assertEqual(get_header(data, "From"), b"sender@test")

  def test_folded(self):
    data = b"Subject: hello\r\n world\r\n\r\nbody"
    self.assertEqual(get_header(data, "Subject"), b"hello world")

  def test_missing(self):
    data = b"From: x\r\n\r\nbody"
    self.assertEqual(get_header(data, "Subject"), b"")

  def test_not_header_section(self):
    data = b"From: x\r\n\r\nSubject: should-not-match"
    self.assertEqual(get_header(data, "Subject"), b"")


class TestFilterHeaders(unittest.TestCase):
  def test_single(self):
    data = b"From: a\r\nSubject: b\r\n\r\nbody"
    self.assertEqual(filter_headers(data, [b"From"]), b"From: a\r\n")

  def test_multiple(self):
    data = b"From: a\r\nSubject: b\r\nX-Custom: c\r\n\r\nbody"
    result = filter_headers(data, [b"From", b"X-Custom"])
    self.assertIn(b"From: a", result)
    self.assertIn(b"X-Custom: c", result)
    self.assertNotIn(b"Subject", result)

  def test_folded(self):
    data = b"Subject: hello\r\n world\r\nFrom: a\r\n\r\nbody"
    result = filter_headers(data, [b"Subject"])
    self.assertEqual(result, b"Subject: hello\r\n world\r\n")

  def test_none_match(self):
    self.assertEqual(filter_headers(b"From: a\r\n\r\nbody", [b"Subject"]), b"")


class TestSearchHelpers(unittest.TestCase):
  def setUp(self):
    self.data = b"From: sender@test\r\nSubject: Hello World\r\n\r\nThis is the body text"

  def test_header_contains(self):
    self.assertTrue(header_contains(self.data, "Subject", b"hello"))
    self.assertFalse(header_contains(self.data, "Subject", b"goodbye"))

  def test_body_contains(self):
    self.assertTrue(body_contains(self.data, b"body"))
    self.assertFalse(body_contains(self.data, b"sender"))

  def test_text_contains(self):
    self.assertTrue(text_contains(self.data, b"sender"))
    self.assertTrue(text_contains(self.data, b"body"))
    self.assertFalse(text_contains(self.data, b"missing"))


class TestDates(unittest.TestCase):
  def test_parse_internal_date(self):
    ts = parse_internal_date(b"01-Jan-2024 12:00:00 +0000")
    dt = __import__("datetime").datetime.fromtimestamp(ts, tz=__import__("datetime").timezone.utc)
    self.assertEqual(dt.year, 2024)
    self.assertEqual(dt.month, 1)
    self.assertEqual(dt.day, 1)
    self.assertEqual(dt.hour, 12)

  def test_format_internal_date(self):
    formatted = format_internal_date(parse_internal_date(b"15-Mar-2024 10:30:00 +0000"))
    self.assertEqual(formatted, b"15-Mar-2024 10:30:00 +0000")

  def test_parse_search_date(self):
    ts = parse_search_date(b"01-Jan-2024")
    dt = __import__("datetime").datetime.fromtimestamp(ts, tz=__import__("datetime").timezone.utc)
    self.assertEqual(dt.year, 2024)
    self.assertEqual(dt.month, 1)
    self.assertEqual(dt.day, 1)


class TestListMatch(unittest.TestCase):
  def test_star(self):
    self.assertTrue(list_match("INBOX", "*"))
    self.assertTrue(list_match("INBOX/Sent", "*"))

  def test_percent_no_hierarchy(self):
    self.assertTrue(list_match("INBOX", "%"))
    self.assertFalse(list_match("INBOX/Sent", "%"))

  def test_percent_matches_hierarchy(self):
    self.assertTrue(list_match("INBOX/Sent", "INBOX/%"))

  def test_exact(self):
    self.assertTrue(list_match("INBOX", "INBOX"))
    self.assertFalse(list_match("INBOX", "INBOX2"))


class TestImapToQuotedString(unittest.TestCase):
  def test_simple(self):
    self.assertEqual(imap_to_quoted_string(b"hello"), b'"hello"')

  def test_with_quote(self):
    self.assertEqual(imap_to_quoted_string(b'he"llo'), b'"he\\"llo"')

  def test_empty(self):
    self.assertEqual(imap_to_quoted_string(b""), b'""')


if __name__ == "__main__":
  unittest.main()
