import asyncio, datetime, unittest
from typing import override
from mailproxy.imap_parsing import (
  IMAPReader, IMAPReadError,
  flags_to_s, flags_s_to_set, flags_set_to_s, flags_to_list_b, flags_to_b,
  parse_sequence_set,
  split_message, get_header, filter_headers, header_contains, body_contains, text_contains,
  parse_internal_date, format_internal_date, parse_search_date, list_match,
  imap_to_quoted_string,
)


class _MockStreamReader:
  _data: bytes
  _pos: int

  def __init__(self, data: bytes) -> None:
    self._data = data
    self._pos = 0

  def at_eof(self) -> bool:
    return self._pos >= len(self._data)

  async def read(self, n: int = -1) -> bytes:
    if self._pos >= len(self._data):
      return b""
    if n == -1:
      result = self._data[self._pos:]
    else:
      result = self._data[self._pos:self._pos + n]
    self._pos += len(result)
    return result


def _make_reader(data: bytes) -> IMAPReader:
  return IMAPReader(_MockStreamReader(data), pre_read=4)


class TestIMAPReaderPeek(unittest.TestCase):
  def test_peek_does_not_consume(self):
    r = _make_reader(b"ABC")
    self.assertEqual(asyncio.run(r.peek(2)), b"AB")
    self.assertEqual(asyncio.run(r.peek(2)), b"AB")

  def test_peek_past_end(self):
    r = _make_reader(b"A")
    self.assertEqual(asyncio.run(r.peek(5)), b"A")

  def test_peek_empty(self):
    r = _make_reader(b"")
    self.assertEqual(asyncio.run(r.peek(1)), b"")


class TestIMAPReaderReadConst(unittest.TestCase):
  def test_match(self):
    r = _make_reader(b"OK\r\n")
    asyncio.run(r.read_const(b"OK"))
    asyncio.run(r.read_crlf())

  def test_mismatch(self):
    r = _make_reader(b"NO")
    with self.assertRaises(IMAPReadError):
      asyncio.run(r.read_const(b"OK"))


class TestIMAPReaderReadAtom(unittest.TestCase):
  def test_simple(self):
    r = _make_reader(b"FETCH ")
    self.assertEqual(asyncio.run(r.read_atom()), b"FETCH")

  def test_stops_at_paren(self):
    r = _make_reader(b"FLAGS(blah)")
    self.assertEqual(asyncio.run(r.read_atom()), b"FLAGS")

  def test_stops_at_crlf(self):
    r = _make_reader(b"EXISTS\r\n")
    self.assertEqual(asyncio.run(r.read_atom()), b"EXISTS")

  def test_empty_raises(self):
    r = _make_reader(b" ")
    with self.assertRaises(IMAPReadError):
      _ = asyncio.run(r.read_atom())


class TestIMAPReaderReadNumber(unittest.TestCase):
  def test_simple(self):
    r = _make_reader(b"12345 ")
    self.assertEqual(asyncio.run(r.read_number()), 12345)

  def test_no_digits(self):
    r = _make_reader(b"abc")
    with self.assertRaises(IMAPReadError):
      _ = asyncio.run(r.read_number())


class TestIMAPReaderReadQuoted(unittest.TestCase):
  def test_simple(self):
    r = _make_reader(b'"hello world"')
    self.assertEqual(asyncio.run(r.read_quoted()), b"hello world")

  def test_escaped_quote(self):
    r = _make_reader(b'"hello \\"world\\""')
    self.assertEqual(asyncio.run(r.read_quoted()), b'hello "world"')

  def test_escaped_backslash(self):
    r = _make_reader(b'"a\\\\b"')
    self.assertEqual(asyncio.run(r.read_quoted()), b"a\\b")

  def test_empty(self):
    r = _make_reader(b'""')
    self.assertEqual(asyncio.run(r.read_quoted()), b"")


class TestIMAPReaderReadLiteral(unittest.TestCase):
  def test_simple(self):
    r = _make_reader(b"{5}\r\nhello")
    self.assertEqual(asyncio.run(r.read_literal()), b"hello")

  def test_with_spaces(self):
    r = _make_reader(b"{11}\r\nhello world")
    self.assertEqual(asyncio.run(r.read_literal()), b"hello world")

  def test_non_synchronizing(self):
    r = _make_reader(b"{5+}\r\nhello")
    self.assertEqual(asyncio.run(r.read_literal()), b"hello")

  def test_empty(self):
    r = _make_reader(b"{0}\r\n")
    self.assertEqual(asyncio.run(r.read_literal()), b"")


class TestIMAPReaderReadAstring(unittest.TestCase):
  def test_atom(self):
    r = _make_reader(b"INBOX ")
    self.assertEqual(asyncio.run(r.read_astring()), b"INBOX")

  def test_quoted(self):
    r = _make_reader(b'"hello world" ')
    self.assertEqual(asyncio.run(r.read_astring()), b"hello world")

  def test_literal(self):
    r = _make_reader(b"{5}\r\nhello ")
    self.assertEqual(asyncio.run(r.read_astring()), b"hello")

  def test_stops_at_paren(self):
    r = _make_reader(b"INBOX)")
    self.assertEqual(asyncio.run(r.read_astring()), b"INBOX")


class TestIMAPReaderReadNstring(unittest.TestCase):
  def test_nil(self):
    r = _make_reader(b"NIL ")
    self.assertIsNone(asyncio.run(r.read_nstring()))

  def test_nil_case_insensitive(self):
    r = _make_reader(b"nil ")
    self.assertIsNone(asyncio.run(r.read_nstring()))

  def test_quoted(self):
    r = _make_reader(b'"hello" ')
    self.assertEqual(asyncio.run(r.read_nstring()), b"hello")

  def test_literal(self):
    r = _make_reader(b"{5}\r\nworld ")
    self.assertEqual(asyncio.run(r.read_nstring()), b"world")

  def test_atom(self):
    r = _make_reader(b"INBOX ")
    self.assertEqual(asyncio.run(r.read_nstring()), b"INBOX")


class TestIMAPReaderReadToken(unittest.TestCase):
  def test_atom(self):
    r = _make_reader(b"UID ")
    self.assertEqual(asyncio.run(r.read_token()), b"UID")

  def test_quoted(self):
    r = _make_reader(b'"hello world" ')
    self.assertEqual(asyncio.run(r.read_token()), b'"hello world"')

  def test_literal(self):
    r = _make_reader(b"{5}\r\nhello ")
    result = asyncio.run(r.read_token())
    self.assertEqual(result, b"{5}\r\nhello")

  def test_paren_group(self):
    r = _make_reader(b"(\\Seen \\Flagged) ")
    self.assertEqual(asyncio.run(r.read_token()), b"(\\Seen \\Flagged)")

  def test_bracket_group(self):
    r = _make_reader(b"BODY[HEADER] ")
    self.assertEqual(asyncio.run(r.read_token()), b"BODY[HEADER]")

  def test_nested_groups(self):
    r = _make_reader(b"BODY[HEADER.FIELDS (From Subject)] ")
    self.assertEqual(asyncio.run(r.read_token()), b"BODY[HEADER.FIELDS (From Subject)]")

  def test_stops_at_close_paren_depth0(self):
    r = _make_reader(b"UID)")
    self.assertEqual(asyncio.run(r.read_token()), b"UID")


class TestIMAPReaderReadTextLine(unittest.TestCase):
  def test_simple(self):
    r = _make_reader(b"hello world\r\nnext")
    self.assertEqual(asyncio.run(r.read_text_line()), b"hello world")

  def test_empty(self):
    r = _make_reader(b"\r\n")
    self.assertEqual(asyncio.run(r.read_text_line()), b"")


class TestIMAPReaderReadUntil(unittest.TestCase):
  def test_simple(self):
    r = _make_reader(b"hello world")
    self.assertEqual(asyncio.run(r.read_until(b" ")), b"hello")

  def test_consumes_delimiter(self):
    r = _make_reader(b"a)b")
    self.assertEqual(asyncio.run(r.read_until(b")")), b"a")
    self.assertEqual(asyncio.run(r.peek(1)), b"b")

  def test_close_paren_consumed_then_crlf(self):
    r = _make_reader(b"UIDNEXT MESSAGES)\r\n")
    _ = asyncio.run(r.read_until(b")"))
    self.assertEqual(asyncio.run(r.peek(1)), b"\r")

  def test_close_bracket_consumed_then_sp(self):
    r = _make_reader(b"UIDVALIDITY 123] text\r\n")
    _ = asyncio.run(r.read_until(b"]"))
    self.assertEqual(asyncio.run(r.peek(1)), b" ")

  def test_multiple_read_until_in_sequence(self):
    r = _make_reader(b"1:5 +FLAGS (\\Seen)\r\n")
    self.assertEqual(asyncio.run(r.read_until(b" ")), b"1:5")
    self.assertEqual(asyncio.run(r.read_until(b" ")), b"+FLAGS")
    asyncio.run(r.read_const(b"("))
    self.assertEqual(asyncio.run(r.read_until(b")")), b"\\Seen")
    asyncio.run(r.read_crlf())


class TestIMAPReaderSkipSp(unittest.TestCase):
  def test_consume_one_sp(self):
    r = _make_reader(b"  hello")
    asyncio.run(r.skip_sp())
    self.assertEqual(asyncio.run(r.peek(1)), b" ")

  def test_no_sp_raises(self):
    r = _make_reader(b"hello")
    with self.assertRaises(IMAPReadError):
      asyncio.run(r.skip_sp())


class TestIMAPReaderSkipWsp(unittest.TestCase):
  def test_consume_run(self):
    r = _make_reader(b"   hello")
    asyncio.run(r.skip_wsp())
    self.assertEqual(asyncio.run(r.peek(1)), b"h")

  def test_none(self):
    r = _make_reader(b"hello")
    asyncio.run(r.skip_wsp())
    self.assertEqual(asyncio.run(r.peek(1)), b"h")


class TestIMAPReaderAtEof(unittest.TestCase):
  def test_not_eof_with_data(self):
    r = _make_reader(b"data")
    self.assertFalse(r.at_eof)

  def test_eof_empty(self):
    r = _make_reader(b"")
    self.assertTrue(r.at_eof)

  def test_eof_after_consume(self):
    r = _make_reader(b"AB")
    _ = asyncio.run(r.readexactly(2))
    self.assertTrue(r.at_eof)


class TestIMAPReaderStreamingFetchResponse(unittest.TestCase):
  """Verify IMAPReader can stream a complete FETCH response with a literal body."""

  def test_fetch_with_literal_body(self):
    body = b"From: x\r\nSubject: hello\r\n\r\nThis is the body"
    data = b"* 1 FETCH (UID 123 FLAGS (\\Seen) RFC822.SIZE %d BODY[] {%d}\r\n%s)\r\nA1 OK FETCH completed\r\n" % (len(body), len(body), body)
    r = _make_reader(data)

    self.assertEqual(asyncio.run(r.read_tag()), b"*")
    asyncio.run(r.skip_sp())
    self.assertEqual(asyncio.run(r.read_number()), 1)
    asyncio.run(r.skip_sp())
    kind = asyncio.run(r.read_atom())
    self.assertEqual(kind, b"FETCH")
    asyncio.run(r.skip_sp())
    asyncio.run(r.read_const(b"("))
    asyncio.run(r.skip_wsp())
    key = asyncio.run(r.read_token())
    self.assertEqual(key, b"UID")
    asyncio.run(r.skip_sp())
    self.assertEqual(asyncio.run(r.read_number()), 123)
    asyncio.run(r.skip_wsp())
    key = asyncio.run(r.read_token())
    self.assertEqual(key, b"FLAGS")
    asyncio.run(r.skip_sp())
    asyncio.run(r.read_const(b"("))
    flags = asyncio.run(r.read_until(b")"))
    self.assertEqual(flags, b"\\Seen")
    asyncio.run(r.skip_wsp())
    key = asyncio.run(r.read_token())
    self.assertEqual(key, b"RFC822.SIZE")
    asyncio.run(r.skip_sp())
    self.assertEqual(asyncio.run(r.read_number()), len(body))
    asyncio.run(r.skip_wsp())
    key = asyncio.run(r.read_token())
    self.assertEqual(key, b"BODY[]")
    asyncio.run(r.skip_sp())
    self.assertEqual(asyncio.run(r.read_literal()), body)
    asyncio.run(r.read_const(b")"))
    asyncio.run(r.read_crlf())

    tag = asyncio.run(r.read_atom())
    self.assertEqual(tag, b"A1")
    asyncio.run(r.skip_sp())
    self.assertEqual(asyncio.run(r.read_atom()), b"OK")
    _ = asyncio.run(r.read_text_line())


class TestIMAPReaderListResponse(unittest.TestCase):
  def test_list_with_quoted_name(self):
    data = b'* LIST (\\HasNoChildren) "/" "INBOX"\r\n'
    r = _make_reader(data)
    self.assertEqual(asyncio.run(r.read_tag()), b"*")
    asyncio.run(r.skip_sp())
    self.assertEqual(asyncio.run(r.read_atom()), b"LIST")
    asyncio.run(r.skip_sp())
    asyncio.run(r.read_const(b"("))
    flags = asyncio.run(r.read_until(b")"))
    self.assertEqual(flags, b"\\HasNoChildren")
    asyncio.run(r.skip_sp())
    delim = asyncio.run(r.read_quoted())
    self.assertEqual(delim, b"/")
    asyncio.run(r.skip_sp())
    name = asyncio.run(r.read_quoted())
    self.assertEqual(name, b"INBOX")
    asyncio.run(r.read_crlf())

  def test_list_with_literal_name(self):
    name = b"folder with spaces"
    data = b'* LIST (\\Noselect) NIL {%d}\r\n%s\r\n' % (len(name), name)
    r = _make_reader(data)
    self.assertEqual(asyncio.run(r.read_tag()), b"*")
    asyncio.run(r.skip_sp())
    self.assertEqual(asyncio.run(r.read_atom()), b"LIST")
    asyncio.run(r.skip_sp())
    asyncio.run(r.read_const(b"("))
    _ = asyncio.run(r.read_until(b")"))
    asyncio.run(r.skip_sp())
    delim = asyncio.run(r.read_nstring())
    self.assertIsNone(delim)
    asyncio.run(r.skip_sp())
    result = asyncio.run(r.read_astring())
    self.assertEqual(result, name)
    asyncio.run(r.read_crlf())


class TestIMAPReaderRespTextCode(unittest.TestCase):
  """Verify resp-text-code parsing: [code] text after OK/NO/BAD/BYE.

  Regression: read_until(b']') consumes ']', so no read_const(b']') after.
  """

  def test_resp_text_code_with_value(self):
    data = b"A1 OK [UIDVALIDITY 123] done\r\n"
    r = _make_reader(data)
    tag = asyncio.run(r.read_atom())
    self.assertEqual(tag, b"A1")
    asyncio.run(r.skip_sp())
    self.assertEqual(asyncio.run(r.read_atom()), b"OK")
    asyncio.run(r.skip_sp())
    asyncio.run(r.read_const(b"["))
    code = asyncio.run(r.read_until(b"]"))
    self.assertEqual(code, b"UIDVALIDITY 123")
    asyncio.run(r.skip_sp())
    text = asyncio.run(r.read_text_line())
    self.assertEqual(text, b"done")

  def test_resp_text_code_uidnext(self):
    data = b"A1 OK [UIDNEXT 456] completed\r\n"
    r = _make_reader(data)
    _ = asyncio.run(r.read_atom())
    asyncio.run(r.skip_sp())
    _ = asyncio.run(r.read_atom())
    asyncio.run(r.skip_sp())
    asyncio.run(r.read_const(b"["))
    code = asyncio.run(r.read_until(b"]"))
    self.assertEqual(code, b"UIDNEXT 456")

  def test_resp_text_code_readonly(self):
    data = b"A1 OK [READ-ONLY] Select completed\r\n"
    r = _make_reader(data)
    _ = asyncio.run(r.read_atom())
    asyncio.run(r.skip_sp())
    _ = asyncio.run(r.read_atom())
    asyncio.run(r.skip_sp())
    asyncio.run(r.read_const(b"["))
    code = asyncio.run(r.read_until(b"]"))
    self.assertEqual(code, b"READ-ONLY")
    asyncio.run(r.skip_sp())
    text = asyncio.run(r.read_text_line())
    self.assertEqual(text, b"Select completed")

  def test_no_resp_text_code(self):
    data = b"A1 OK done\r\n"
    r = _make_reader(data)
    _ = asyncio.run(r.read_atom())
    asyncio.run(r.skip_sp())
    _ = asyncio.run(r.read_atom())
    asyncio.run(r.skip_sp())
    text = asyncio.run(r.read_text_line())
    self.assertEqual(text, b"done")


class TestIMAPReaderStatusResponse(unittest.TestCase):
  """Verify STATUS response parsing: * STATUS mailbox (items).

  Regression: read_until(b')') consumes ')', so no read_const(b')') after.
  """

  def test_status_quoted_mailbox(self):
    data = b'* STATUS "INBOX" (MESSAGES 5 UNSEEN 2)\r\n'
    r = _make_reader(data)
    self.assertEqual(asyncio.run(r.read_tag()), b"*")
    asyncio.run(r.skip_sp())
    self.assertEqual(asyncio.run(r.read_atom()), b"STATUS")
    asyncio.run(r.skip_sp())
    self.assertEqual(asyncio.run(r.read_astring()), b"INBOX")
    asyncio.run(r.skip_sp())
    asyncio.run(r.read_const(b"("))
    items = asyncio.run(r.read_until(b")"))
    asyncio.run(r.read_crlf())
    self.assertEqual(items.strip(), b"MESSAGES 5 UNSEEN 2")

  def test_status_literal_mailbox(self):
    name = b"folder with spaces"
    data = b'* STATUS {%d}\r\n%s (MESSAGES 0)\r\n' % (len(name), name)
    r = _make_reader(data)
    self.assertEqual(asyncio.run(r.read_tag()), b"*")
    asyncio.run(r.skip_sp())
    self.assertEqual(asyncio.run(r.read_atom()), b"STATUS")
    asyncio.run(r.skip_sp())
    self.assertEqual(asyncio.run(r.read_astring()), name)
    asyncio.run(r.skip_sp())
    asyncio.run(r.read_const(b"("))
    items = asyncio.run(r.read_until(b")"))
    asyncio.run(r.read_crlf())
    self.assertEqual(items.strip(), b"MESSAGES 0")


class TestIMAPReaderStoreCommand(unittest.TestCase):
  """Verify STORE command parsing: UID STORE seq +FLAGS (flags).

  Regression: read_until(b')') consumes ')', so no read_const(b')') after.
  """

  def test_store_add_flags(self):
    data = b"1:5 +FLAGS (\\Seen \\Flagged)\r\n"
    r = _make_reader(data)
    self.assertEqual(asyncio.run(r.read_until(b" ")), b"1:5")
    self.assertEqual(asyncio.run(r.read_until(b" ")), b"+FLAGS")
    asyncio.run(r.read_const(b"("))
    flags = asyncio.run(r.read_until(b")"))
    asyncio.run(r.read_crlf())
    self.assertEqual(flags.strip(), b"\\Seen \\Flagged")

  def test_store_silent_flags(self):
    data = b"3:3 -FLAGS.SILENT (\\Seen)\r\n"
    r = _make_reader(data)
    self.assertEqual(asyncio.run(r.read_until(b" ")), b"3:3")
    self.assertEqual(asyncio.run(r.read_until(b" ")), b"-FLAGS.SILENT")
    asyncio.run(r.read_const(b"("))
    flags = asyncio.run(r.read_until(b")"))
    asyncio.run(r.read_crlf())
    self.assertEqual(flags.strip(), b"\\Seen")
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
  @override
  def setUp(self):
    self.data: bytes = b"From: sender@test\r\nSubject: Hello World\r\n\r\nThis is the body text"

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
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    self.assertEqual(dt.year, 2024)
    self.assertEqual(dt.month, 1)
    self.assertEqual(dt.day, 1)
    self.assertEqual(dt.hour, 12)

  def test_format_internal_date(self):
    formatted = format_internal_date(parse_internal_date(b"15-Mar-2024 10:30:00 +0000"))
    self.assertEqual(formatted, b"15-Mar-2024 10:30:00 +0000")

  def test_parse_search_date(self):
    ts = parse_search_date(b"01-Jan-2024")
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
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
  _ = unittest.main()
