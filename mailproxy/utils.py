import re

def match_line(pattern: str, line: str, flags: int = re.I) -> dict[str, str] | None:
  m = re.fullmatch(pattern, line, flags)
  if m is None: return None
  else: return { "": "" } | m.groupdict()

def match_lineb(pattern: bytes, line: bytes, flags: int = re.I) -> dict[str, bytes] | None:
  m = re.fullmatch(pattern, line, flags)
  if m is None: return None
  else: return { "": b"" } | m.groupdict()
