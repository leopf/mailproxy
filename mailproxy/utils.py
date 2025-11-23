import re

def match_line(pattern: str, line: str, flags: int = re.I):
  m = re.fullmatch(pattern, line, flags)
  if m is None: return None
  else: return { "": "" } | m.groupdict()
