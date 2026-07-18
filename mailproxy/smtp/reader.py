from mailproxy.reader import ReadError, ScopedReader


class SMTPReader(ScopedReader):

  async def read_ci_const(self, expected: bytes) -> bytes:
    result = await self.readexactly(len(expected))
    if result.upper() != expected.upper():
      raise ReadError(f"expected {expected!r} (case-insensitive), got {result!r}")
    return result

  async def read_data_body(self) -> bytes:
    accumulated = bytearray()
    while True:
      line = await self.read_until(b"\r\n")
      if line == b".":
        return bytes(accumulated)
      if line.startswith(b".."):
        line = line[1:]
      accumulated.extend(line)
      accumulated.extend(b"\r\n")

  async def read_response(self) -> tuple[int, str]:
    texts: list[str] = []
    code = 0
    while True:
      code_b = await self.readexactly(3)
      sep = await self.readexactly(1)
      text = await self.read_text_line()
      try:
        code = int(code_b)
      except ValueError:
        raise ReadError(f"invalid SMTP code {code_b!r}")
      texts.append(text.decode("ascii", errors="replace"))
      if sep != b"-":
        return code, "\n".join(texts)
