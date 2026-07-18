import asyncio, importlib.resources, logging, re, ssl
from mailproxy.db import db_open
from mailproxy.auth import authenticate_sasl
from mailproxy.model import Account, Config
from mailproxy.reader import ReadError
from mailproxy.smtp.backend import smtp_forward_mail
from mailproxy.smtp.reader import SMTPReader


class SMTPServerSession:
  _config: Config
  _reader: SMTPReader
  _writer: asyncio.StreamWriter
  _account: Account | None
  _sender: str
  _recipients: list[str]
  _tls_active: bool
  _done: bool

  def __init__(self, config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    self._config = config
    self._reader = SMTPReader(reader)
    self._writer = writer
    self._account = None
    self._sender = ""
    self._recipients = []
    self._tls_active = False
    self._done = False

  def _write_line(self, line: str) -> None:
    self._writer.write(line.encode("ascii"))
    self._writer.write(b"\r\n")

  def _reply(self, code: int, text: str) -> None:
    if text and not re.fullmatch(r'[\t\x20-\x7E]+', text):
      raise ValueError("Invalid reply!")
    self._write_line(f"{code} {text}")

  async def run(self) -> None:
    logging.debug("SMTP frontend: client connected")
    self._reply(220, f"{self._config.domain} Ready")
    try:
      while not self._reader.at_eof and not self._done:
        try:
          await self._reader.handle_options([
            lambda: self._h_quit(),
            lambda: self._h_helo(),
            lambda: self._h_ehlo(),
            lambda: self._h_noop(),
            lambda: self._h_rset(),
            lambda: self._h_auth(),
            lambda: self._h_mail(),
            lambda: self._h_rcpt(),
            lambda: self._h_data(),
            lambda: self._h_vrfy(),
            lambda: self._h_starttls(),
          ])
        except ReadError:
          _ = await self._reader.read_text_line()
          self._reply(500, "unknown")
        except asyncio.IncompleteReadError:
          break
    except Exception as e:
      logging.error("connection closing because of an error: %s", e)
    finally:
      logging.debug("SMTP frontend: connection closed")
      self._writer.close()

  async def _h_quit(self) -> None:
    _ = await self._reader.read_ci_const(b"QUIT")
    await self._reader.read_crlf()
    self._reply(221, f"{self._config.domain} closing transmission channel")
    self._done = True

  async def _h_helo(self) -> None:
    _ = await self._reader.read_ci_const(b"HELO")
    _ = await self._reader.read_const(b" ")
    domain = await self._reader.read_text_line()
    logging.debug("HELO from domain: %s", domain.decode(errors="replace"))
    self._reply(250, self._config.domain)

  async def _h_ehlo(self) -> None:
    _ = await self._reader.read_ci_const(b"EHLO")
    _ = await self._reader.read_const(b" ")
    domain = await self._reader.read_text_line()
    logging.debug("EHLO from domain: %s", domain.decode(errors="replace"))
    self._write_line(f"250-{self._config.domain} hello")
    features = "AUTH PLAIN"
    if not self._tls_active: features += " STARTTLS"
    self._write_line(f"250 {features}")

  async def _h_noop(self) -> None:
    _ = await self._reader.read_ci_const(b"NOOP")
    _ = await self._reader.read_text_line()
    self._reply(250, "OK")

  async def _h_rset(self) -> None:
    _ = await self._reader.read_ci_const(b"RSET")
    await self._reader.read_crlf()
    logging.debug("resetting connection")
    self._sender = ""
    self._recipients.clear()
    self._reply(250, "OK")

  async def _h_auth(self) -> None:
    _ = await self._reader.read_ci_const(b"AUTH")
    _ = await self._reader.read_const(b" ")
    auth_type = (await self._reader.read_re(br"[^ \r]*")).upper()
    if auth_type != b"PLAIN":
      await self._reader.read_crlf()
      self._reply(504, "only PLAIN auth supported")
      return
    auth_data = await self._reader.read_one_of(self._auth_inline, self._auth_twoline)
    with db_open(self._config.db_path) as db:
      self._account = authenticate_sasl(self._config, db, auth_data)
    if self._account is None:
      logging.debug("SMTP AUTH PLAIN failed")
      self._reply(535, "5.7.8  Authentication credentials invalid")
    else:
      logging.debug("SMTP AUTH PLAIN success for %s", self._account.key)
      self._reply(235, "2.7.0  Authentication Succeeded")

  async def _auth_inline(self) -> bytes:
    _ = await self._reader.read_const(b" ")
    return await self._reader.read_text_line()

  async def _auth_twoline(self) -> bytes:
    await self._reader.read_crlf()
    self._reply(334, "")
    return await self._reader.read_text_line()

  async def _h_mail(self) -> None:
    _ = await self._reader.read_ci_const(b"MAIL")
    _ = await self._reader.read_const(b" ")
    _ = await self._reader.read_ci_const(b"FROM:")
    await self._reader.skip_re(br" *")
    _ = await self._reader.read_const(b"<")
    mailbox = await self._reader.read_until(b">")
    _ = await self._reader.read_text_line()
    if self._account is None:
      self._reply(550, "not authenticated")
      return
    logging.debug("MAIL FROM: %s", mailbox.decode(errors="replace"))
    self._sender = mailbox.decode("utf-8", errors="replace")
    self._recipients.clear()
    self._reply(250, "OK")

  async def _h_rcpt(self) -> None:
    _ = await self._reader.read_ci_const(b"RCPT")
    _ = await self._reader.read_const(b" ")
    _ = await self._reader.read_ci_const(b"TO:")
    await self._reader.skip_re(br" *")
    _ = await self._reader.read_const(b"<")
    mailbox = await self._reader.read_until(b">")
    _ = await self._reader.read_text_line()
    if self._account is None:
      self._reply(550, "not authenticated")
      return
    logging.debug("RCPT TO: %s", mailbox.decode(errors="replace"))
    self._recipients.append(mailbox.decode("utf-8", errors="replace"))
    self._reply(250, "OK")

  async def _h_data(self) -> None:
    _ = await self._reader.read_ci_const(b"DATA")
    await self._reader.read_crlf()
    if self._account is None:
      self._reply(503, "not authenticated")
      return
    self._reply(354, "Start mail input; end with <CRLF>.<CRLF>")
    mail_data = await self._reader.read_data_body()
    try:
      await smtp_forward_mail(self._config.db_path, self._account, self._sender, tuple(self._recipients), mail_data)
      self._reply(250, "OK")
    except Exception as e:
      logging.error("failed to send message: %s", e)
      self._reply(451, "local error in processing")
    finally:
      self._sender = ""
      self._recipients.clear()

  async def _h_vrfy(self) -> None:
    _ = await self._reader.read_ci_const(b"VRFY")
    _ = await self._reader.read_text_line()
    self._reply(252, "cannot VRFY")

  async def _h_starttls(self) -> None:
    _ = await self._reader.read_ci_const(b"STARTTLS")
    await self._reader.read_crlf()
    if self._tls_active:
      self._reply(503, "TLS already active")
      return
    self._reply(220, "Ready to start TLS")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with importlib.resources.path("mailproxy.assets", "dummy-cert.pem") as cert_path, importlib.resources.path("mailproxy.assets", "dummy-key.pem") as key_path:
      ctx.load_cert_chain(cert_path, key_path)
    await self._writer.start_tls(ctx)
    self._tls_active = True
    logging.debug("SMTP STARTTLS: TLS upgrade complete")


async def smtp_server_handle_client(config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
  session = SMTPServerSession(config, reader, writer)
  await session.run()
