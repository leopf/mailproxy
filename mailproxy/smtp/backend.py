import asyncio, base64, contextlib, logging, pathlib, ssl
from mailproxy.auth import account_get_oauth_access_token
from mailproxy.db import db_open
from mailproxy.model import Account, AuthenticationOAUTH2, AuthenticationPLAIN, TLSMode
from mailproxy.smtp.reader import SMTPReader


async def _smtp_send(writer: asyncio.StreamWriter, smtp_reader: SMTPReader, command: str, expect_code: int | None = None) -> tuple[int, str]:
  writer.write(command.encode("ascii") + b"\r\n")
  await writer.drain()
  code, message = await smtp_reader.read_response()
  if expect_code is not None and code != expect_code:
    raise RuntimeError(f"SMTP command '{command}' failed: {code} {message}")
  return code, message

async def _smtp_authenticate(writer: asyncio.StreamWriter, smtp_reader: SMTPReader, account: Account, db_path: pathlib.Path):
  match account.auth:
    case AuthenticationOAUTH2():
      logging.debug("SMTP backend: authenticating as OAUTH2 (XOAUTH2)")
      with db_open(db_path) as db:
        access_token = account_get_oauth_access_token(db, account)
      auth_string = f"user={account.addresses[0]}\1auth=Bearer {access_token}\1\1"
      code, message = await _smtp_send(writer, smtp_reader, f"AUTH XOAUTH2 {base64.b64encode(auth_string.encode()).decode()}")
      if code == 334:
        writer.write(b"\r\n")
        await writer.drain()
        _, err_msg = await smtp_reader.read_response()
        raise RuntimeError(f"XOAUTH2 auth failed: {err_msg}")
      if code != 235:
        raise RuntimeError(f"XOAUTH2 auth failed: {code} {message}")
    case AuthenticationPLAIN():
      logging.debug("SMTP backend: authenticating as PLAIN")
      auth_string = f"\0{account.addresses[0]}\0{account.auth.password}"
      _ = await _smtp_send(writer, smtp_reader, f"AUTH PLAIN {base64.b64encode(auth_string.encode()).decode()}", expect_code=235)

async def smtp_forward_mail(db_path: pathlib.Path, account: Account, sender: str, recipients: tuple[str, ...], mail_data: bytes):
  ssl_param = ssl.create_default_context() if account.smtp_tlsmode == TLSMode.DIRECT else None
  logging.debug("SMTP backend: connecting to %s:%d (tls=%s)", account.smtp_host, account.smtp_port, account.smtp_tlsmode)
  reader, writer = await asyncio.open_connection(account.smtp_host, account.smtp_port, ssl=ssl_param)
  smtp_reader = SMTPReader(reader)
  try:
    _ = await smtp_reader.read_response()
    ehlo_domain = account.addresses[0].split("@")[-1] if "@" in account.addresses[0] else "localhost"
    _ = await _smtp_send(writer, smtp_reader, f"EHLO {ehlo_domain}")
    if account.smtp_tlsmode == TLSMode.STARTTLS:
      _ = await _smtp_send(writer, smtp_reader, "STARTTLS")
      await writer.start_tls(ssl.create_default_context())
      _ = await _smtp_send(writer, smtp_reader, f"EHLO {ehlo_domain}")
    await _smtp_authenticate(writer, smtp_reader, account, db_path)
    _ = await _smtp_send(writer, smtp_reader, f"MAIL FROM:<{sender}>", expect_code=250)
    for rcp in recipients:
      _ = await _smtp_send(writer, smtp_reader, f"RCPT TO:<{rcp}>", expect_code=250)
    _ = await _smtp_send(writer, smtp_reader, "DATA", expect_code=354)
    writer.write(mail_data + b"\r\n.\r\n")
    await writer.drain()
    _ = await smtp_reader.read_response()
  finally:
    with contextlib.suppress(Exception):
      _ = await _smtp_send(writer, smtp_reader, "QUIT")
    writer.close()
