import asyncio, logging, re, ssl, importlib.resources
from mailproxy.db import db_open
from mailproxy.auth import authenticate_sasl
from mailproxy.model import Account, Config
from mailproxy.smtp_backend import smtp_forward_mail
from mailproxy.utils import match_line

async def smtp_server_handle_client(config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
  def write_line(line: str):
    writer.write(line.encode("ascii"))
    writer.write(b"\r\n")

  def reply(code: int, textstring: str):
    if textstring and not re.fullmatch(r'[\t\x20-\x7E]+', textstring):
      raise ValueError("Invalid reply!", code, textstring)
    write_line(f"{code} {textstring}")

  account: Account | None = None
  sender: str = ""
  recipients: list[str] = []
  tls_active: bool = False

  logging.debug("SMTP frontend: client connected")
  try:
    write_line(f"220 {config.domain} Ready")

    while not reader.at_eof():
      line = (await reader.readuntil(b"\r\n"))[:-2].decode("ascii")
      logging.debug("SMTP client: %s", line)
      verb, _, rest = line.partition(" ")
      match verb.upper():
        case "QUIT":
          reply(221, f"{config.domain} closing transmission channel")
          return
        case "HELO":
          logging.debug("HELO connected from domain: " + rest)
          reply(250, config.domain)
        case "EHLO":
          logging.debug("EHLO connected from domain: " + rest)
          write_line(f"250-{config.domain} hello")
          features = "AUTH PLAIN"
          if not tls_active: features += " STARTTLS"
          write_line(f"250 {features}")
        case "NOOP":
          reply(250, "OK")
        case "RSET":
          logging.debug("resetting connection")
          sender = ""
          recipients.clear()
          reply(250, "OK")
        case "AUTH" if (m:=match_line(r"PLAIN (?P<data>\S+)", rest)):
          with db_open(config.db_path) as db:
            account = authenticate_sasl(config, db, m["data"].encode())
          if account is None:
            logging.debug("SMTP AUTH PLAIN failed")
            reply(535, "5.7.8  Authentication credentials invalid")
          else:
            logging.debug("SMTP AUTH PLAIN success for %s", account.key)
            reply(235, "2.7.0  Authentication Succeeded")
        case "AUTH" if match_line(r"PLAIN\s*", rest):
          write_line("334 ")
          auth_line = (await reader.readuntil(b"\r\n"))[:-2]
          with db_open(config.db_path) as db:
            account = authenticate_sasl(config, db, auth_line)
          if account is None:
            logging.debug("SMTP AUTH PLAIN (two-line) failed")
            reply(535, "5.7.8  Authentication credentials invalid")
          else:
            logging.debug("SMTP AUTH PLAIN (two-line) success for %s", account.key)
            reply(235, "2.7.0  Authentication Succeeded")
        case "MAIL" if account is not None and (m:=match_line(r"FROM:<(?P<mailbox>.*)>( .*)?", rest)):
          logging.debug("sending mail from mailbox: " + m["mailbox"])
          sender = m["mailbox"]
          recipients.clear()
          reply(250, "OK")
        case "RCPT" if account is not None and (m:=match_line(r"TO:<(?P<recipient>.*)>( .*)?", rest)):
          logging.debug("added recipient: " + m["recipient"])
          recipients.append(m["recipient"])
          reply(250, "OK")
        case "DATA" if account is not None:
          reply(354, "Start mail input; end with <CRLF>.<CRLF>")
          mail_data = (await reader.readuntil(b"\r\n.\r\n"))[:-5]
          try:
            await smtp_forward_mail(config.db_path, account, sender, tuple(recipients), mail_data)
            reply(250, "OK")
          except Exception as e:
            logging.error("failed to send message: %s", e)
            reply(451, "local error in processing")
          finally:
            sender = ""
            recipients.clear()
        case "VRFY":
          reply(252, "cannot VRFY")
        case "STARTTLS" if not tls_active:
          reply(220, "Ready to start TLS")
          ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
          with importlib.resources.path("mailproxy.assets", "dummy-cert.pem") as cert_path, importlib.resources.path("mailproxy.assets", "dummy-key.pem") as key_path:
            ctx.load_cert_chain(cert_path, key_path)
          await writer.start_tls(ctx)
          tls_active = True
          logging.debug("SMTP STARTTLS: TLS upgrade complete")
        case "STARTTLS":
          reply(503, "TLS already active")
        case _:
          reply(500, "unknown")

  except Exception as e:
    logging.error("connection closing because of an error: %s", e)
  finally:
    logging.debug("SMTP frontend: connection closed")
    writer.close()
