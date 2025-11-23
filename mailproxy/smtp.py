import asyncio, re, logging
from mailproxy.auth import authenticate_sasl
from mailproxy.config import Account, Config
from mailproxy.utils import match_line

async def smtp_forward_mail(account: Account, sender: str, recipients: tuple[str, ...], mail_data: bytes):
  pass

async def smtp_server_handle_client(config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
  def write_line(line: str):
    writer.write(line.encode("ascii"))
    writer.write(b"\r\n")
  
  def reply(code: int, textstring: str):
    if not re.fullmatch(r'[\t\x20-\x7E]+', textstring):
      raise ValueError("Invalid reply!", code, textstring)

    write_line(f"{code} {textstring}")

  account: Account | None = None
  sender: str = ""
  recipients: list[str] = []

  try:
    write_line(f"220 {config.domain} Ready" )

    while not reader.at_eof():
      line = (await reader.readuntil(b"\r\n"))[:-2].decode("ascii")
      
      logging.debug("reading line: " + line)

      if match_line(r"QUIT", line):
        reply(221, f"{config.domain} closing transmission channel")
        return
      elif (m:=match_line(r"HELO (?P<domain>.*)\s*", line)):
        logging.debug("HELO connected from domain: " + m["domain"])
        reply(250, config.domain)
      elif ((m:=match_line(r"EHLO (?P<domain>.*)\s*", line))):
        logging.debug("EHLO connected from domain: " + m["domain"])
        write_line(f"250-{config.domain} hello")
        write_line("250 AUTH PLAIN") # space for last!
      elif match_line(r"NOOP(\s.*)?", line):
        reply(250, "OK")
      elif match_line(r"RSET", line):
        logging.debug("resetting connection")
        sender = ""
        recipients.clear()
        reply(250, "OK")

      # authorization
      elif (m:=match_line(r"AUTH PLAIN (?P<data>[a-z0-9\+\/]*(=|==)?)", line)):
        account = authenticate_sasl(config, m["data"])
        if account is None:
          reply(235, "2.7.0  Authentication Succeeded")
        else:
          reply(535, "5.7.8  Authentication credentials invalid")

      # following is only stuff allowed in auth
      elif account is not None and (m:=match_line(r"MAIL FROM:<(?P<mailbox>.*)>( AUTH=.*)?", line)):
        logging.debug("sending mail from mailbox: " + m["mailbox"])
        sender = m["mailbox"]
        recipients.clear()
        reply(250, "OK")
      elif account is not None and (m:=match_line(r"RCPT TO:<(?P<recipient>.*)>", line)):
        logging.debug("added recipient: " + m["recipient"])
        recipients.append(m["recipient"])
        reply(250, "OK")
      elif account is not None and match_line(f"DATA", line):
        reply(354, "Start mail input; end with <CRLF>.<CRLF>")
        mail_data = (await reader.readuntil(b"\r\n.\r\n"))[:-5]
        try:
          await smtp_forward_mail(account, sender, tuple(recipients), mail_data)
          reply(250, "OK")
        except Exception as e:
          logging.error("failed to send message", e)
          reply(451, "local error in processing")
        finally:
          sender = ""
          recipients.clear()
      elif account is not None and match_line(r"VRFY (?P<user>.*)", line):
        raise NotImplementedError("https://datatracker.ietf.org/doc/html/rfc5321#section-3.5")
        """
        if name is allowed, get mailbox name and return with 250 inside <>
        if not, return 553 with message
        """
        reply(250, "OK")
      else:
        reply(500, "unknown")

  except Exception as e:
    logging.error("connection closing because of an error", e)
  finally:
    logging.debug("connection closed")
    writer.close()
