import functools, asyncio, dataclasses, re, logging, base64

def match_line(pattern: str, line: str, flags: int = re.I):
  m = re.fullmatch(pattern, line, flags)
  if m is None: return None
  else: return { "": "" } | m.groupdict()

@dataclasses.dataclass
class Config:
  database_path: str
  domain: str # verify!!
  log_level: int = logging.ERROR
  host: str = "127.0.0.1"
  IMAP_port: int = 143
  SMTP_port: int = 587

async def run_imap(config: Config):
  pass

def smtp_forward_mail(config: Config, sender: str, recipients: tuple[str, ...], data: bytes):
  print("FORWARDING:", data.decode())

def authenticate(username: str, password: str) -> bool:
  print("try auth", username, password)
  return True

async def handle_smtp(config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
  def write_line(line: str):
    writer.write(line.encode("ascii"))
    writer.write(b"\r\n")
  
  def reply(code: int, textstring: str):
    if not re.fullmatch(r'[\t\x20-\x7E]+', textstring):
      raise ValueError("Invalid reply!", code, textstring)

    write_line(f"{code} {textstring}")

  authenticated: bool = False
  sender: str = ""
  recipients: list[str] = []

  try:
    write_line(f"220 {config.domain} Ready" )

    while not reader.at_eof():
      line = (await reader.readuntil(b"\r\n"))[:-2].decode("ascii").strip()
      if line == "":
        continue
      
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
        data = base64.b64decode(m["data"]).split(b"\0")
        if authenticate(data[1].decode(), data[1].decode()):
          reply(235, "2.7.0  Authentication Succeeded")
          authenticated = True
        else:
          authenticated = False
          reply(535, "5.7.8  Authentication credentials invalid")

      # following is only stuff allowed in auth
      elif authenticated and (m:=match_line(r"MAIL FROM:<(?P<mailbox>.*)>( AUTH=.*)?", line)):
        logging.debug("sending mail from mailbox: " + m["mailbox"])
        sender = m["mailbox"]
        recipients.clear()
        reply(250, "OK")
      elif authenticated and (m:=match_line(r"RCPT TO:<(?P<recipient>.*)>", line)):
        logging.debug("added recipient: " + m["recipient"])
        recipients.append(m["recipient"])
        reply(250, "OK")
      elif authenticated and match_line(f"DATA", line):
        reply(354, "Start mail input; end with <CRLF>.<CRLF>")
        mail_data = (await reader.readuntil(b"\r\n.\r\n"))[:-5]
        try:
          await asyncio.to_thread(smtp_forward_mail, config, sender, tuple(recipients), mail_data)
          reply(250, "OK")
        except Exception as e:
          logging.error("failed to send message", e)
          reply(451, "local error in processing")
        finally:
          sender = ""
          recipients.clear()
      elif authenticated and match_line(r"VRFY (?P<user>.*)", line):
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

async def main():
  config = Config(
    log_level=logging.DEBUG,
    database_path="/tmp/mailproxy.sqlite",
    domain="example.com",
    SMTP_port=1587
  )

  logging.basicConfig(level=config.log_level)

  async with asyncio.TaskGroup() as tg:
    smtp_server = await asyncio.start_server(functools.partial(handle_smtp, config), config.host, config.SMTP_port)
    tg.create_task(smtp_server.serve_forever(), name="SMTP server")


if __name__ == "__main__":
    asyncio.run(main())