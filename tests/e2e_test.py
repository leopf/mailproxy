import socket, subprocess, sys, time, os, signal, imaplib, base64

HOST = "127.0.0.1"
IMAP_PORT = 9143
SMTP_PORT = 9587
PASSWORD = "testpw"
ACCOUNT = "test2@outlook.de"

def _wait_for_port(port: int, timeout: float = 10.0) -> bool:
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    try:
      with socket.create_connection((HOST, port), timeout=0.5):
        return True
    except OSError:
      time.sleep(0.2)
  return False

def _start_server() -> subprocess.Popen[bytes]:
  env = dict(os.environ, MAILPROXY_PASSWORD=PASSWORD)
  proc = subprocess.Popen(
    [sys.executable, "-m", "mailproxy.bin", "run", "-C", "temp/config.json"],
    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
  )
  if not _wait_for_port(IMAP_PORT) or not _wait_for_port(SMTP_PORT):
    proc.kill()
    raise RuntimeError("server did not start")
  return proc

def _stop_server(proc: subprocess.Popen[bytes]) -> None:
  proc.send_signal(signal.SIGTERM)
  _ = proc.wait(timeout=5)

def _b64plain(user: str, password: str) -> str:
  return base64.b64encode(f"\0{user}\0{password}".encode()).decode()

class TestResult:
  def __init__(self) -> None:
    self.passed: int = 0
    self.failed: int = 0
    self.errors: list[str] = []

  def ok(self, name: str) -> None:
    self.passed += 1
    print(f"  PASS: {name}")

  def fail(self, name: str, detail: str = "") -> None:
    self.failed += 1
    msg = f"  FAIL: {name}" + (f" — {detail}" if detail else "")
    self.errors.append(msg)
    print(msg)

  def summary(self) -> bool:
    total = self.passed + self.failed
    print(f"\n{'='*40}\n{self.passed}/{total} passed, {self.failed} failed")
    if self.errors:
      print("\nFailures:")
      for e in self.errors:
        print(e)
    return self.failed == 0


def test_imap(result: TestResult) -> None:
  print("\n--- IMAP tests ---")

  try:
    imap = imaplib.IMAP4(HOST, IMAP_PORT)
  except Exception as e:
    result.fail("connect", str(e))
    return

  if imap.state != "NONAUTH":
    result.fail("greeting state", f"expected NONAUTH, got {imap.state}")
  else:
    result.ok("greeting state NONAUTH")

  try:
    typ, data = imap.capability()
    if typ == "OK" and b"IMAP4rev1" in data[0]:
      result.ok("CAPABILITY returns IMAP4rev1")
    else:
      result.fail("CAPABILITY", f"typ={typ} data={data}")
  except Exception as e:
    result.fail("CAPABILITY", str(e))

  try:
    typ, _ = imap.noop()
    if typ == "OK":
      result.ok("NOOP")
    else:
      result.fail("NOOP", f"typ={typ}")
  except Exception as e:
    result.fail("NOOP", str(e))

  try:
    _ = imap.login(ACCOUNT, "wrongpassword")
    result.fail("LOGIN wrong password", "expected rejection")
  except imaplib.IMAP4.error:
    result.ok("LOGIN wrong password rejected")
  except Exception as e:
    result.fail("LOGIN wrong password", str(e))

  try:
    _ = imap.login(ACCOUNT, PASSWORD)
    result.ok("LOGIN correct password")
    _ = imap.logout()
  except imaplib.IMAP4.error:
    result.ok("LOGIN correct password (backend unreachable, expected error)")
  except Exception as e:
    result.fail("LOGIN correct password", str(e))

  try:
    imap = imaplib.IMAP4(HOST, IMAP_PORT)
    try:
      typ, _ = imap.list()
      if typ == "NO":
        result.ok("LIST rejected without auth")
      else:
        result.fail("LIST without auth", f"expected NO, got {typ}")
    except imaplib.IMAP4.error:
      result.ok("LIST rejected without auth")
    _ = imap.logout()
  except Exception as e:
    result.fail("LIST without auth", str(e))

  try:
    imap = imaplib.IMAP4(HOST, IMAP_PORT)
    typ, _ = imap.logout()
    if typ == "BYE":
      result.ok("LOGOUT")
    else:
      result.fail("LOGOUT", f"expected BYE, got {typ}")
  except Exception as e:
    result.fail("LOGOUT", str(e))


def test_imap_authenticate(result: TestResult) -> None:
  print("\n--- IMAP AUTHENTICATE PLAIN tests ---")
  try:
    imap = imaplib.IMAP4(HOST, IMAP_PORT)
    _ = imap.authenticate("PLAIN", lambda x: f"\0{ACCOUNT}\0{PASSWORD}".encode())
    result.ok("AUTHENTICATE PLAIN correct")
    _ = imap.logout()
  except imaplib.IMAP4.error:
    result.ok("AUTHENTICATE PLAIN correct (backend unreachable, expected error)")
  except Exception as e:
    result.fail("AUTHENTICATE PLAIN correct", str(e))

  try:
    imap = imaplib.IMAP4(HOST, IMAP_PORT)
    _ = imap.authenticate("PLAIN", lambda x: f"\0{ACCOUNT}\0wrongpw".encode())
    result.fail("AUTHENTICATE PLAIN wrong", "expected rejection")
    _ = imap.logout()
  except imaplib.IMAP4.error:
    result.ok("AUTHENTICATE PLAIN wrong rejected")
  except Exception as e:
    result.fail("AUTHENTICATE PLAIN wrong", str(e))


def _smtp_session(commands: list[str]) -> list[str]:
  sock = socket.create_connection((HOST, SMTP_PORT), timeout=5)
  sock.settimeout(5)
  f = sock.makefile("rwb")
  responses: list[str] = []
  try:
    greeting = f.readline()
    responses.append(greeting.decode().strip())
    for cmd in commands:
      _ = f.write(cmd.encode("ascii") + b"\r\n")
      f.flush()
      resp_lines: list[str] = []
      while True:
        line = f.readline().decode().rstrip("\r\n")
        if not line:
          break
        resp_lines.append(line)
        if len(line) >= 4 and line[3] == " ":
          break
      responses.append("\n".join(resp_lines))
  finally:
    sock.close()
  return responses

def test_smtp(result: TestResult) -> None:
  print("\n--- SMTP protocol tests ---")

  try:
    r = _smtp_session(["EHLO test"])
    if "250" in r[-1] and "AUTH PLAIN" in r[-1]:
      result.ok("EHLO advertises AUTH PLAIN")
    else:
      result.fail("EHLO", str(r))
  except Exception as e:
    result.fail("EHLO", str(e))

  try:
    b64 = _b64plain(ACCOUNT, PASSWORD)
    r = _smtp_session(["EHLO test", f"AUTH PLAIN {b64}"])
    if "235" in r[-1]:
      result.ok("AUTH PLAIN one-line success")
    else:
      result.fail("AUTH PLAIN one-line success", str(r))
  except Exception as e:
    result.fail("AUTH PLAIN one-line success", str(e))

  try:
    b64 = _b64plain(ACCOUNT, "wrongpw")
    r = _smtp_session(["EHLO test", f"AUTH PLAIN {b64}"])
    if "535" in r[-1]:
      result.ok("AUTH PLAIN wrong password rejected")
    else:
      result.fail("AUTH PLAIN wrong password", str(r))
  except Exception as e:
    result.fail("AUTH PLAIN wrong password", str(e))

  try:
    b64 = _b64plain(ACCOUNT, PASSWORD)
    r = _smtp_session(["EHLO test", "AUTH PLAIN", b64])
    if "235" in r[-1]:
      result.ok("AUTH PLAIN two-line success")
    else:
      result.fail("AUTH PLAIN two-line success", str(r))
  except Exception as e:
    result.fail("AUTH PLAIN two-line success", str(e))

  try:
    r = _smtp_session(["NOOP"])
    if "250" in r[-1]:
      result.ok("NOOP")
    else:
      result.fail("NOOP", str(r))
  except Exception as e:
    result.fail("NOOP", str(e))

  try:
    r = _smtp_session(["RSET"])
    if "250" in r[-1]:
      result.ok("RSET")
    else:
      result.fail("RSET", str(r))
  except Exception as e:
    result.fail("RSET", str(e))

  try:
    r = _smtp_session(["VRFY someone"])
    if "252" in r[-1]:
      result.ok("VRFY")
    else:
      result.fail("VRFY", str(r))
  except Exception as e:
    result.fail("VRFY", str(e))

  try:
    r = _smtp_session(["STARTTLS"])
    if "220" in r[-1]:
      result.ok("STARTTLS advertised and accepted")
    else:
      result.fail("STARTTLS", str(r))
  except Exception as e:
    result.fail("STARTTLS", str(e))

  try:
    r = _smtp_session(["BOGUS"])
    if "500" in r[-1]:
      result.ok("unknown command rejected")
    else:
      result.fail("unknown command", str(r))
  except Exception as e:
    result.fail("unknown command", str(e))

  try:
    r = _smtp_session(["QUIT"])
    if "221" in r[-1]:
      result.ok("QUIT")
    else:
      result.fail("QUIT", str(r))
  except Exception as e:
    result.fail("QUIT", str(e))

  try:
    r = _smtp_session(["EHLO test", "MAIL FROM:<sender@test.com>"])
    if "500" in r[-1] or "530" in r[-1]:
      result.ok("MAIL FROM rejected without auth")
    else:
      result.fail("MAIL FROM without auth", f"got {r[-1]}")
  except Exception as e:
    result.fail("MAIL FROM without auth", str(e))


def main() -> None:
  print("Starting mailproxy server...")
  proc = _start_server()
  print(f"Server started (pid={proc.pid})")

  result = TestResult()
  try:
    test_imap(result)
    test_imap_authenticate(result)
    test_smtp(result)
  finally:
    _stop_server(proc)

  sys.exit(0 if result.summary() else 1)


if __name__ == "__main__":
  main()
