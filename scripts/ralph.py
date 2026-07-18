#!/usr/bin/env python3
"""Ralph loop: drive an opencode web session to fix bugs repeatedly.

Starts an `opencode web` server, creates a session, and re-sends a
hard-coded prompt in a loop.  All permission requests (including questions)
are denied automatically via the SSE event stream so the loop runs unattended.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.client import HTTPResponse
from types import FrameType
from typing import cast

HOST = "127.0.0.1"
PORT = 4098
BASE = f"http://{HOST}:{PORT}"

PROMPT = "Look around the codebase, find a bug, and fix it."
MODEL = "openrouter/z-ai/glm-5.2"

HEALTH_TIMEOUT = 30.0
HEALTH_INTERVAL = 0.5
MESSAGE_TIMEOUT = 600.0
SSE_RECONNECT_DELAY = 0.5

JsonObject = dict[str, object]


def _request(
  method: str,
  path: str,
  body: JsonObject | None = None,
  timeout: float | None = None,
) -> JsonObject | bytes | None:
  data = json.dumps(body).encode() if body is not None else None
  req = urllib.request.Request(BASE + path, data=data, method=method)
  if data is not None:
    req.add_header("content-type", "application/json")
  try:
    resp = cast(HTTPResponse, urllib.request.urlopen(req, timeout=timeout))
    try:
      raw = resp.read()
      if not raw:
        return None
      ct = resp.headers.get("content-type", "")
      if "application/json" in ct:
        return cast(JsonObject, json.loads(raw))
      return raw
    finally:
      resp.close()
  except urllib.error.HTTPError as exc:
    return {"error": exc.code, "body": exc.read().decode("utf-8", "replace")}


def _wait_for_server() -> None:
  deadline = time.monotonic() + HEALTH_TIMEOUT
  while time.monotonic() < deadline:
    try:
      res = _request("GET", "/global/health", timeout=2.0)
      if isinstance(res, dict) and res.get("healthy"):
        return
    except Exception:
      pass
    time.sleep(HEALTH_INTERVAL)
  raise RuntimeError(f"server at {BASE} did not become healthy")


def _create_session() -> str:
  res = _request("POST", "/session", {})
  if not isinstance(res, dict) or "id" not in res:
    raise RuntimeError(f"failed to create session: {res!r}")
  return cast(str, res["id"])


def _deny_loop(session_id: str, stop: threading.Event) -> None:
  """Stream /event SSE and reject any permission request for our session."""
  while not stop.is_set():
    try:
      req = urllib.request.Request(BASE + "/event")
      resp = cast(HTTPResponse, urllib.request.urlopen(req, timeout=None))
      try:
        buf: bytes = b""
        while not stop.is_set():
          chunk = resp.read(1024)
          if not chunk:
            break
          buf += chunk
          while b"\n\n" in buf:
            block, _, buf = cast(tuple[bytes, bytes, bytes], buf.partition(b"\n\n"))
            _process_sse_block(block, session_id)
      finally:
        resp.close()
    except Exception as exc:
      if not stop.is_set():
        print(f"  [event stream reconnect] {exc}", flush=True)
        time.sleep(SSE_RECONNECT_DELAY)


def _process_sse_block(block: bytes, session_id: str) -> None:
  for line in block.split(b"\n"):
    if not line.startswith(b"data: "):
      continue
    try:
      evt = cast(JsonObject, json.loads(line[6:]))
    except json.JSONDecodeError:
      continue
    props = cast(JsonObject, evt.get("properties") or {})
    if props.get("sessionID") != session_id:
      continue
    if evt.get("type") == "permission.asked":
      pid = cast(str | None, props.get("id"))
      if pid:
        _ = _request("POST", f"/session/{session_id}/permissions/{pid}", {"response": "reject"})
        print(f"  [denied] {props.get('permission')}: {pid}", flush=True)


def _run_turn(session_id: str, prompt: str) -> JsonObject:
  stop = threading.Event()
  worker = threading.Thread(target=_deny_loop, args=(session_id, stop), daemon=True)
  worker.start()
  try:
    res = _request(
      "POST",
      f"/session/{session_id}/message",
      {"model": MODEL, "parts": [{"type": "text", "text": prompt}]},
      timeout=MESSAGE_TIMEOUT,
    )
  finally:
    stop.set()
    worker.join(timeout=2.0)
  if not isinstance(res, dict):
    raise RuntimeError(f"unexpected message response: {res!r}")
  return res


def _summarize(res: JsonObject) -> str:
  info = cast(JsonObject, res.get("info") or {})
  parts = cast(list[JsonObject], res.get("parts") or [])
  text = " ".join(cast(str, p.get("text", "")) for p in parts if p.get("type") == "text")
  finish = info.get("finish")
  msg = text.strip().replace("\n", " ")
  if len(msg) > 200:
    msg = msg[:200] + "..."
  return f"finish={finish!r} text={msg!r}"


def main() -> None:
  proc = subprocess.Popen(
    ["opencode", "web", "--port", str(PORT), "--hostname", HOST],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    env=os.environ.copy(),
  )

  def _cleanup() -> None:
    if proc.poll() is None:
      proc.terminate()
      try:
        _ = proc.wait(timeout=5)
      except subprocess.TimeoutExpired:
        proc.kill()

  def _sig(_signo: int, _frame: FrameType | None) -> None:
    _cleanup()
    sys.exit(0)

  _ = signal.signal(signal.SIGINT, _sig)
  _ = signal.signal(signal.SIGTERM, _sig)

  try:
    _wait_for_server()
    print(f"opencode server ready at {BASE}", flush=True)

    sid = _create_session()
    print(f"session: {sid}", flush=True)
    print(f"web dashboard: {BASE}/session/{sid}", flush=True)
    print(f"prompt: {PROMPT!r}", flush=True)
    print("-" * 60, flush=True)

    i = 0
    while True:
      i += 1
      print(f"[turn {i}] sending prompt...", flush=True)
      try:
        res = _run_turn(sid, PROMPT)
        print(f"[turn {i}] {_summarize(res)}", flush=True)
      except Exception as exc:
        print(f"[turn {i}] error: {exc}", flush=True)
      print("-" * 60, flush=True)
  finally:
    _cleanup()


if __name__ == "__main__":
  main()
