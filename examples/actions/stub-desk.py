"""A tiny ticket API on this computer, for trying rest-ticket.py without a
real ticket system. Standard library only; tickets live in memory.

    python stub-desk.py [--port 8765] [--token TOKEN]

It prints the address it listens on (http://127.0.0.1:PORT/api), then one
line per request. With --token, every request needs
`Authorization: Bearer TOKEN`. Stop it with Ctrl-C.

    GET   /api/tickets?external_id=ID   the tickets for a finding
    POST  /api/tickets                  open one: title, description, ...
    GET   /api/tickets/{id}             one ticket
    PATCH /api/tickets/{id}             change its status (and add a comment)
    POST  /api/hooks/NAME               a chat webhook: takes any JSON, no token
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TICKETS: dict = {}
HOOKS: list = []
LOCK = threading.Lock()


class Desk(BaseHTTPRequestHandler):
    token = None

    def log_message(self, fmt, *args):
        print(f"{self.command} {self.path} -> {args[1] if len(args) > 1 else ''}", flush=True)

    def answer(self, code: int, body) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def allowed(self) -> bool:
        if self.token and self.headers.get("Authorization") != f"Bearer {self.token}":
            self.answer(401, {"error": "a valid token is needed"})
            return False
        return True

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def route(self):
        url = urllib.parse.urlsplit(self.path)
        parts = [p for p in url.path.split("/") if p]
        if parts[:2] != ["api", "tickets"] or len(parts) > 3:
            return None, None, url
        return "tickets", (parts[2] if len(parts) == 3 else None), url

    def do_GET(self):
        if not self.allowed():
            return
        what, tid, url = self.route()
        if what is None:
            return self.answer(404, {"error": "not found"})
        with LOCK:
            if tid is None:
                want = urllib.parse.parse_qs(url.query).get("external_id", [None])[0]
                return self.answer(200, [t for t in TICKETS.values() if want is None or t["external_id"] == want])
            if tid not in TICKETS:
                return self.answer(404, {"error": f"no ticket {tid}"})
            return self.answer(200, TICKETS[tid])

    def do_POST(self):
        if self.path.startswith("/api/hooks/"):
            # A chat webhook: its URL is its secret, so no token.
            HOOKS.append(self.body())
            return self.answer(200, {"ok": True})
        if not self.allowed():
            return
        what, tid, _ = self.route()
        if what is None or tid is not None:
            return self.answer(404, {"error": "not found"})
        b = self.body()
        if not b.get("title"):
            return self.answer(400, {"error": "title is needed"})
        with LOCK:
            n = len(TICKETS) + 1
            tid = f"t-{n}"
            TICKETS[tid] = {
                "id": tid,
                "number": f"DESK{n:04d}",
                "status": "Open",
                "url": f"https://desk.example.com/tickets/DESK{n:04d}",
                "title": b["title"],
                "description": b.get("description", ""),
                "queue": b.get("queue"),
                "urgency": b.get("urgency"),
                "external_id": b.get("external_id"),
                "comments": [],
            }
            return self.answer(201, TICKETS[tid])

    def do_PATCH(self):
        if not self.allowed():
            return
        what, tid, _ = self.route()
        if what is None or tid is None:
            return self.answer(404, {"error": "not found"})
        b = self.body()
        with LOCK:
            if tid not in TICKETS:
                return self.answer(404, {"error": f"no ticket {tid}"})
            t = TICKETS[tid]
            if b.get("status"):
                t["status"] = str(b["status"])
            if b.get("comment"):
                t["comments"].append(str(b["comment"]))
            return self.answer(200, t)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--port", type=int, default=8765, help="the port (0: any free one)")
    p.add_argument("--token", help="the token every request must carry")
    a = p.parse_args()
    Desk.token = a.token
    server = ThreadingHTTPServer(("127.0.0.1", a.port), Desk)
    print(f"listening on http://127.0.0.1:{server.server_port}/api", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
