"""Minimal stdlib-only stub of the Platform SRE Agent threads API for P13.3 malformed-findings staging verification.

Implements just enough of POST /api/v1/threads, GET /api/v1/threads/{id}, and
GET /api/v1/threads/{id}/messages to let a real deployed escalation proxy reach a
"completed" thread whose only message is a malformed final report (missing the
required ### Verdict section). It ignores the Authorization header entirely -
this is a disposable test double, not a security boundary.
"""

import http.server
import json
import re
import uuid

MALFORMED_REPORT = (
    "### Root Cause\n"
    "Stub root cause for P13.3 malformed-findings staging verification.\n\n"
    "### Evidence\n"
    "- Synthetic stub evidence only.\n\n"
    "### Recommended Actions\n"
    "1. No action required; this is a test fixture.\n\n"
    "FINALIZATION_TOKEN: ESCALATION_FINAL_V1"
)

THREAD_PATH = re.compile(r"^/api/v1/threads/([^/]+)$")
MESSAGES_PATH = re.compile(r"^/api/v1/threads/([^/]+)/messages$")


class Handler(http.server.BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/api/v1/threads":
            self._send_json(201, {"id": str(uuid.uuid4()), "status": "completed"})
            return
        self._send_json(404, {"detail": "not found"})

    def do_GET(self):
        if THREAD_PATH.fullmatch(self.path):
            self._send_json(200, {"status": "completed", "agentStatus": "completed"})
            return
        if MESSAGES_PATH.fullmatch(self.path):
            self._send_json(
                200,
                {"value": [{"author": {"role": "SREAgent"}, "text": MALFORMED_REPORT}]},
            )
            return
        self._send_json(404, {"detail": "not found"})

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
