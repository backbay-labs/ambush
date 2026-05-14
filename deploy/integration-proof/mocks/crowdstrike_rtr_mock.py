#!/usr/bin/env python3
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


LOG_PATH = Path(os.environ.get("MOCK_LOG_PATH", "/runtime-data/mocks/crowdstrike-rtr.jsonl"))
HOST = os.environ.get("MOCK_HOST", "0.0.0.0")
PORT = int(os.environ.get("MOCK_PORT", "8080"))


def append_log(entry: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True))
        handle.write("\n")


class Handler(BaseHTTPRequestHandler):
    server_version = "SwarmProofCrowdStrikeMock/1.0"

    def log_message(self, fmt: str, *args) -> None:
        return

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send_json(200, {"ok": True})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8")
        parsed_url = urlparse(self.path)
        try:
            body = json.loads(raw_body) if raw_body else None
        except json.JSONDecodeError:
            body = raw_body
        append_log(
            {
                "method": "POST",
                "path": parsed_url.path,
                "query": parse_qs(parsed_url.query),
                "authorization": self.headers.get("Authorization"),
                "content_type": self.headers.get("Content-Type"),
                "body": body,
            }
        )

        if parsed_url.path == "/oauth2/token":
            self._send_json(200, {"access_token": "proof-access-token"})
            return
        if parsed_url.path == "/devices/entities/devices-actions/v2":
            self._send_json(200, {"resources": [{"id": "device-action-1"}]})
            return
        if parsed_url.path == "/real-time-response/entities/sessions/v1":
            self._send_json(200, {"resources": [{"session_id": "proof-session-1"}]})
            return
        if parsed_url.path == "/real-time-response/entities/execute-admin-command/v1":
            self._send_json(200, {"resources": [{"cloud_request_id": "proof-command-1"}]})
            return
        self._send_json(404, {"error": "unknown route"})


if __name__ == "__main__":
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
