#!/usr/bin/env python3
"""Local-only fake adapter for Stage 5 browser checks. Never contacts a device."""

from __future__ import annotations

import argparse
import base64
import copy
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

WEB_ROOT = Path(__file__).resolve().parents[1] / "web"
PREVIEW_TOKEN = "synthetic-preview-token"
INITIAL_TOKENS = [
    {"id": "tok_TTTTTTTTTTTTTTTTTTTT01", "label": "Web administration", "createdAt": "2026-01-01T08:00:00Z", "scope": "admin", "outlets": None, "enabled": True},
    {"id": "tok_TTTTTTTTTTTTTTTTTTTT02", "label": "Read-only monitoring", "createdAt": "2026-01-02T08:00:00Z", "scope": "read", "outlets": None, "enabled": True},
    {"id": "tok_TTTTTTTTTTTTTTTTTTTT03", "label": "Maintenance window", "createdAt": "2026-01-03T08:00:00Z", "scope": "control", "outlets": ["AAAAAAAAAAAAAAAAAAAA01"], "enabled": False},
]
TOKENS = copy.deepcopy(INITIAL_TOKENS)
OUTLETS = [
    {"id": f"AAAAAAAAAAAAAAAAAAAA{index:02d}", "pduId": "PPPPPPPPPPPPPPPPPPPP01", "position": index, "name": f"Outlet {index:02d}", "state": status, "availableActions": []}
    for index, status in enumerate(("on", "on", "unknown", "on", "on", "on", "unknown", "on"), 1)
]


def response(handler: BaseHTTPRequestHandler, status: int, payload: object) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def no_content(handler: BaseHTTPRequestHandler) -> None:
    handler.send_response(204)
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.end_headers()


def closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


class Handler(BaseHTTPRequestHandler):
    server_version = "PM3000Fake/1"

    def log_message(self, format: str, *args: object) -> None:
        print(format % args, flush=True)

    def authorized(self) -> bool:
        return self.headers.get("Authorization") == f"Bearer {PREVIEW_TOKEN}"

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/v1/health":
            response(self, 200, {"apiVersion": "v1", "status": "live"})
        elif path == "/api/v1/outlets":
            if not self.authorized():
                response(self, 401, {"code": "unauthorized", "message": "Token rejected."})
            else:
                response(self, 200, {"apiVersion": "v1", "inventoryRevision": "RRRRRRRRRRRRRRRRRRRR01", "outlets": OUTLETS})
        elif path == "/api/v1/tokens":
            if not self.authorized():
                response(self, 401, {"code": "unauthorized", "message": "Token rejected."})
            else:
                response(self, 200, {"tokens": TOKENS})
        else:
            self.serve_asset(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if not self.authorized():
            response(self, 401, {"code": "unauthorized", "message": "Token rejected."})
            return
        if path == "/api/v1/tokens":
            if self.headers.get("Content-Type") != "application/json":
                response(self, 415, {"code": "unsupported_media_type", "message": "application/json required."})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 1 or length > 2048:
                response(self, 413 if length > 2048 else 400, {"code": "payload_too_large" if length > 2048 else "bad_request", "message": "Invalid request size."})
                return
            try:
                body = json.loads(self.rfile.read(length), object_pairs_hook=closed_object)
                if not isinstance(body, dict) or not {"label", "scope"}.issubset(body) or not set(body) <= {"label", "scope", "outlets"}:
                    raise ValueError
                label, scope = body["label"], body["scope"]
                outlets = body.get("outlets")
                if (not isinstance(label, str) or not 1 <= len(label) <= 64 or
                        len(label.encode("utf-8")) > 128 or
                        label != label.strip() or any(ord(char) < 0x20 or ord(char) == 0x7f for char in label) or
                        scope not in {"read", "control", "admin"}):
                    raise ValueError
                if "outlets" in body:
                    if not isinstance(outlets, list) or len(outlets) > 256 or len(outlets) != len(set(outlets)):
                        raise ValueError
                    if any(not isinstance(item, str) or len(item) != 22 or not all(c.isascii() and (c.isalnum() or c in "_-") for c in item) for item in outlets):
                        raise ValueError
            except (ValueError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
                response(self, 400, {"code": "bad_request", "message": "Invalid token request."})
                return
            suffix = f"{len(TOKENS) + 1:02d}"
            record = {"id": "tok_" + "T" * 20 + suffix, "label": label, "createdAt": "2026-01-04T08:00:00Z", "scope": scope, "outlets": outlets, "enabled": True}
            TOKENS.append(record)
            plaintext = "pm3_" + base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
            response(self, 201, {**record, "token": plaintext})
            return
        if path.endswith("/enable") or path.endswith("/disable"):
            token_id, action = path.removeprefix("/api/v1/tokens/").rsplit("/", 1)
            for record in TOKENS:
                if record["id"] == token_id:
                    record["enabled"] = action == "enable"
                    no_content(self)
                    return
        response(self, 404, {"code": "not_found", "message": "Route not found."})

    def do_DELETE(self) -> None:
        if not self.authorized():
            response(self, 401, {"code": "unauthorized", "message": "Token rejected."})
            return
        token_id = urlparse(self.path).path.removeprefix("/api/v1/tokens/")
        for index, record in enumerate(TOKENS):
            if record["id"] == token_id:
                del TOKENS[index]
                no_content(self)
                return
        response(self, 404, {"code": "not_found", "message": "Token not found."})

    def serve_asset(self, path: str) -> None:
        if path in {"/", "/index.html", "/preview"}:
            if path == "/preview":
                TOKENS[:] = copy.deepcopy(INITIAL_TOKENS)
            content = (WEB_ROOT / "index.html").read_text()
            if path == "/preview":
                content = content.replace('src="app.js"', 'src="preview-app.js"')
            body = content.encode()
            mime = "text/html; charset=utf-8"
        else:
            name = path.removeprefix("/")
            if name not in {"styles.css", "app.js", "preview-app.js"}:
                self.send_error(404)
                return
            source_name = "app.js" if name == "preview-app.js" else name
            body = (WEB_ROOT / source_name).read_bytes()
            if name == "preview-app.js":
                body += b"\ndocument.getElementById('token-input').value='synthetic-preview-token';document.querySelector('#connect-form button[type=submit]').click();\n"
            mime = "text/css; charset=utf-8" if name.endswith(".css") else "text/javascript; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"fake UI adapter listening on http://{args.bind}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
