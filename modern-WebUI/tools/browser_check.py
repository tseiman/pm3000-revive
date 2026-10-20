#!/usr/bin/env python3
"""Render Stage 5 through Firefox WebDriver after explicit readiness checks."""

from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen

BASE = "http://127.0.0.1:4444"
OUTPUT = Path(__file__).resolve().parents[1] / "artifacts"


def call(method: str, path: str, payload: object | None = None) -> object:
    data = None if payload is None else json.dumps(payload).encode()
    request = Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json"})
    timeout = 60 if method == "POST" and path == "/session" else 20
    with urlopen(request, timeout=timeout) as result:
        parsed = json.load(result)
    if parsed.get("value") and isinstance(parsed["value"], dict) and "error" in parsed["value"]:
        raise RuntimeError(parsed["value"])
    return parsed.get("value")


def execute(session: str, script: str) -> object:
    return call("POST", f"/session/{session}/execute/sync", {"script": script, "args": []})


def wait_for(session: str, script: str, description: str) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if execute(session, script):
            return
        time.sleep(0.1)
    raise RuntimeError(f"Timed out waiting for {description}")


def screenshot(session: str, name: str) -> None:
    encoded = call("GET", f"/session/{session}/screenshot")
    (OUTPUT / name).write_bytes(base64.b64decode(str(encoded)))


def navigate_ready(session: str) -> None:
    call("POST", f"/session/{session}/url", {"url": "http://127.0.0.1:8765/preview"})
    wait_for(session, "return document.querySelectorAll('.outlet-card').length === 8", "eight outlet cards")


def main() -> int:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    value = call("POST", "/session", {"capabilities": {"alwaysMatch": {"browserName": "firefox", "moz:firefoxOptions": {"args": ["-headless"], "prefs": {"layout.css.devPixelsPerPx": "1.15"}}}}})
    if not isinstance(value, dict) or not isinstance(value.get("sessionId"), str):
        raise RuntimeError("WebDriver did not return a session ID")
    session = value["sessionId"]
    try:
        call("POST", f"/session/{session}/window/rect", {"width": 1440, "height": 1000, "x": 0, "y": 0})
        navigate_ready(session)
        screenshot(session, "stage5-outlets-desktop.png")

        execute(session, "document.querySelector('[data-view=tokens]').click(); return true")
        wait_for(session, "return document.querySelectorAll('#token-rows tr').length === 3", "three token rows")
        screenshot(session, "stage5-tokens-desktop.png")

        execute(session, "document.getElementById('open-create-token').click();document.getElementById('token-label').value='Cancel probe';document.getElementById('close-create-title').click();return true")
        wait_for(session, "return !document.getElementById('create-token-dialog').open && document.querySelectorAll('#token-rows tr').length === 3", "title close without token creation")
        execute(session, "document.getElementById('open-create-token').click(); return true")
        wait_for(session, "return document.getElementById('create-token-dialog').open", "create-token dialog")
        execute(session, "document.getElementById('token-label').value='Browser check';document.getElementById('all-outlets').click();document.getElementById('token-outlets').value='AAAAAAAAAAAAAAAAAAAA01';const b=document.querySelector('#create-token-form button[type=submit]');b.click();b.click();return true")
        wait_for(session, "return document.getElementById('new-token-secret').textContent.length === 47 && document.querySelectorAll('#token-rows tr').length === 4 && document.querySelectorAll('#token-rows tr')[3].children[2].textContent === '1 selected'", "one-time restricted token and fourth metadata row")
        execute(session, "document.getElementById('token-secret-dialog').close();return true")
        wait_for(session, "return document.getElementById('new-token-secret').textContent === ''", "one-time secret cleanup on native dialog close")
        execute(session, "document.querySelector('#token-rows tr:last-child .row-actions button').click();return true")
        wait_for(session, "return document.querySelector('#token-rows tr:last-child .enabled-badge').textContent === 'Disabled'", "204 disable response and disabled metadata refresh")
        execute(session, "document.querySelector('#token-rows tr:last-child .row-actions button').click();return true")
        wait_for(session, "return document.querySelector('#token-rows tr:last-child .enabled-badge').textContent === 'Enabled'", "204 enable response and enabled metadata refresh")
        execute(session, "window.confirm=()=>true;document.querySelectorAll('#token-rows tr:last-child .row-actions button')[1].click();return true")
        wait_for(session, "return document.querySelectorAll('#token-rows tr').length === 3", "204 revoke response and metadata removal")
        execute(session, "document.getElementById('open-create-token').click();document.getElementById('token-label').value='Disconnect probe';document.querySelector('#create-token-form button[type=submit]').click();return true")
        wait_for(session, "return document.getElementById('token-secret-dialog').open && document.getElementById('new-token-secret').textContent.length === 47", "secret before disconnect")
        execute(session, "document.getElementById('disconnect').click();return true")
        wait_for(session, "return !document.getElementById('token-secret-dialog').open && document.getElementById('new-token-secret').textContent === '' && !document.getElementById('login-view').hidden", "disconnect secret cleanup")

        call("POST", f"/session/{session}/window/rect", {"width": 390, "height": 844, "x": 0, "y": 0})
        navigate_ready(session)
        try:
            wait_for(session, "return document.documentElement.clientWidth <= 450 && document.documentElement.scrollWidth === document.documentElement.clientWidth && document.getElementById('disconnect').getBoundingClientRect().width > 0", "narrow layout without horizontal overflow and with operable disconnect")
        except RuntimeError as error:
            metrics = execute(session, "return {clientWidth:document.documentElement.clientWidth,scrollWidth:document.documentElement.scrollWidth,innerWidth:window.innerWidth,devicePixelRatio:window.devicePixelRatio}")
            raise RuntimeError(f"{error}; metrics={metrics}") from error
        screenshot(session, "stage5-outlets-narrow.png")
        print("browser check: cancel-safe create, single restricted create, 204 disable/enable/revoke, dialog+disconnect secret cleanup, desktop+narrow screenshots ready")
        return 0
    finally:
        call("DELETE", f"/session/{session}")


if __name__ == "__main__":
    sys.exit(main())
