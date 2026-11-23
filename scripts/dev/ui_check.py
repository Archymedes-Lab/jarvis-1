"""Browser QC for the web UI: brand, script errors and layout, on real pages.

    uv run --with playwright==1.55.0 python3 scripts/dev/ui_check.py [--shots DIR]

Serves the checkout's pages on 127.0.0.1:8790 and forwards GET /api/* to the
live daemon on 127.0.0.1:8787; anything else is refused, so the check cannot
change state. One synthetic finding is added to /api/state so the brand rule
is exercised on server text every run: product prose must read ARGUS-INSTINCT, real
Windows object names must keep their spelling. Uses Playwright's Linux
chromium-headless-shell (Windows policy blocks headless Chrome/Edge here).
Exit status 0 only when every page passes.
"""
import argparse
import http.server
import json
import re
import sys
import threading
import urllib.request
from pathlib import Path

STATIC = Path(__file__).resolve().parents[2] / "jarvis" / "web" / "static"
if len(sys.argv) > 2 and sys.argv[1] == "--static":     # negative control: another tree
    STATIC = Path(sys.argv.pop(2)).resolve()
    sys.argv.pop(1)
DAEMON = "http://127.0.0.1:8787"
PORT = 8790
PAGES = {"/": "dashboard.html", "/coverage": "coverage.html", "/geo": "geo.html",
         "/procs": "procs.html", "/world": "world.html"}
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
         ".json": "application/json", ".woff2": "font/woff2", ".css": "text/css"}
PROBE = {"job": "control", "severity": "critical", "host": "win", "category": "visibility",
         "title": "JARVIS could not verify the JARVIS input hook task",
         "where": "JARVIS JarvisSensorDefender collector", "detail": "run jarvis status",
         "reasons": [], "fix": "", "id": "uiprobe"}
# A visible JARVIS is allowed only as part of a real Windows object name.
ALLOWED = re.compile(r"\bJARVIS (input hook|independent health monitor|connectivity guard"
                     r"|native sensor|Jarvis)")
WIDTHS = (390, 1280)


class Preview(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass                                 # the page moved on; nothing to report

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/"):
            if path == "/api/stream":
                return self._send(204, b"", "text/plain")   # keep the check short
            try:
                # Every data route needs a credential: this account's paired
                # client token, or the daemon's token file when readable.
                sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
                from jarvis.web import apiclient, token
                req = urllib.request.Request(DAEMON + self.path,
                                             headers={token.HEADER: apiclient.credential()})
                with urllib.request.urlopen(req, timeout=20) as r:
                    body, ctype = r.read(), r.headers.get("Content-Type", "application/json")
            except Exception as exc:
                return self._send(502, str(exc).encode(), "text/plain")
            if path == "/api/state":
                state = json.loads(body)
                state.setdefault("findings", []).insert(0, dict(PROBE))
                body = json.dumps(state).encode()
            return self._send(200, body, ctype)
        name = PAGES.get(path) or (path[len("/static/"):] if path.startswith("/static/") else None)
        file = (STATIC / name).resolve() if name else None
        if not file or STATIC not in file.parents or not file.is_file():
            return self._send(404, b"not found", "text/plain")
        self._send(200, file.read_bytes(), TYPES.get(file.suffix, "application/octet-stream"))

    def do_POST(self):
        self._send(403, b"read-only preview", "text/plain")

    do_PUT = do_DELETE = do_PATCH = do_POST


def check(shots):
    from playwright.sync_api import sync_playwright
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Preview)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    failures = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            for width in WIDTHS:
                for route in PAGES:
                    page = browser.new_page(viewport={"width": width, "height": 900})
                    errors = []
                    page.on("pageerror", lambda e, errors=errors: errors.append(str(e)))
                    page.goto(f"http://127.0.0.1:{PORT}{route}", wait_until="domcontentloaded")
                    page.wait_for_timeout(6000)
                    text = page.evaluate("document.body.innerText") + " " + page.title()
                    leaks = sorted({m.group(0) for m in re.finditer(r"\bJARVIS\b.{0,30}", text)
                                    if not ALLOWED.match(m.group(0))})
                    overflow = page.evaluate(
                        "document.documentElement.scrollWidth - document.documentElement.clientWidth")
                    label = f"{route} @{width}px"
                    if leaks:
                        failures.append(f"{label}: visible JARVIS: {leaks[:5]}")
                    if errors:
                        failures.append(f"{label}: script errors: {errors[:3]}")
                    if overflow > 1:
                        failures.append(f"{label}: horizontal overflow {overflow}px")
                    if "ARGUS-INSTINCT" not in text:
                        failures.append(f"{label}: brand ARGUS-INSTINCT not shown")
                    if route == "/" and "JARVIS input hook" not in text:
                        failures.append(f"{label}: real task name was rewritten or not shown")
                    if shots:
                        Path(shots).mkdir(parents=True, exist_ok=True)
                        page.screenshot(path=f"{shots}/{route.strip('/') or 'dashboard'}-{width}.png",
                                        full_page=False)
                    print(f"{label}: {'ok' if not any(f.startswith(label) for f in failures) else 'FAIL'}")
                    page.close()
            browser.close()
    finally:
        server.shutdown()
    for f in failures:
        print("FAIL", f)
    return not failures


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--shots", help="directory for screenshots")
    sys.exit(0 if check(ap.parse_args().shots) else 1)
