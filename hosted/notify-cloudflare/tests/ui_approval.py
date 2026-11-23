"""The phone app in a real browser (Chromium, phone viewport), end to end, against `wrangler dev`:
scan the pairing QR with a fake camera, allow notifications, set up a passkey on a virtual
authenticator (user-verified, like Face ID), pair, receive an approval, approve it with the passkey,
see the server apply it, then undo it. Also the iPhone-in-Safari path (install guide).

    pip install playwright cryptography      # a scratch venv is fine
    USERPROFILE=<scratch> HOME=<scratch> python tests/ui_approval.py OUT_DIR [path/to/chrome.exe]

It also fails on any console error, page error or Content-Security-Policy violation.
"""
import glob
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.abspath(os.path.join(ROOT, "..", "..")))
from playwright.sync_api import sync_playwright  # noqa: E402

from jarvis.cli.commands import notify as cli  # noqa: E402
from jarvis.response import defense  # noqa: E402
from jarvis.response.actions import base  # noqa: E402
from jarvis.response.notify import crypto, devices, qr, relay, replies  # noqa: E402

PORT = 9468
BASE = f"http://localhost:{PORT}"        # WebAuthn needs a hostname, not an IP, as its relying-party id
CONF = {"notify_url": BASE, "notify_label": "web-1"}
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(tempfile.gettempdir(), "argus-ui-approval")
results = {}
problems = []


def check(name, ok, detail=""):
    results[name] = bool(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


class Store:
    def __init__(self):
        self.meta = {}

    def get_meta(self, k, default=None):
        return self.meta.get(k, default)

    def set_meta(self, k, v):
        self.meta[k] = v


class Reversible:
    id, reversible = "quarantine", True


def chrome_path():
    if len(sys.argv) > 2:
        return sys.argv[2]
    found = sorted(glob.glob(os.path.expanduser("~/AppData/Local/ms-playwright/chromium-*/chrome-win64/chrome.exe"))
                   + glob.glob(os.path.expanduser("~/.cache/ms-playwright/chromium-*/chrome-linux/chrome")))
    return found[-1] if found else None


def write_y4m(path, text):
    """A looping fake camera feed that shows the QR code (raw YUV4MPEG2)."""
    w, h, scale, quiet = 640, 480, 6, 4
    m = qr.encode(text)
    n = len(m)
    y = bytearray([255]) * (w * h)
    x0, y0 = (w - n * scale) // 2, (h - n * scale) // 2
    for r in range(n):
        for c in range(n):
            if m[r][c]:
                for dy in range(scale):
                    row = (y0 + r * scale + dy) * w + x0 + c * scale
                    y[row:row + scale] = bytes(scale)
    frame = b"FRAME\n" + bytes(y) + bytes([128]) * (w * h // 2)
    with open(path, "wb") as fh:
        fh.write(f"YUV4MPEG2 W{w} H{h} F30:1 Ip A1:1 C420jpeg\n".encode())
        fh.write(frame * 30)


def wait_port():
    for _ in range(120):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.5)
    return False


def watch(page, label):
    # Chrome logs this itself for any Push subscribe in a private (test) browser; the app handles the failure.
    expected = "Push API in incognito mode"
    page.on("console", lambda m: problems.append(f"{label} console.{m.type}: {m.text}")
            if (m.type in ("error",) or "Content Security Policy" in m.text) and expected not in m.text else None)
    page.on("pageerror", lambda e: problems.append(f"{label} pageerror: {e}"))


def main():
    os.makedirs(OUT, exist_ok=True)
    exe = chrome_path()
    if not exe:
        sys.exit("no Chromium found; pass its path as the second argument")
    srv = subprocess.Popen([os.path.join(ROOT, "node_modules", ".bin", "wrangler"), "dev", "--ip", "127.0.0.1", "--port", str(PORT), "--local",
                            "--log-level", "warn"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_port():
            sys.exit("wrangler dev did not start")
        time.sleep(2)
        ident = crypto.Identity.load(create=True)
        code, secret = crypto.pairing_code(), os.urandom(16)
        relay.call(CONF, ident, "PUT", f"/v1/pair/{code}", {"mb": ident.mailbox, "s_sig": crypto.b64u(ident.sig_pub),
                   "s_enc": crypto.b64u(ident.enc_pub), "label": "web-1", "expires": int(time.time()) + 600})
        link = f"{BASE}/#/pair?c={code}&k={crypto.b64u(secret)}&mb={ident.mailbox}"
        feed = os.path.join(OUT, "qr-feed.y4m")
        write_y4m(feed, link)

        with sync_playwright() as pw:
            browser = pw.chromium.launch(executable_path=exe, headless=True, args=[
                "--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream",
                f"--use-file-for-fake-video-capture={feed}"])
            ctx = browser.new_context(viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True,
                                      permissions=["camera"])
            page = ctx.new_page()
            watch(page, "app")

            def wf(sel, timeout=15000):
                """wait_for_selector that saves a screenshot and the screen's text when it times out."""
                try:
                    return page.wait_for_selector(sel, timeout=timeout)
                except Exception:
                    page.screenshot(path=os.path.join(OUT, "fail.png"))
                    print("WAITING FOR:", sel, "| SCREEN:", " / ".join(page.inner_text("#view")[:500].splitlines()), flush=True)
                    raise

            cdp = ctx.new_cdp_session(page)
            cdp.send("WebAuthn.enable")
            cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                "protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True,
                "isUserVerified": True, "automaticPresenceSimulation": True}})

            # --- scan the QR with the (fake) camera ---
            page.goto(f"{BASE}/#/add")
            wf("text=Scan the QR code", timeout=15000)
            page.screenshot(path=os.path.join(OUT, "1-scan.png"))
            try:
                wf("text=Set up this phone", timeout=30000)
                check("the in-app scanner reads the QR from the camera and opens the setup", True)
            except Exception as exc:
                page.screenshot(path=os.path.join(OUT, "1-scan-failed.png"))
                check("the in-app scanner reads the QR from the camera and opens the setup", False, str(exc)[:200])
                raise

            # --- notifications, passkey, pair ---
            ctx.grant_permissions(["notifications"], origin=BASE)          # what tapping Allow on the system prompt does
            page.click("button:has-text('Allow notifications')")
            wf("text=Notifications are on", timeout=10000)
            page.click("button:has-text('Set up Face ID')")
            try:
                wf("text=Face ID / fingerprint is set up", timeout=15000)
                check("passkey created on a user-verified authenticator and its public key exported", True)
            except Exception as exc:
                page.screenshot(path=os.path.join(OUT, "2-passkey-failed.png"))
                check("passkey created on a user-verified authenticator and its public key exported", False,
                      page.inner_text("#view")[:200])
                raise
            page.screenshot(path=os.path.join(OUT, "2-setup.png"))
            page.click("button:has-text('Pair this phone')")
            wf("text=Almost there", timeout=15000)
            check("the pairing secret is not left in the address bar once the claim is sent", "k=" not in page.url, page.url)
            claim = None
            for _ in range(60):
                claims = relay.call(CONF, ident, "GET", f"/v1/mailbox/{ident.mailbox}/claims?code={code}") or []
                if claims:
                    claim = claims[0]
                    break
                time.sleep(0.5)
            check("the claim reaches the server", claim is not None)
            d_sig, d_enc = crypto.unb64u(claim["d_sig"]), crypto.unb64u(claim["d_enc"])
            passkey = cli._qr_claim(secret, claim, d_sig, d_enc)
            check("the browser's QR proof verifies on the server and brings the passkey", bool(passkey), str(passkey)[:20])
            devices.add({"dev": claim["dev"], "d_sig": claim["d_sig"], "d_enc": claim["d_enc"], "name": claim["name"],
                         "passkey": claim["passkey"]})
            relay.call(CONF, ident, "POST", f"/v1/mailbox/{ident.mailbox}/devices/{claim['dev']}/activate", {"code": code})
            wf("text=Paired", timeout=20000)
            page.screenshot(path=os.path.join(OUT, "3-paired.png"))
            check("the phone shows Paired and that it can approve", "approve reversible" in page.inner_text("#view"))

            # --- an approval arrives; approve with the passkey ---
            store = Store()
            patches = [mock.patch.object(base, "get", lambda i: {"quarantine": Reversible()}.get(i)),
                       mock.patch.object(defense, "approve", return_value=(True, "moved aside")),
                       mock.patch.object(defense, "undo", return_value=(True, "restored"))]
            patches[0].start()
            approve, undo = patches[1].start(), patches[2].start()
            entry = {"action": "quarantine", "title": "Quarantine a dropped file", "target": {"path": "/tmp/x"},
                     "finding": {"severity": "high"}, "job": "files", "preview": "Move /tmp/x aside.", "status": "proposed", "at": 1}
            store.set_meta(defense.LEDGER_META, json.dumps({"e1": entry}))
            aid = replies.offer(store, CONF, "e1", entry)
            check("server offers the approval", bool(aid))
            page.goto(f"{BASE}/#/")
            page.reload()
            wf("text=Approve: Quarantine a dropped file", timeout=20000)
            page.screenshot(path=os.path.join(OUT, "4-inbox.png"))
            check("the inbox marks it as needing approval", "approve" in page.inner_text("#view").lower())
            page.click("text=Approve: Quarantine a dropped file")
            wf("text=Approve with Face ID", timeout=10000)
            page.screenshot(path=os.path.join(OUT, "5-approval.png"))
            body = page.inner_text("#view")
            check("the screen shows what will happen and that it can be undone", "Move /tmp/x aside." in body and "undo" in body.lower())
            page.click("button:has-text('Approve with Face ID')")
            wf("text=Sent. You will get a notification", timeout=15000)
            page.screenshot(path=os.path.join(OUT, "6-sent.png"))
            end = time.time() + 20
            while time.time() < end and not approve.call_count:
                replies.poll(store, CONF)
                time.sleep(1)
            check("server verified the browser's passkey assertion and applied the action",
                  approve.call_count == 1 and approve.call_args.args[1] == "e1")

            # --- undo from the result ---
            store.set_meta(defense.LEDGER_META, json.dumps({"e1": {**entry, "status": "applied",
                           "approved_by": "phone:" + claim["dev"][:10]}}))
            page.goto(f"{BASE}/#/")
            page.reload()
            wf("text=Approved from a phone", timeout=20000)
            page.click("text=Approved from a phone")
            wf("text=Undo with Face ID", timeout=10000)
            page.screenshot(path=os.path.join(OUT, "7-undo.png"))
            page.click("button:has-text('Undo with Face ID')")
            wf("text=Sent. You will get a notification", timeout=15000)
            end = time.time() + 20
            while time.time() < end and not undo.call_count:
                replies.poll(store, CONF)
                time.sleep(1)
            check("undo works end to end", undo.call_count == 1)

            # --- a tampered request is not approvable in the UI ---
            entry2 = {**entry, "target": {"path": "/tmp/y"}}
            store.set_meta(defense.LEDGER_META, json.dumps({"e2": entry2}))
            replies.offer(store, CONF, "e2", entry2)
            for p in patches:
                p.stop()
            page.goto(f"{BASE}/#/")
            page.reload()
            wf("text=Approve: Quarantine a dropped file", timeout=20000)
            page.click("text=Approve: Quarantine a dropped file")
            wf("text=Not now", timeout=10000)
            page.click("button:has-text('Not now')")
            wf("text=You dismissed this", timeout=10000)
            check("Not now dismisses without any biometric prompt", True)
            page.screenshot(path=os.path.join(OUT, "8-dismissed.png"))

            # --- iPhone in Safari (not yet on the Home Screen) is sent to the install guide ---
            ios = browser.new_context(viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True,
                                      user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
                                                 "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1")
            ipage = ios.new_page()
            watch(ipage, "ios")
            ipage.goto(f"{BASE}/#/add")
            ipage.wait_for_selector("text=Add Argus to your Home Screen", timeout=10000)
            ipage.screenshot(path=os.path.join(OUT, "9-ios-install.png"))
            check("iPhone Safari gets the Add to Home Screen guide, not the scanner", "Add to Home Screen" in ipage.inner_text("#view"))
            ipage.goto(f"{BASE}/#/pair?c={code}&k={crypto.b64u(secret)}&mb={ident.mailbox}")
            ipage.wait_for_selector("text=Add Argus to your Home Screen", timeout=10000)
            check("a QR opened as a link in iPhone Safari also lands on the guide", True)
            browser.close()
        check("no console errors, page errors or CSP violations", not problems, "; ".join(problems)[:400])
    finally:
        srv.terminate()
        try:
            srv.wait(10)
        except subprocess.TimeoutExpired:
            srv.kill()
    failed = [k for k, v in results.items() if not v]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed" + (f"; failed: {failed}" if failed else ""))
    print(f"screenshots: {OUT}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
