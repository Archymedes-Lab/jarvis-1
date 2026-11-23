"""Upgrade path: a relay whose mailbox was created BEFORE approvals (no passkey / proof columns, no replies
table) must keep working, and keep its data, when the new code starts on it.

1. start the relay with a persistent state dir; pair a phone the old way (no passkey); deliver an alert
2. stop it; strip the new columns/table from the stored Durable Object database (the old schema)
3. start the new code on that state; the old alert is still readable; replies work; a new QR-style claim carries
   its passkey and proof through to the server

    USERPROFILE=<scratch> HOME=<scratch> python tests/e2e_upgrade.py        (a scratch home: it creates a server identity)
"""
import glob
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.abspath(os.path.join(ROOT, "..", "..")))
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519  # noqa: E402

from jarvis.response.notify import crypto, relay  # noqa: E402

PORT = 9469
BASE = f"http://127.0.0.1:{PORT}"
CONF = {"notify_url": BASE, "notify_label": "upgrade"}
results = {}


def check(name, ok, detail=""):
    results[name] = bool(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


def start(state):
    p = subprocess.Popen([os.path.join(ROOT, "node_modules", ".bin", "wrangler"), "dev", "--ip", "127.0.0.1", "--port", str(PORT),
                          "--local", "--persist-to", state, "--log-level", "warn"], cwd=ROOT,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(120):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=1).close()
            break
        except OSError:
            time.sleep(0.5)
    time.sleep(2)
    return p


def stop(p):
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
    else:
        p.terminate()
    try:
        p.wait(15)
    except subprocess.TimeoutExpired:
        p.kill()
    time.sleep(2)


class Device:
    def __init__(self):
        self.sig, self.enc = ed25519.Ed25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
        self.sig_pub, self.enc_pub = crypto._raw(self.sig.public_key()), crypto._raw(self.enc.public_key())
        self.dev = crypto.key_id(self.sig_pub)

    def call(self, method, path, body=None):
        raw = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {**crypto.sign_request(self.sig, self.sig_pub, method, path, raw, time.time()), "Content-Type": "application/json"}
        req = urllib.request.Request(BASE + path, data=raw if body is not None else None, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")


def pair(ident, dev, extra=None):
    code = crypto.pairing_code()
    relay.call(CONF, ident, "PUT", f"/v1/pair/{code}", {"mb": ident.mailbox, "s_sig": crypto.b64u(ident.sig_pub),
               "s_enc": crypto.b64u(ident.enc_pub), "label": "upgrade", "expires": int(time.time()) + 600})
    body = {"dev": dev.dev, "d_sig": crypto.b64u(dev.sig_pub), "d_enc": crypto.b64u(dev.enc_pub), "name": "phone", "push": None}
    body.update(extra or {})
    status, _ = dev.call("POST", f"/v1/pair/{code}/claim", body)
    return code, status


def downgrade(state):
    """Put every mailbox database back to the pre-approvals schema."""
    n = 0
    for path in glob.glob(os.path.join(state, "**", "*.sqlite"), recursive=True):
        db = sqlite3.connect(path)
        try:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "devices" not in tables:
                continue
            cols = {r[1] for r in db.execute("PRAGMA table_info(devices)")}
            for c in ("passkey", "proof"):
                if c in cols:
                    db.execute(f"ALTER TABLE devices DROP COLUMN {c}")
            db.execute("DROP TABLE IF EXISTS replies")
            db.commit()
            n += 1
        finally:
            db.close()
    return n


def main():
    state = tempfile.mkdtemp(prefix="argus-upgrade-")
    srv = start(state)
    try:
        ident = crypto.Identity.load(create=True)
        old = Device()
        code, status = pair(ident, old)
        relay.call(CONF, ident, "POST", f"/v1/mailbox/{ident.mailbox}/devices/{old.dev}/activate", {"code": code})
        device = {"dev": old.dev, "d_enc": crypto.b64u(old.enc_pub)}
        env = crypto.seal(ident, device, {"kind": "alert", "title": "from before the upgrade", "severity": "high"}, time.time())
        relay.call(CONF, ident, "POST", f"/v1/mailbox/{ident.mailbox}/envelopes", [env])
        check("old-style pairing and alert before the upgrade", status == 200)
        stop(srv)

        n = downgrade(state)
        check("stored database put back to the old schema", n >= 1, f"{n} mailbox database(s)")
        srv = start(state)

        status, inbox = old.call("GET", f"/v1/device/{old.dev}/inbox?mb={ident.mailbox}")
        ok = status == 200 and len(inbox) == 1 and \
            crypto.open_envelope(inbox[0], old.enc, ident.sig_pub)["title"] == "from before the upgrade"
        check("after the upgrade the old phone still reads its old alert", ok, f"{status}")

        replies = relay.call(CONF, ident, "GET", f"/v1/mailbox/{ident.mailbox}/replies")
        check("the new replies queue exists and is empty", replies == [])

        status, _ = old.call("POST", f"/v1/device/{old.dev}/replies?mb={ident.mailbox}",
                             {"id": "a" * 22, "dev": old.dev, "mb": ident.mailbox, "expires": int(time.time()) + 600})
        check("an old phone can post a reply on the migrated mailbox", status == 200, str(status))
        got = relay.call(CONF, ident, "GET", f"/v1/mailbox/{ident.mailbox}/replies")
        check("the server fetches it", len(got) == 1 and got[0]["id"] == "a" * 22)

        new = Device()
        passkey, proof = crypto.b64u(os.urandom(91)), crypto.b64u(os.urandom(32))
        code2, status2 = pair(ident, new, {"passkey": passkey, "proof": proof})
        claims = relay.call(CONF, ident, "GET", f"/v1/mailbox/{ident.mailbox}/claims?code={code2}")
        check("a new QR-style claim carries its passkey and proof to the server",
              status2 == 200 and len(claims) == 1 and claims[0]["passkey"] == passkey and claims[0]["proof"] == proof, str(claims)[:120])
        stop(srv)
        srv = None
    finally:
        if srv:
            stop(srv)
    failed = [k for k, v in results.items() if not v]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed" + (f"; failed: {failed}" if failed else ""))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
