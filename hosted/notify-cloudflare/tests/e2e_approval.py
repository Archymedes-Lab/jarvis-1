"""Approvals end to end: the real Worker under `wrangler dev`, the server's Python side (offer, poll, verify,
apply), and a scripted phone running the app's own protocol.js with a software passkey.

    USERPROFILE=<scratch> HOME=<scratch> python tests/e2e_approval.py        (a scratch home: it creates a server identity)

NOTIFY_BASE=http://127.0.0.1:9466 uses a relay that is already running instead of starting one.
"""
import json
import os
import socket
import subprocess
import sys
import time
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.abspath(os.path.join(ROOT, "..", "..")))
from jarvis.cli.commands import notify as cli  # noqa: E402
from jarvis.response import defense  # noqa: E402
from jarvis.response.actions import base  # noqa: E402
from jarvis.response.notify import crypto, devices, relay, replies  # noqa: E402

PORT = 9466
BASE = os.environ.get("NOTIFY_BASE") or f"http://127.0.0.1:{PORT}"
OWN_RELAY = not os.environ.get("NOTIFY_BASE")
CONF = {"notify_url": BASE, "notify_label": "e2e-server"}
results = {}


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


class Irreversible:
    id, reversible = "wipe", False


def wait_port():
    for _ in range(120):
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


class Phone:
    def __init__(self, code, secret):
        bun = "bun"
        cand = os.path.join(os.environ.get("APPDATA", ""), "npm", "node_modules", "bun", "bin", "bun.exe")
        if os.path.exists(cand):
            bun = cand
        self.p = subprocess.Popen([bun, os.path.join(HERE, "e2e_phone_approval.js"), BASE, code, crypto.b64u(secret)],
                                  cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8")

    def send(self, **cmd):
        self.p.stdin.write(json.dumps(cmd) + "\n")
        self.p.stdin.flush()

    def read(self, step):
        for line in self.p.stdout:
            msg = json.loads(line)
            if msg.get("step") == step:
                return msg
        raise RuntimeError(f"phone ended before {step}")

    def close(self):
        try:
            self.send(cmd="quit")
            self.p.wait(15)
        except Exception:
            self.p.kill()


def poll_until(store, want, seconds=20):
    end = time.time() + seconds
    last = {}
    while time.time() < end:
        last = replies.poll(store, CONF)
        if last.get("handled"):
            return last
        time.sleep(1)
    return last


def pair(code, secret, phone, **pair_cmd):
    ident = crypto.Identity.load(create=True)
    relay.call(CONF, ident, "PUT", f"/v1/pair/{code}", {"mb": ident.mailbox, "s_sig": crypto.b64u(ident.sig_pub),
               "s_enc": crypto.b64u(ident.enc_pub), "label": "e2e-server", "expires": int(time.time()) + 600})
    phone.send(cmd="pair", **pair_cmd)
    claim = None
    for _ in range(40):
        claims = relay.call(CONF, ident, "GET", f"/v1/mailbox/{ident.mailbox}/claims?code={code}") or []
        if claims:
            claim = claims[0]
            break
        time.sleep(0.3)
    d_sig, d_enc = crypto.unb64u(claim["d_sig"]), crypto.unb64u(claim["d_enc"])
    passkey = cli._qr_claim(secret, claim, d_sig, d_enc)
    dev = {"dev": claim["dev"], "d_sig": claim["d_sig"], "d_enc": claim["d_enc"], "name": claim["name"]}
    if passkey:
        dev["passkey"] = claim["passkey"]
    devices.add(dev)
    relay.call(CONF, ident, "POST", f"/v1/mailbox/{ident.mailbox}/devices/{claim['dev']}/activate", {"code": code})
    return ident, claim, passkey


def main():
    srv = subprocess.Popen(["./node_modules/.bin/wrangler", "dev", "--ip", "127.0.0.1", "--port", str(PORT), "--local",
                            "--log-level", "warn"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) if OWN_RELAY else None
    phone = None
    try:
        if OWN_RELAY and not wait_port():
            sys.exit("wrangler dev did not start")
        time.sleep(2)
        code, secret = crypto.pairing_code(), os.urandom(16)
        phone = Phone(code, secret)
        ident, claim, passkey = pair(code, secret, phone)
        phone.read("claimed")
        check("QR claim carries a proof the server accepts, with the passkey", passkey and passkey == claim["passkey"])
        phone.read("active")

        store = Store()
        patches = [mock.patch.object(base, "get", lambda i: {"quarantine": Reversible(), "wipe": Irreversible()}.get(i)),
                   mock.patch.object(defense, "approve", return_value=(True, "moved aside")),
                   mock.patch.object(defense, "undo", return_value=(True, "restored"))]
        approve, undo = patches[1].start(), patches[2].start()
        patches[0].start()
        entry = {"action": "quarantine", "title": "Quarantine a dropped file", "target": {"path": "/tmp/x"},
                 "finding": {"severity": "high"}, "job": "files", "preview": "Move /tmp/x aside.", "status": "proposed", "at": 1}
        store.set_meta(defense.LEDGER_META, json.dumps({"e1": entry}))

        # --- approve ---
        aid = replies.offer(store, CONF, "e1", entry)
        check("server offers the approval through the relay", bool(aid))
        phone.send(cmd="inbox")
        msg = phone.read("inbox")
        req = next((i for i in msg["items"] if i.get("kind") == "approval"), None)
        check("phone decrypts the request and its challenge checks out", req and req["approval"] == "approve" and req["eid"] == "e1", str(msg)[:300])
        if not req:
            sys.exit("no approval reached the phone")
        phone.send(cmd="answer", request=req, decision="approve")
        ans = phone.read("answered")
        check("phone recomputed the same challenge from what it shows", ans["challengeOk"] is True)
        check("relay accepted the sealed reply and saw only envelope fields",
              ans["status"] == 200 and ans["relay_saw"] == sorted(["v", "id", "mb", "dev", "sent", "expires", "epk", "iv", "ct", "sig"]),
              str(ans["status"]))
        out = poll_until(store, 1)
        check("server verified signature, counter and Face-ID assertion, then applied the action",
              approve.call_count == 1 and approve.call_args.args[1] == "e1", str(out))
        check("the approval is recorded as made by the phone", approve.call_args.kwargs["by"].startswith("phone:"))
        phone.send(cmd="inbox")
        res = phone.read("inbox")
        done = next((i for i in res["items"] if i.get("kind") == "result"), None)
        check("every phone is told the outcome, and offered Undo", done and done.get("approval") == "undo", str(res["items"])[:200])

        # --- a request signed for the wrong action is refused ---
        entry2 = {**entry, "target": {"path": "/tmp/y"}}
        store.set_meta(defense.LEDGER_META, json.dumps({"e2": entry2}))
        aid2 = replies.offer(store, CONF, "e2", entry2)
        phone.send(cmd="inbox")
        req2 = next(i for i in phone.read("inbox")["items"] if i.get("kind") == "approval")
        before = approve.call_count
        phone.send(cmd="answer", request=req2, decision="approve", wrongChallenge=True)
        phone.read("answered")
        poll_until(store, 1)
        check("biometric proof for another action is refused", approve.call_count == before)
        phone.send(cmd="answer", request=req2, decision="approve", flags=1)       # user present, NOT verified
        phone.read("answered")
        poll_until(store, 1)
        check("an assertion without user verification is refused", approve.call_count == before)

        # --- undo (only for what a phone approved) ---
        store.set_meta(defense.LEDGER_META, json.dumps({"e1": {**entry, "status": "applied", "approved_by": "phone:" + claim["dev"][:10]}}))
        phone.send(cmd="answer", request=done, decision="approve")
        phone.read("answered")
        poll_until(store, 1)
        check("undo offered after an approval is honoured", undo.call_count == 1)

        # --- deny, and a revoked phone ---
        phone.send(cmd="answer", request=req2, decision="deny")
        phone.read("answered")
        poll_until(store, 1)
        check("deny applies nothing", approve.call_count == before)
        dev = devices.active()[0]["dev"]
        devices.revoke(dev)
        relay.call(CONF, ident, "DELETE", f"/v1/mailbox/{ident.mailbox}/devices/{dev}")
        phone.send(cmd="answer", request=req2, decision="deny")
        check("a revoked phone cannot post replies", phone.read("answered")["status"] == 403)
        for p in patches:
            p.stop()

        # --- a typed-code phone (no QR proof) gets alerts only ---
        code2, secret2 = crypto.pairing_code(), os.urandom(16)
        phone2 = Phone(code2, secret2)
        try:
            ident2, claim2, passkey2 = pair(code2, os.urandom(16), phone2)         # the server holds a different secret
            phone2.read("claimed")
            check("a claim whose proof the server cannot verify is not trusted with approvals", passkey2 is None)
            check("...and the registry holds no passkey for it", not devices.get(claim2["dev"]).get("passkey"))
            phone2.read("active")
        finally:
            phone2.close()
    finally:
        if phone:
            phone.close()
        if srv:
            srv.terminate()
            try:
                srv.wait(10)
            except subprocess.TimeoutExpired:
                srv.kill()
    failed = [k for k, v in results.items() if not v]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed" + (f"; failed: {failed}" if failed else ""))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
