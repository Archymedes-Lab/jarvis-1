"""Local end to end: the real Worker under `wrangler dev`, the server's Python side,
and a scripted phone using the app's protocol.js. Run with HOME set to a scratch
directory (the server identity and device registry are created under it).

    HOME=$(mktemp -d) python3 tests/e2e_local.py
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.abspath(os.path.join(ROOT, "..", "..")))
from jarvis.response.notify import channel, crypto, devices, relay  # noqa: E402

PORT = 9466
# NOTIFY_BASE=https://argus.archymedes.xyz runs the same checks against the deployed relay.
BASE = os.environ.get("NOTIFY_BASE") or f"http://127.0.0.1:{PORT}"
LOCAL = BASE.startswith("http://127.0.0.1")
CONF = {"notify_url": BASE, "notify_label": "e2e-server"}
results = {}


def check(name, ok, detail=""):
    results[name] = bool(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


def wait_port():
    for _ in range(120):
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def main():
    dev_srv = subprocess.Popen(["./node_modules/.bin/wrangler", "dev", "--ip", "127.0.0.1", "--port", str(PORT),
                                "--local", "--log-level", "warn"], cwd=ROOT,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) if LOCAL else None
    try:
        if LOCAL and not wait_port():
            sys.exit("wrangler dev did not start")
        time.sleep(1)
        ident = crypto.Identity.load(create=True)
        code = crypto.pairing_code()
        offer = {"mb": ident.mailbox, "s_sig": crypto.b64u(ident.sig_pub), "s_enc": crypto.b64u(ident.enc_pub),
                 "label": "e2e-server", "expires": int(time.time()) + 600}
        relay.call(CONF, ident, "PUT", f"/v1/pair/{code}", offer)
        # Replaying the server's signed request is refused: a fresh code, so the
        # first send must succeed and only the identical second one fail.
        code2 = crypto.pairing_code()
        body = json.dumps(offer, separators=(",", ":")).encode()
        headers = ident.request_headers("PUT", f"/v1/pair/{code2}", body, time.time())
        req = urllib.request.Request(f"{BASE}/v1/pair/{code2}", data=body, method="PUT",
                                     headers={**headers, "Content-Type": "application/json", "User-Agent": relay.UA})
        statuses = []
        for _ in range(2):
            try:
                urllib.request.urlopen(req, timeout=10)
                statuses.append(200)
            except urllib.error.HTTPError as e:
                statuses.append((e.code, json.loads(e.read() or b"{}").get("error")))
        check("server replay refused", statuses == [200, (409, "replayed request")], f"{statuses}")
        # A signed offer for someone else's mailbox is refused.
        stranger = crypto.Identity.generate()
        try:
            relay.call(CONF, stranger, "PUT", f"/v1/pair/{crypto.pairing_code()}", {**offer, "expires": int(time.time()) + 600})
            check("offer for another mailbox refused", False)
        except relay.RelayError as e:
            check("offer for another mailbox refused", "400" in str(e), str(e))

        phone = subprocess.Popen(["bun", os.path.join(HERE, "e2e_phone.js"), BASE, code], cwd=ROOT,
                                 stdout=subprocess.PIPE, text=True)
        seen = {}
        for line in phone.stdout:
            msg = json.loads(line)
            step = msg.get("step")
            seen[step] = msg
            if step == "sas":
                claims = []
                for _ in range(20):
                    claims = relay.call(CONF, ident, "GET", f"/v1/mailbox/{ident.mailbox}/claims?code={code}")
                    if claims:
                        break
                    time.sleep(0.3)
                check("exactly one pending claim (the racing second phone was refused)", len(claims) == 1
                      and seen["second_claim"]["status"] == 404, f"{len(claims)} claims, second {seen['second_claim']['status']}")
                c = claims[0]
                ours = crypto.sas(ident.sig_pub, ident.enc_pub, crypto.unb64u(c["d_sig"]), crypto.unb64u(c["d_enc"]))
                check("6-digit code matches on both sides", ours == msg["sas"], f"{ours} vs {msg['sas']}")
                devices.add({"dev": c["dev"], "d_sig": c["d_sig"], "d_enc": c["d_enc"], "name": c["name"]})
                relay.call(CONF, ident, "POST", f"/v1/mailbox/{ident.mailbox}/devices/{c['dev']}/activate", {"code": code})
            elif step == "active":
                err = channel.send(CONF, "e2e-server: known-exploited vulnerability fixed but not installed: openssh",
                                   "CVE-2024-6387 — install the update.", severity="critical",
                                   category="updates")
                check("server sends a sealed alert", err == "", err)
            elif step == "message":
                p = msg["payload"]
                check("phone decrypts and verifies the alert", p["severity"] == "critical" and "openssh" in p["title"])
                check("the alert carries its category", p.get("category") == "updates"
                      and p.get("category_label") == "Updates", str(p.get("category")))
                check("relay saw only the envelope fields",
                      msg["relay_saw"] == sorted(["v", "id", "mb", "dev", "sent", "expires", "epk", "iv", "ct", "sig"]))
            elif step == "ack":
                check("ack accepted", msg["status"] == 200)
                try:
                    listed = relay.call(CONF, ident, "GET", f"/v1/mailbox/{ident.mailbox}/devices")
                except relay.RelayError as e:
                    listed = None
                    if LOCAL or "404" not in str(e):
                        check("relay lists devices with liveness", False, str(e))
                    else:
                        print("SKIP  relay lists devices with liveness (route not deployed yet)", flush=True)
                if listed is not None:
                    ours = [d for d in listed if d.get("dev") == devices.active()[0]["dev"]]
                    check("relay lists devices with liveness", len(ours) == 1 and ours[0]["state"] == "active"
                          and ours[0]["push"] is False and (ours[0]["last_seen"] or 0) >= int(time.time()) - 60
                          and set(ours[0]) == {"dev", "name", "state", "added", "last_seen", "push"}, str(ours))
            elif step == "replay":
                check("phone request replay refused", msg["status"] == 409, str(msg["status"]))
            elif step == "same_second":
                check("identical requests in the same second both accepted", msg["status"] == [200, 200], str(msg["status"]))
            elif step == "other_device_inbox":
                check("another device cannot read this inbox", msg["status"] == 403, str(msg["status"]))
            elif step == "forged":
                check("forged signature refused", msg["status"] == 401, str(msg["status"]))
            elif step == "evil_push":
                check("push endpoint outside the push services refused", msg["status"] == 400, str(msg["status"]))
                dev = devices.active()[0]["dev"]
                devices.revoke(dev)
                relay.call(CONF, ident, "DELETE", f"/v1/mailbox/{ident.mailbox}/devices/{dev}")
            elif step == "after_revoke":
                check("revoked phone can read nothing", msg["status"] == 403, str(msg["status"]))
        phone.wait(30)
        check("all phone steps ran", {"claimed", "sas", "active", "message", "after_revoke"} <= set(seen), str(sorted(seen)))
    finally:
        if dev_srv:
            dev_srv.terminate()
            try:
                dev_srv.wait(10)
            except subprocess.TimeoutExpired:
                dev_srv.kill()
    failed = [k for k, v in results.items() if not v]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed" + (f"; failed: {failed}" if failed else ""))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
