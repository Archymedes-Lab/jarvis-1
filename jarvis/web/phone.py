"""/api/phone/*: pair and manage phones for alerts from the dashboard or the
desktop app (jarvis/response/notify/pairing.py holds the state machine and
its invariants).

The server calls `get` and `post` only after its own gates: a credential on
every /api/* route, and for POST also the same-origin check. Routes:

    GET  /api/phone/status         relay, crypto, device counts, last delivery
    GET  /api/phone/devices        paired phones (no key material)
    GET  /api/phone/pair           the current pairing, if any
    POST /api/phone/pair/start     {} -> session, code, relay, expires
    POST /api/phone/pair/poll      {session} -> waiting | claimed{name, sas} | ...
    POST /api/phone/pair/confirm   {session, sas, same} (the owner compared codes)
    POST /api/phone/pair/cancel    {session}
    POST /api/phone/revoke         {device}
    POST /api/phone/test           {}
"""

import re
import socket

from jarvis.response import alert
from jarvis.response.notify import channel, crypto, pairing

ROUTES_GET = ("/api/phone/status", "/api/phone/devices", "/api/phone/pair")
ROUTES_POST = ("/api/phone/pair/start", "/api/phone/pair/poll", "/api/phone/pair/confirm",
               "/api/phone/pair/cancel", "/api/phone/revoke", "/api/phone/test")
_SESSION = re.compile(r"^[0-9a-f]{16}$")
_SAS = re.compile(r"^[0-9]{6}$")
_DEV = re.compile(r"^[A-Za-z0-9_-]{4,64}$")


def _label(conf):
    return str(conf.get("notify_label") or socket.gethostname() or "ARGUS-INSTINCT")


def _send_test(conf, subject, text, store=None):
    return channel.send(conf, subject, text, severity="ok", kind="test", store=store)


def _ident():
    return crypto.Identity.load(create=True)


PAIRINGS = pairing.Pairings(alert.load_conf, _ident, _label, send_fn=_send_test)


def get(path, store, pairings=None, conf_fn=None):
    p = pairings or PAIRINGS
    conf = (conf_fn or alert.load_conf)()
    if path == "/api/phone/status":
        return 200, pairing.status(conf, store)
    if path == "/api/phone/devices":
        return 200, {"devices": pairing.public_devices()}
    if path == "/api/phone/pair":
        return 200, {"pairing": p.current()}
    return 404, {"error": "not found"}


def post(path, body, store, pairings=None, conf_fn=None):
    p = pairings or PAIRINGS
    body = body if isinstance(body, dict) else {}
    sid = str(body.get("session") or "")
    try:
        if path == "/api/phone/pair/start":
            return 200, p.start()
        if path in ("/api/phone/pair/poll", "/api/phone/pair/confirm", "/api/phone/pair/cancel"):
            if not _SESSION.match(sid):
                return 400, {"error": "missing or malformed pairing session"}
            if path.endswith("/poll"):
                return 200, p.poll(sid)
            if path.endswith("/cancel"):
                return 200, p.cancel(sid)
            sas, same = str(body.get("sas") or ""), body.get("same")
            if not _SAS.match(sas) or not isinstance(same, bool):
                return 400, {"error": "confirm needs the 6-digit code shown and same: true or false"}
            return 200, p.confirm(sid, sas, same)
        conf = (conf_fn or alert.load_conf)()
        if path == "/api/phone/revoke":
            dev = str(body.get("device") or "")
            if not _DEV.match(dev):
                return 400, {"error": "missing or malformed device id"}
            ok, message = pairing.revoke(conf, dev)
            return (200 if ok else 404), {"ok": ok, "message": message}
        if path == "/api/phone/test":
            err = _send_test(conf, "Test notification", "If this arrived, alerts will too.", store)
            return (200 if not err else 502), {"ok": not err, "message": "sent" if not err
                                              else f"failed: {pairing.short_error(err)}"}
    except pairing.Busy as exc:
        return 409, {"error": str(exc)}
    except pairing.Refused as exc:
        return 409, {"error": str(exc)}
    except crypto.Unavailable as exc:
        return 503, {"error": f"phone alerts are unavailable here: {pairing.short_error(exc)}"}
    return 404, {"error": "not found"}
