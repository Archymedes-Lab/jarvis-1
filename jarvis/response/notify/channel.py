"""The `notify` alert channel: seal one alert per active device, post them.

It counts as a channel that can reach the owner only while a device is active
and python3-cryptography is present (N5); each send's outcome is kept in the
store's meta for `notify status` and the coverage of alert channels.
"""

import json
import socket
import time

from jarvis.response.notify import crypto, devices, relay

META = "notify_state"
LOCK_SCREEN_TITLE = 90
BODY = 1200


def ready(conf=None):
    """True when sealing for at least one active device is possible."""
    if not devices.active():
        return False
    try:
        crypto._lib()
    except crypto.Unavailable:
        return False
    return True


def payload(subject, text, severity, host=None, now=None, kind="alert", category=None, counts=None,
            extra=None):
    from jarvis.response import categories
    cat = category if category in categories.LABELS else ("test" if kind == "test" else "system")
    from jarvis.core.brand import brand
    out = {"kind": kind, "title": brand(subject)[:LOCK_SCREEN_TITLE], "body": brand(text)[:BODY],
           "severity": severity, "category": cat, "category_label": categories.label(cat),
           "host": host or socket.gethostname(), "at": int(time.time() if now is None else now)}
    if counts:
        out["counts"] = {k: int(v) for k, v in counts.items() if k in categories.LABELS}
    if extra:
        # Fixed fields win: an extra can add (approval_id, challenge ...) but never rewrite what an alert is.
        out = {**extra, **out}
    return out


def send(conf, subject, text, severity="high", kind="alert", now=None, opener=None, store=None,
         category=None, counts=None, extra=None, only=None):
    """'' when the relay accepted the envelopes, else a short reason.

    `extra` adds payload fields (approval requests); `only` limits the devices (a predicate)."""
    now = time.time() if now is None else now
    try:
        ident = crypto.Identity.load()
        targets = [d for d in devices.active() if only is None or only(d)]
        if ident is None or not targets:
            return "no paired device"
        body = payload(subject, text, severity, conf.get("notify_label"), now, kind, category, counts, extra)
        envelopes = [crypto.seal(ident, d, body, now) for d in targets]
        kw = {"opener": opener} if opener else {}
        relay.call(conf, ident, "POST", f"/v1/mailbox/{ident.mailbox}/envelopes", envelopes, now=now, **kw)
        error = ""
    except crypto.Unavailable as exc:
        error = str(exc)
    except (relay.RelayError, ValueError) as exc:
        error = f"relay: {exc}"
    if store is not None:
        state = {"last_try": int(now), "last_error": error}
        if not error:
            state["last_ok"] = int(now)
        try:
            old = json.loads(store.get_meta(META, "{}") or "{}")
        except ValueError:
            old = {}
        store.set_meta(META, json.dumps({**old, **state}, sort_keys=True))
    return error
