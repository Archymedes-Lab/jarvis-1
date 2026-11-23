"""Approving a defense proposal from a paired phone (docs/architecture/ARGUS-NOTIFY.md, "Approvals").

The server never listens (N1): it offers an approval in a sealed envelope, then polls the relay for the
phone's sealed, signed reply. A reply can do exactly two things, and only for ONE outstanding request:

  approve   apply one REVERSIBLE defense proposal (jarvis/response/defense.py) that this server offered
  undo      take back what a phone approved
  deny      dismiss the request (nothing is applied)

Everything else stays on the desktop and the CLI: irreversible actions, spend, identity, fix-apply, config.
Every reply must pass, in this order: a known active device, a valid device signature, a fresh timestamp,
a counter greater than the last one seen (replay), a request this server offered and has not expired, and,
for approve and undo, a WebAuthn assertion (Face ID / fingerprint) over a challenge bound to the exact action.
Each outcome is written to an audit list and announced to every paired phone.
"""

import secrets
import time

from jarvis.response import defense
from jarvis.response.actions import base
from jarvis.response.notify import channel, crypto, devices, relay

META = "notify_approvals"
APPROVAL_TTL = 600           # seconds a request can be answered
UNDO_TTL = 3600              # seconds an undo stays available after an approval
REPLY_WINDOW = 900           # a reply must have been sealed this recently
MAX_PENDING = 50
AUDIT_KEEP = 200
TARGET_MAX = 200             # the target text shown to the phone and bound into the challenge
MAX_REPLIES = 50
# Only proposals for serious findings are pushed to a phone for approval: the ledger can hold hundreds of
# low-severity proposals (on the owner's machine, 399 on 2026-11-04), and a stream of "Approve?" prompts
# trains a reflex tap. The same threshold defense.py uses before a reversible action may run unasked.
OFFER_SEVERITIES = defense.AUTO_MIN_SEVERITY


def _state(store):
    import json
    try:
        st = json.loads(store.get_meta(META, "{}") or "{}")
    except ValueError:
        st = {}
    if not isinstance(st, dict):
        st = {}
    st.setdefault("pending", {})
    st.setdefault("audit", [])
    return st


def _save(store, st):
    import json
    st["audit"] = st["audit"][-AUDIT_KEEP:]
    store.set_meta(META, json.dumps(st, sort_keys=True))


def _prune(st, now):
    for aid in [a for a, p in st["pending"].items() if p.get("expires", 0) <= now]:
        del st["pending"][aid]


def audit(st, now, **fields):
    st["audit"].append({"at": int(now), **{k: (str(v)[:200] if isinstance(v, str) else v) for k, v in fields.items()}})


def worth_a_phone_prompt(entry):
    """Whether a proposal is serious enough to push to a phone (the desktop and CLI still list all)."""
    finding = entry.get("finding") if isinstance(entry, dict) and isinstance(entry.get("finding"), dict) else {}
    return finding.get("severity") in OFFER_SEVERITIES


def phone_can_approve(entry):
    """The allowlist: a proposal that is still waiting and whose action is reversible."""
    if not isinstance(entry, dict) or entry.get("status") != "proposed":
        return False
    action = base.get(entry.get("action"))
    return bool(action is not None and action.reversible is True)


def _has_passkey(d):
    return bool(d.get("passkey"))


def _target(entry_or_text):
    return str(entry_or_text)[:TARGET_MAX]


def _extra(approval_id, kind, eid, action, target, expires):
    challenge = crypto.approval_challenge(approval_id, eid, action, target, expires)
    return {"approval_id": approval_id, "approval": kind, "eid": eid, "action": action, "target": target,
            "expires": int(expires), "challenge": crypto.b64u(challenge)}


def offer(store, conf, eid, entry, now=None, opener=None):
    """Ask paired phones to approve proposal `eid`. Returns the approval id, or '' when nothing was offered
    (no phone with a passkey, not allowed from a phone, already offered, relay unreachable)."""
    now = time.time() if now is None else now
    if store is None or not phone_can_approve(entry) or not worth_a_phone_prompt(entry):
        return ""
    if not any(_has_passkey(d) for d in devices.active()):
        return ""
    st = _state(store)
    _prune(st, now)
    if len(st["pending"]) >= MAX_PENDING or any(p.get("eid") == eid and p.get("kind") == "approve"
                                                for p in st["pending"].values()):
        return ""
    approval_id = crypto.b64u(secrets.token_bytes(16))
    target = _target(entry.get("target"))
    expires = int(now) + APPROVAL_TTL
    extra = _extra(approval_id, "approve", eid, entry["action"], target, expires)
    extra["preview"] = str(entry.get("preview") or "")[:600]
    finding = entry.get("finding") if isinstance(entry.get("finding"), dict) else {}
    severity = finding["severity"]                    # critical or high (worth_a_phone_prompt)
    text = "Tap to see what will happen. You can undo it afterwards."
    kw = {"opener": opener} if opener else {}
    err = channel.send(conf, f"Approve: {entry.get('title') or entry['action']}", text, severity=severity,
                       kind="approval", now=now, store=store, extra=extra, only=_has_passkey, **kw)
    if err:
        return ""
    devs = [d["dev"] for d in devices.active() if _has_passkey(d)]
    st["pending"][approval_id] = {"kind": "approve", "eid": eid, "action": entry["action"], "target": target,
                                  "expires": expires, "challenge": extra["challenge"], "devs": devs}
    _save(store, st)
    return approval_id


def _announce(store, conf, title, text, severity, now, opener, undo=None):
    """Tell every paired phone what happened. Phones with a passkey also get the undo offer."""
    kw = {"opener": opener} if opener else {}
    if undo:
        channel.send(conf, title, text, severity=severity, kind="result", now=now, store=store, extra=undo,
                     only=_has_passkey, **kw)
        channel.send(conf, title, text, severity=severity, kind="result", now=now, store=store,
                     only=lambda d: not _has_passkey(d), **kw)
    else:
        channel.send(conf, title, text, severity=severity, kind="result", now=now, store=store, **kw)


def _rp(conf):
    """The WebAuthn origin and relying-party id of the phone app: the relay's own address."""
    from urllib.parse import urlsplit
    parts = urlsplit(relay.base_url(conf))
    return f"{parts.scheme}://{parts.netloc}", parts.hostname


def _check_passkey(conf, device, payload, pending):
    assertion = payload.get("assertion")
    if not isinstance(assertion, dict) or not device.get("passkey"):
        return "no biometric proof"
    origin, rp_id = _rp(conf)
    try:
        count = crypto.verify_webauthn(crypto.unb64u(device["passkey"]), assertion, crypto.unb64u(pending["challenge"]),
                                       rp_id=rp_id, origin=origin)
    except ValueError as exc:
        return f"passkey check failed: {exc}"
    last = int(device.get("sign_count") or 0)
    if count and last and count <= last:
        return "passkey counter went backwards (cloned key?)"
    if count:
        devices.update(device["dev"], sign_count=count)
    return ""


def handle(store, conf, ident, st, reply, now, opener=None):
    """One reply. Returns (outcome, detail); outcome is 'approved', 'undone', 'denied' or 'rejected'."""
    dev = str(reply.get("dev") or "")
    device = devices.get(dev)
    if device is None:
        return "rejected", "unknown or revoked device"
    try:
        payload = crypto.open_reply(reply, ident, crypto.unb64u(device["d_sig"]))
    except Exception:                                  # signature, tag, malformed: never say which
        return "rejected", "reply did not verify"
    if not isinstance(payload, dict):
        return "rejected", "malformed reply"
    sent, expires = reply.get("sent"), reply.get("expires")
    if not isinstance(sent, int) or not isinstance(expires, int) or abs(now - sent) > REPLY_WINDOW or expires < now:
        return "rejected", "stale reply"
    counter = payload.get("counter")
    last = int(device.get("last_counter") or 0)
    if not isinstance(counter, int) or counter <= last:
        return "rejected", "replayed reply"
    devices.update(dev, last_counter=counter)          # burn the counter before acting on it
    pending = st["pending"].get(str(payload.get("approval_id") or ""))
    if pending is None:
        return "rejected", "no such request, or it expired"
    if pending["expires"] <= now:
        st["pending"].pop(payload["approval_id"], None)
        return "rejected", "request expired"
    if dev not in pending.get("devs", []):
        return "rejected", "this phone was not asked"
    decision = payload.get("decision")
    if decision == "deny":
        st["pending"].pop(payload["approval_id"], None)
        _announce(store, conf, "Dismissed on a phone", f"{device.get('name', 'A phone')} dismissed: {pending['action']}",
                  "ok", now, opener)
        return "denied", pending["action"]
    if decision != "approve":
        return "rejected", "unknown decision"
    why = _check_passkey(conf, device, payload, pending)
    if why:
        return "rejected", why

    ledger = defense.load(store)
    entry = ledger.get(pending["eid"])
    if pending["kind"] == "undo":
        if not (isinstance(entry, dict) and entry.get("status") == "applied"
                and str(entry.get("approved_by") or "").startswith("phone:")):
            st["pending"].pop(payload["approval_id"], None)
            return "rejected", "nothing a phone approved can be undone here"
        ok, detail = defense.undo(store, pending["eid"])
        st["pending"].pop(payload["approval_id"], None)
        _announce(store, conf, "Undone from a phone" if ok else "Undo failed",
                  f"{entry.get('title') or pending['action']}: {detail}", "ok" if ok else "high", now, opener)
        return ("undone" if ok else "rejected"), detail

    if not phone_can_approve(entry) or entry.get("action") != pending["action"] \
            or _target(entry.get("target")) != pending["target"]:
        st["pending"].pop(payload["approval_id"], None)
        return "rejected", "that proposal is no longer waiting, or it changed"
    st["pending"].pop(payload["approval_id"], None)
    ok, detail = defense.approve(store, pending["eid"], now=now, conf=conf, by=f"phone:{dev[:10]}")
    undo = None
    if ok:
        aid = crypto.b64u(secrets.token_bytes(16))
        undo_expires = int(now) + UNDO_TTL
        undo = _extra(aid, "undo", pending["eid"], pending["action"], pending["target"], undo_expires)
        st["pending"][aid] = {"kind": "undo", "eid": pending["eid"], "action": pending["action"],
                              "target": pending["target"], "expires": undo_expires,
                              "challenge": undo["challenge"], "devs": pending["devs"]}
    _announce(store, conf, "Approved from a phone" if ok else "Approval did not apply",
              f"{entry.get('title') or pending['action']}: {detail}", "ok" if ok else "high", now, opener, undo)
    return ("approved" if ok else "rejected"), detail


def poll(store, conf, now=None, opener=None, force=False):
    """Fetch and process the phone's replies. Cheap when nothing is outstanding (no request is made).
    Returns a small summary dict."""
    now = time.time() if now is None else now
    out = {"checked": False, "handled": 0}
    st = _state(store)
    _prune(st, now)
    if not st["pending"] and not force:
        _save(store, st)
        return out
    ident = crypto.Identity.load()
    if ident is None:
        return out
    kw = {"opener": opener} if opener else {}
    try:
        replies = relay.call(conf, ident, "GET", f"/v1/mailbox/{ident.mailbox}/replies", now=now, **kw) or []
    except relay.RelayError as exc:
        out["error"] = str(exc)
        return out
    out["checked"] = True
    done = []
    for reply in [r for r in replies if isinstance(r, dict)][:MAX_REPLIES]:
        done.append(str(reply.get("id") or ""))
        try:
            outcome, detail = handle(store, conf, ident, st, reply, now, opener)
        except Exception as exc:                       # one bad reply must not stop the others
            outcome, detail = "rejected", f"error: {type(exc).__name__}"
        audit(st, now, dev=reply.get("dev"), outcome=outcome, detail=detail)
        out["handled"] += 1
    _save(store, st)
    done = [i for i in done if i]
    if done:
        try:
            relay.call(conf, ident, "POST", f"/v1/mailbox/{ident.mailbox}/replies/ack", {"ids": done}, now=now, **kw)
        except relay.RelayError as exc:
            out["error"] = str(exc)
    return out


# --- the scheduler's side ---------------------------------------------------------------
#
# defense.process (inside a collection run) only QUEUES an offer: no network call may stall a collector.
# tick() runs from the scheduler's housekeeping, sends the queued offers, and polls for replies.

POLL_EVERY_S = 5
QUEUE_MAX = 50


def queue_offer(store, eid):
    """Remember that proposal `eid` should be offered to phones. Cheap and local; never raises."""
    try:
        if store is None or not any(_has_passkey(d) for d in devices.active()):
            return False
        st = _state(store)
        queue = st.setdefault("queue", [])
        if eid in queue or len(queue) >= QUEUE_MAX:
            return False
        queue.append(eid)
        _save(store, st)
        return True
    except Exception:
        return False


def register():
    """Hear about new defense proposals (idempotent). The scheduler calls it before its first collection."""
    if queue_offer not in defense.PROPOSAL_LISTENERS:
        defense.PROPOSAL_LISTENERS.append(queue_offer)


register()


def flush_offers(store, conf, now=None, opener=None):
    """Offer every queued proposal that is still waiting. Returns how many were offered."""
    st = _state(store)
    queue = list(st.get("queue") or [])
    if not queue:
        return 0
    st["queue"] = []
    _save(store, st)
    ledger = defense.load(store)
    sent = 0
    for eid in queue:
        if offer(store, conf, eid, ledger.get(eid), now=now, opener=opener):
            sent += 1
    return sent


def tick(store, conf, now=None, opener=None):
    """One housekeeping pass: send queued offers, then handle replies. Never raises."""
    try:
        flush_offers(store, conf, now=now, opener=opener)
        return poll(store, conf, now=now, opener=opener)
    except Exception as exc:
        return {"checked": False, "handled": 0, "error": type(exc).__name__}
