r"""Phone pairing through the sealed relay: the steps `notify pair` and the
desktop/dashboard API share (docs/architecture/ARGUS-NOTIFY.md).

Steps (each one relay call or one local check):

    offer        PUT /v1/pair/<code>: the relay may hand our public keys to
                 whichever phone enters the one-time code
    find_claim   GET the claims for that code: the phone's public keys and name
    check_claim  the keys are 32 bytes each and hash to the claimed device id
    reject       DELETE the claim (the owner said the 6-digit codes differ)
    accept       record the device locally, then activate it on the relay

`Session` is the API's state machine for one pairing at a time:

    waiting --(phone claimed the code)--> claimed --(owner: same)----> paired
       |                                     |  \--(owner: differ)--> rejected
       +--(10 minutes)--> expired            +--(10 minutes)--> expired
       +--(relay refused the offer / malformed claim)--> error

Invariants (tests/test_phone_pairing.py):
- The 6-digit comparison is never skipped: only `confirm` with the exact SAS
  that `poll` showed, for this session, while `claimed`, can pair a phone.
  A stale or mismatched SAS, a second confirm, or a confirm in any other state
  is refused and changes nothing.
- The page sees only: session id, pairing code (it must be typed on the phone),
  relay URL, expiry, device id, the claimed name (control characters removed)
  and the SAS. Never key material, mailbox signing keys or tokens.
- Bounded: one live session at a time (a second start is refused until the
  first ends or expires); 10-minute expiry on a monotonic clock; no thread of
  its own: each poll makes at most one relay call, at most every POLL_MIN_S,
  and never two at once.
- A daemon restart loses the session: the claim stays pending on the relay and
  is never activated, so nothing is paired without the owner's comparison.
"""

import json
import secrets
import threading
import time

from jarvis.response.notify import channel, crypto, devices, relay

PAIR_WAIT_S = 600
POLL_MIN_S = 2.0
ACTIVATE_TRIES = 5
ACTIVATE_WAIT_S = 6
NAME_LIMIT = 40
ERROR_LIMIT = 160


def printable(text, limit=NAME_LIMIT):
    """A name chosen by whoever claimed the code, made safe to show: control
    characters (escape sequences could hide or fake the 6-digit code shown
    beside it) become spaces."""
    return "".join(ch if ch.isprintable() else " " for ch in str(text))[:limit].strip() or "phone"


def short_error(exc):
    return printable(exc, ERROR_LIMIT) if str(exc) else type(exc).__name__


def offer(conf, ident, code, label, expires):
    relay.call(conf, ident, "PUT", f"/v1/pair/{code}",
               {"mb": ident.mailbox, "s_sig": crypto.b64u(ident.sig_pub),
                "s_enc": crypto.b64u(ident.enc_pub), "label": label, "expires": expires})


def find_claim(conf, ident, code):
    """The claim a phone made for `code`, or None yet. Raises RelayError."""
    claims = relay.call(conf, ident, "GET", f"/v1/mailbox/{ident.mailbox}/claims?code={code}") or []
    if not isinstance(claims, list):
        return None
    return next((c for c in claims if isinstance(c, dict) and c.get("code") == code), None)


def check_claim(ident, claim):
    """(dev, name, sas) of a well-formed claim; ValueError otherwise."""
    try:
        d_sig, d_enc = crypto.unb64u(claim["d_sig"]), crypto.unb64u(claim["d_enc"])
        dev = claim.get("dev")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"malformed claim ({type(exc).__name__})") from None
    if len(d_sig) != 32 or len(d_enc) != 32 or not isinstance(dev, str) or crypto.key_id(d_sig) != dev:
        raise ValueError("device keys do not match the device id")
    return dev, printable(claim.get("name") or "phone"), crypto.sas(ident.sig_pub, ident.enc_pub, d_sig, d_enc)


def reject(conf, ident, dev):
    """Delete the claim on the relay; '' or why it could not."""
    try:
        relay.call(conf, ident, "DELETE", f"/v1/mailbox/{ident.mailbox}/devices/{dev}")
        return ""
    except relay.RelayError as exc:
        return short_error(exc)


def activate(conf, ident, dev, code, tries=ACTIVATE_TRIES, wait=ACTIVATE_WAIT_S, sleep=time.sleep):
    """Tell the relay the owner confirmed this phone; '' when it agreed.

    Retried: a relay hiccup here used to leave a device recorded locally but
    pending on the relay, so every later send failed with "unknown or inactive
    device" and nothing said why."""
    err = ""
    for attempt in range(tries):
        try:
            relay.call(conf, ident, "POST", f"/v1/mailbox/{ident.mailbox}/devices/{dev}/activate", {"code": code})
            return ""
        except relay.RelayError as exc:
            err = str(exc)
            if err.startswith("HTTP 404"):
                return err      # no pending claim any more: retrying cannot help
        if attempt + 1 < tries:
            sleep(wait)
    return err


def accept(conf, ident, claim, code, name, activate_fn=None, passkey=None):
    """Record the confirmed phone, then activate it on the relay; '' or the
    activation error (the device then stays visibly 'not activated').

    `passkey` only for a phone whose claim proved it scanned the QR (notify
    pair): it is what lets that phone approve reversible actions."""
    device = {"dev": claim["dev"], "d_sig": claim["d_sig"], "d_enc": claim["d_enc"], "name": name,
              "relay_pending": True}
    if passkey:
        device["passkey"] = passkey
    devices.add(device)
    err = (activate_fn or activate)(conf, ident, claim["dev"], code)
    if not err:
        devices.mark_active(claim["dev"])
    return err


def public_devices(path=None):
    """The device registry without key material."""
    out = []
    for d in devices.load(path)["devices"]:
        out.append({"dev": str(d.get("dev", "")), "name": printable(d.get("name", "phone")),
                    "paired_at": d.get("paired_at"), "revoked_at": d.get("revoked_at"),
                    "pending": bool(d.get("relay_pending")) and not d.get("revoked_at")})
    return out


class Busy(RuntimeError):
    """Another pairing is in progress."""


class Refused(RuntimeError):
    """The request does not apply to the current pairing state."""


class Session:
    """One pairing driven by the page's polls (see the module docstring)."""

    def __init__(self, conf, ident, label, now=time.monotonic, wall=time.time):
        self.conf, self.ident, self.label = conf, ident, label
        self.now, self.wall = now, wall
        self.id = secrets.token_hex(8)
        self.code = crypto.pairing_code()
        self.started = now()
        self.expires_at = int(wall()) + PAIR_WAIT_S
        self.state = "waiting"
        self.message = ""
        self.claim = None
        self.dev = self.name = self.sas = None
        self.last_poll = -1e9
        self.polling = False
        self.notice = ""
        self.warning = False

    def expired(self):
        return self.now() - self.started >= PAIR_WAIT_S

    def live(self):
        if self.state in ("waiting", "claimed") and self.expired():
            self.state, self.message = "expired", "no confirmation within 10 minutes"
        return self.state in ("waiting", "claimed")

    def view(self):
        self.live()
        try:
            url = relay.base_url(self.conf)
        except relay.RelayError:
            url = ""                                     # the offer itself reported why
        out = {"session": self.id, "state": self.state, "code": crypto.format_code(self.code),
               "relay": url, "expires": self.expires_at,
               "remaining": max(0, int(PAIR_WAIT_S - (self.now() - self.started)))}
        if self.dev:
            out.update({"device": self.dev, "name": self.name})
        if self.state == "claimed":
            out["sas"] = self.sas
        if self.message:
            out["message"] = self.message
        if self.notice:
            out["notice"] = self.notice
        if self.warning:
            out["warning"] = True
        return out


class Pairings:
    """The daemon's single pairing slot. Thread-safe; holds no thread."""

    def __init__(self, conf_fn, ident_fn, label_fn, now=time.monotonic, wall=time.time,
                 activate_fn=None, send_fn=None):
        self.conf_fn, self.ident_fn, self.label_fn = conf_fn, ident_fn, label_fn
        self.now, self.wall = now, wall
        self.activate_fn, self.send_fn = activate_fn, send_fn
        self.lock = threading.Lock()
        self.session = None

    def _get(self, sid):
        s = self.session
        if s is None or not secrets.compare_digest(str(sid or ""), s.id):
            raise Refused("no such pairing (it ended or was replaced); start again")
        return s

    def start(self):
        with self.lock:
            if self.session is not None and self.session.live():
                raise Busy("a pairing is already in progress; finish or cancel it first")
            conf = self.conf_fn()
            ident = self.ident_fn()                      # may raise crypto.Unavailable
            s = Session(conf, ident, self.label_fn(conf)[:NAME_LIMIT], self.now, self.wall)
            self.session = s
        try:
            offer(conf, ident, s.code, s.label, s.expires_at)
        except relay.RelayError as exc:
            with self.lock:
                s.state, s.message = "error", f"the relay refused the pairing offer ({short_error(exc)})"
        with self.lock:
            return s.view()

    def poll(self, sid):
        with self.lock:
            s = self._get(sid)
            if not s.live() or s.state != "waiting" or s.polling or s.now() - s.last_poll < POLL_MIN_S:
                return s.view()
            s.polling, s.last_poll = True, s.now()
        try:
            claim, err = find_claim(s.conf, s.ident, s.code), ""
        except relay.RelayError as exc:
            claim, err = None, short_error(exc)
        with self.lock:
            s.polling = False
            if self.session is not s or not s.live() or s.state != "waiting":
                return s.view()
            s.notice = f"relay: {err}; retrying" if err else ""
            if claim is not None:
                try:
                    s.dev, s.name, s.sas = check_claim(s.ident, claim)
                    s.claim, s.state = claim, "claimed"
                except ValueError as exc:
                    s.state, s.message = "error", f"the relay returned a {exc}; nothing was paired"
            return s.view()

    def confirm(self, sid, sas, same):
        """The owner compared the 6-digit codes. Only the exact SAS shown, once."""
        with self.lock:
            s = self._get(sid)
            if not s.live() or s.state != "claimed":
                raise Refused(f"this pairing is {s.state}; nothing to confirm")
            if not isinstance(same, bool) or not secrets.compare_digest(str(sas or ""), s.sas or "\0"):
                raise Refused("that is not the code this pairing showed")
            s.state = "confirming"                          # a second confirm now fails
        if not same:
            err = reject(s.conf, s.ident, s.dev)
            with self.lock:
                s.state = "rejected"
                s.message = ("not paired. If the codes differed, someone may be interfering; pair again."
                             + (f" (relay did not confirm the removal: {err})" if err else ""))
                return s.view()
        try:
            err = accept(s.conf, s.ident, s.claim, s.code, s.name, self.activate_fn)
        except (ValueError, OSError) as exc:                # registry full or unwritable
            with self.lock:
                s.state, s.message = "error", short_error(exc)
                return s.view()
        if err:
            note = (f"paired here, but the relay did not activate the phone ({short_error(err)}); "
                    "it will not receive alerts until you pair it again")
        else:
            send = self.send_fn
            terr = send(s.conf, f"{s.label} is paired", "Alerts from this computer will arrive here.") if send else ""
            note = "a test notification is on its way" if not terr else f"test notification failed: {short_error(terr)}"
        with self.lock:
            s.state, s.message, s.warning = "paired", note, bool(err)
            return s.view()

    def cancel(self, sid):
        with self.lock:
            s = self._get(sid)
            dev = s.dev if s.state == "claimed" else None
            if s.state in ("waiting", "claimed"):
                s.state, s.message = "cancelled", "pairing cancelled"
        if dev:
            reject(s.conf, s.ident, dev)
        with self.lock:
            return s.view()

    def current(self):
        with self.lock:
            return self.session.view() if self.session is not None else None


def status(conf, store=None, ident_fn=None):
    """What the page may show about phone alerts: relay, crypto availability,
    device counts, last delivery. No relay call, no key material."""
    try:
        crypto._lib()
        crypto_ok, crypto_msg = True, ""
    except crypto.Unavailable as exc:
        crypto_ok, crypto_msg = False, short_error(exc)
    try:
        ident = (ident_fn or crypto.Identity.load)()
    except crypto.Unavailable:
        ident = None
    try:
        url, url_err = relay.base_url(conf), ""
    except relay.RelayError as exc:
        url, url_err = "", short_error(exc)
    state = {}
    if store is not None:
        try:
            state = json.loads(store.get_meta(channel.META, "{}") or "{}")
        except (ValueError, TypeError):
            state = {}
    live = [d for d in public_devices() if not d["revoked_at"]]
    return {"relay": url, "relay_error": url_err, "crypto": crypto_ok, "crypto_error": crypto_msg,
            "identity": ident is not None, "devices": len(live),
            "pending": sum(1 for d in live if d["pending"]),
            "last_ok": state.get("last_ok") if isinstance(state, dict) else None,
            "last_error": printable(state["last_error"], ERROR_LIMIT)
            if isinstance(state, dict) and state.get("last_error") else ""}


def revoke(conf, dev, ident_fn=None):
    """Revoke one device here, then on the relay. (ok, message)."""
    hit = devices.revoke(dev)
    if not hit:
        return False, "no active device matches"
    try:
        ident = (ident_fn or crypto.Identity.load)()
    except crypto.Unavailable as exc:
        return True, f"revoked here (nothing is sealed for it any more); relay not told: {short_error(exc)}"
    err = reject(conf, ident, hit)
    return True, ("revoked here and on the relay" if not err else
                  f"revoked here (nothing is sealed for it any more); the relay did not confirm: {err}")
