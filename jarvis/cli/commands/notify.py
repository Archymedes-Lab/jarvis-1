"""Phone notifications through the sealed relay (docs/architecture/ARGUS-NOTIFY.md).

    notify pair [--label NAME] [--no-qr]
                                 pair a phone: scan a QR (alerts and approvals), or type a code (alerts only)
    notify devices               the paired phones
    notify revoke DEVICE         stop sealing for a phone, here and on the relay
    notify test                  send a test notification to every paired phone
    notify status                relay, identity, devices, last delivery
"""

import json
import os
import socket
import sys
import time

from jarvis.response import alert
from jarvis.response.notify import channel, crypto, devices, pairing, qr, relay

PAIR_WAIT_S = pairing.PAIR_WAIT_S
POLL_S = 3
ACTIVATE_TRIES = pairing.ACTIVATE_TRIES
ACTIVATE_WAIT_S = pairing.ACTIVATE_WAIT_S
_printable = pairing.printable
activate = pairing.activate


def _conf():
    return alert.load_conf()


def _identity(create=False):
    try:
        return crypto.Identity.load(create=create)
    except crypto.Unavailable as exc:
        sys.exit(f"notify: {exc}")


def _qr_text(link, args):
    """The pairing QR as terminal text, or a plain line when it cannot be drawn or --no-qr was given."""
    if getattr(args, "no_qr", False):
        return f"  {link}"
    try:
        return qr.render_ansi(qr.encode(link))
    except qr.TooLong:
        return f"  {link}"


def _qr_claim(secret, claim, d_sig, d_enc):
    """None when the claim does not prove it came from the QR (the 6-digit check then decides, and the
    phone gets alerts only). Otherwise the phone's passkey public key as sent ('' if it made none)."""
    proof, passkey = claim.get("proof"), claim.get("passkey")
    if not proof:
        return None
    try:
        spki = crypto.valid_passkey(passkey) if passkey else b""
        if crypto.check_qr_proof(secret, proof, d_sig, d_enc, spki):
            return passkey or ""
    except (ValueError, crypto.Unavailable):
        pass
    return None


def cmd_pair(args, store):
    conf = _conf()
    if not sys.stdin.isatty():
        # The 6-digit comparison is what stops a malicious relay from slipping
        # in its own device: never skip it silently.
        sys.exit("notify pair needs a terminal to confirm the 6-digit code shown on the phone")
    ident = _identity(create=True)
    label = (args.label or conf.get("notify_label") or socket.gethostname())[:40]
    code = crypto.pairing_code()
    secret = os.urandom(16)
    expires = int(time.time()) + PAIR_WAIT_S
    try:
        pairing.offer(conf, ident, code, label, expires)
    except relay.RelayError as exc:
        sys.exit(f"notify: the relay refused the pairing offer ({exc})")
    url = relay.base_url(conf)
    # The QR carries the relay address, the one-time code, this server's mailbox id (the hash of its key)
    # and a secret the relay never sees. The phone pins the server from the camera, and proves with the
    # secret that its claim is its own: no digits to compare, and the phone may approve actions.
    link = f"{url}/#/pair?c={code}&k={crypto.b64u(secret)}&mb={ident.mailbox}"
    print(f"\n  On your phone, open {url} from your Home Screen (iPhone: Share > Add to Home Screen first),\n"
          f"  tap “Add a server” and scan this code within 10 minutes:\n", flush=True)
    print(_qr_text(link, args), flush=True)
    print(f"\n  No camera? Choose “Type the code instead” in the app and enter {crypto.format_code(code)}.\n"
          f"  (A typed code gives alerts only: approving actions needs the QR.)\n\n"
          f"  Waiting for the phone ...", flush=True)
    claim = None
    # The offer's expiry is wall-clock for the relay; the wait itself is monotonic.
    deadline = time.monotonic() + PAIR_WAIT_S
    while time.monotonic() < deadline and claim is None:
        time.sleep(POLL_S)
        try:
            claim = pairing.find_claim(conf, ident, code)
        except relay.RelayError as exc:
            print(f"  (relay: {exc}; retrying)", flush=True)
    if claim is None:
        sys.exit("notify: no phone claimed the code in 10 minutes; run `notify pair` again")
    try:
        dev, name, sas = pairing.check_claim(ident, claim)
        d_sig, d_enc = crypto.unb64u(claim["d_sig"]), crypto.unb64u(claim["d_enc"])
    except ValueError as exc:
        sys.exit(f"notify: the relay returned a {exc}; nothing was paired")
    # '' or the passkey when the claim proves it came from the QR (the phone then pinned this
    # server from the camera); None otherwise, and the 6-digit comparison decides.
    passkey = _qr_claim(secret, claim, d_sig, d_enc)
    if passkey is not None:
        approve = " and approve reversible actions" if passkey else ""
        print(f"\n  “{name}” scanned the QR code and wants to receive this server's alerts{approve}.", flush=True)
        answer = input("  Add it? [y/N] ")
        declined = "notify: not paired."
    else:
        print(f"\n  “{name}” wants to receive this server's alerts (alerts only: it did not scan the QR code).\n"
              f"  It shows a code. Pair only if it is exactly:\n\n      {sas[:3]} {sas[3:]}\n", flush=True)
        answer = input("  Same code on the phone? [y/N] ")
        declined = "notify: not paired. If the codes differed, someone may be interfering; pair again."
    if answer.strip().lower() not in ("y", "yes"):
        pairing.reject(conf, ident, dev)
        sys.exit(declined)
    err = pairing.accept(conf, ident, claim, code, name, activate_fn=activate, passkey=passkey or None)
    if err:
        print(f"  warning: paired here, but the relay did not activate the phone ({err}).\n"
              f"  The phone will not receive alerts until it is activated: run `notify pair` again.", flush=True)
    err = channel.send(conf, f"{label} is paired", "Alerts from this server will arrive here.",
                       severity="ok", kind="test", store=store)
    print(f"\n  Paired “{name}”." + (" A test notification is on its way." if not err else f" Test failed: {err}"))


def cmd_devices(args, store):
    doc = devices.load()
    if args.json:
        print(json.dumps([{k: v for k, v in d.items() if k not in ("d_sig", "d_enc")} for d in doc["devices"]], indent=1))
        return
    if not doc["devices"]:
        print("no paired devices; run `notify pair`")
    for d in doc["devices"]:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(d.get("paired_at", 0)))
        state = ("revoked " + time.strftime("%Y-%m-%d", time.localtime(d["revoked_at"])) if d.get("revoked_at")
                 else "NOT ACTIVATED on the relay (pair again)" if d.get("relay_pending") else "active")
        print(f"  {_printable(d.get('dev', '?'), 10)}  {_printable(d.get('name', '?'), 40):<24} paired {when}  {state}")


def cmd_revoke(args, store):
    dev = devices.revoke(args.device)
    if not dev:
        sys.exit(f"notify: no active device matches {args.device!r}")
    ident = _identity()
    try:
        relay.call(_conf(), ident, "DELETE", f"/v1/mailbox/{ident.mailbox}/devices/{dev}")
        print(f"revoked {dev[:10]} here and on the relay")
    except relay.RelayError as exc:
        print(f"revoked {dev[:10]} here (nothing is sealed for it any more); the relay did not confirm: {exc}")


def cmd_test(args, store):
    err = channel.send(_conf(), "Test notification", "If this arrived, alerts will too.",
                       severity="ok", kind="test", store=store)
    print("sent" if not err else f"failed: {err}")
    if err:
        sys.exit(1)


def cmd_status(args, store):
    conf = _conf()
    try:
        crypto._lib()
        lib = "python3-cryptography present"
    except crypto.Unavailable as exc:
        lib = str(exc)
    ident = None
    try:
        ident = crypto.Identity.load()
    except crypto.Unavailable:
        pass
    state = {}
    if store is not None:
        try:
            state = json.loads(store.get_meta(channel.META, "{}") or "{}")
        except ValueError:
            state = {}
    print(f"relay      {conf.get('notify_url') or relay.DEFAULT_URL}")
    print(f"crypto     {lib}")
    print(f"mailbox    {ident.mailbox if ident else 'not created (run notify pair)'}")
    active = devices.active()
    pending = [d for d in active if d.get("relay_pending")]
    print(f"devices    {len(active)} active" + (f", {len(pending)} not activated on the relay" if pending else ""))
    if ident is not None and active:
        try:
            listed = relay.call(conf, ident, "GET", f"/v1/mailbox/{ident.mailbox}/devices") or []
        except relay.RelayError as exc:
            listed = None
            print(f"relay side {exc}")
        if isinstance(listed, list):
            known = {d["dev"]: d for d in active}
            for row in listed:
                if not isinstance(row, dict) or row.get("dev") not in known:
                    continue
                seen = row.get("last_seen")
                when = time.strftime("%Y-%m-%d %H:%M", time.localtime(seen)) if seen else "never"
                print(f"  {str(row['dev'])[:10]}  {str(row.get('name') or '?'):<24} {row.get('state')}  "
                      f"push {'yes' if row.get('push') else 'no'}  last fetched inbox {when}")
    if state:
        fmt = lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else "never"  # noqa: E731
        print(f"last ok    {fmt(state.get('last_ok'))}")
        if state.get("last_error"):
            print(f"last error {state['last_error']}")


def add_parser(sub):
    p = sub.add_parser("notify", help="phone notifications through the sealed relay")
    nsub = p.add_subparsers(dest="notify_cmd", required=True)
    pp = nsub.add_parser("pair", help="pair a phone: scan a QR code (or type the code for alerts only)")
    pp.add_argument("--label", help="the name the phone shows for this server")
    pp.add_argument("--no-qr", action="store_true", help="print the pairing link instead of drawing the QR code")
    pp.set_defaults(fn=cmd_pair)
    dp = nsub.add_parser("devices", help="the paired phones")
    dp.add_argument("--json", action="store_true")
    dp.set_defaults(fn=cmd_devices)
    rp = nsub.add_parser("revoke", help="stop sealing for a phone")
    rp.add_argument("device", help="device id (a prefix is enough)")
    rp.set_defaults(fn=cmd_revoke)
    nsub.add_parser("test", help="send a test notification").set_defaults(fn=cmd_test)
    nsub.add_parser("status", help="relay, devices, last delivery").set_defaults(fn=cmd_status)
