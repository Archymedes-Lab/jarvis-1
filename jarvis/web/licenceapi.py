"""The licence screen's API for the desktop app and the dashboard (GET/POST /api/licence...).

Thin wrapper over jarvis/licensing/licence.py. Premium content only: nothing here is consulted
by detection, collectors, alerts or evidence (tests/test_licence_never_gates_core.py), and an
unlicensed answer is an ordinary 200 with licensed=false, never a payment-required status.
"""

import re
import threading
import time

from jarvis.licensing import licence

_renew_lock = threading.Lock()
_last_renew_try = [0.0]
RENEW_CHECK_EVERY = 3600


# What the in-app purchase may open (hosted/licence-cloudflare OFFERS). The service's claim
# answer names server and desktop; the monthly Desktop offer takes the same claim id.
UPGRADE_OFFERS = {'server': 'argus-server', 'desktop': 'argus-desktop', 'desktop-monthly': 'argus-desktop-monthly'}


# An optional promo code for the checkout (hosted/licence-cloudflare PROMO; the same pattern in
# desktop/ui/src/lib/licence.ts). The licence service looks it up at Stripe and, whatever the
# answer, still opens checkout where a code can be typed. Here it is only checked and passed on:
# never stored or logged, and a malformed one is refused before any network call.
PROMO = re.compile(r'[A-Za-z0-9_-]{1,40}')
BAD_PROMO = 'A promo code is up to 40 letters, digits, - or _. Check the code, or leave the field empty.'


def _promo(payload):
    """(code or '', ok). Empty or missing is no code; anything else must match PROMO exactly."""
    raw = payload.get('promo')
    if raw is None:
        return '', True
    if not isinstance(raw, str):
        return '', False
    raw = raw.strip()
    if not raw:
        return '', True
    return (raw, True) if PROMO.fullmatch(raw) else ('', False)


def _links():
    return {'buy_server': licence.SERVER_CHECKOUT, 'buy_desktop': licence.DESKTOP_CHECKOUT,
            'manage': licence.MANAGE_URL, 'recover': licence.RECOVER_URL}


def _maybe_renew_in_background(path):
    """While Argus runs: at most hourly, renew in a thread if the lease is in its last 7 days."""
    now = time.time()
    with _renew_lock:
        if now - _last_renew_try[0] < RENEW_CHECK_EVERY:
            return
        _last_renew_try[0] = now
    threading.Thread(target=licence.maybe_renew, args=(path,), daemon=True, name='licence-renew').start()


def state(db_path):
    path = licence.path_for(db_path)
    _maybe_renew_in_background(path)
    st = licence.status(path)
    pending = (licence.load(path) or {}).get('claim')
    out = {k: v for k, v in st.items() if k != 'activation_id'}
    out['purchase_waiting'] = bool(pending and pending.get('expires', 0) > time.time())
    return {**out, 'links': _links()}


def action(db_path, name, payload):
    """(HTTP status, body) for POST /api/licence/<name>."""
    path = licence.path_for(db_path)
    payload = payload if isinstance(payload, dict) else {}
    try:
        if name == 'activate':
            licence.activate(path, str(payload.get('key') or '')[:200])
        elif name == 'deactivate':
            licence.deactivate(path)
        elif name == 'refresh':
            licence.refresh(path)
        elif name == 'upgrade':
            plan = payload.get('plan') if payload.get('plan') in UPGRADE_OFFERS else 'desktop'
            promo, promo_ok = _promo(payload)
            if not promo_ok:
                return 200, {'ok': False, 'code': 'bad_promo', 'error': BAD_PROMO}
            claim = licence.claim_start(path)
            link = (claim.get('buy') or {}).get(plan) or \
                f"{licence.PAY_ORIGIN}/buy/{UPGRADE_OFFERS[plan]}?claim={claim['claim_id']}"
            if promo:   # PROMO's characters need no URL escaping
                link += ('&' if '?' in link else '?') + 'promo=' + promo
            # promo_sent: the service checks the code at checkout and says there if it was not applied.
            return 200, {'ok': True, 'open': link, 'interval': claim.get('interval', 5), 'promo_sent': bool(promo)}
        elif name == 'poll':
            done = licence.claim_poll(path) == 'active'
            return 200, {'ok': True, 'active': done, **({'state': state(db_path)} if done else {})}
        else:
            return 404, {'ok': False, 'error': 'unknown licence action'}
    except licence.LicenceError as exc:
        return 200, {'ok': False, 'code': exc.code, 'error': str(exc), 'state': state(db_path)}
    return 200, {'ok': True, 'state': state(db_path)}
