"""Argus licences: signed, device-bound leases from the Archymedes licence service.

docs/LICENSING-ARCHITECTURE.md. Argus is sold through Stripe Checkout (Managed Payments) at
https://pay.archymedes.xyz/buy/<offer>; the licence service there (hosted/licence-cloudflare)
issues a key, and this module turns the key, or an in-app purchase, into a certificate for
this machine.

Rules (tests/test_licence.py, tests/test_licence_crypto.py):
- Licence state only unlocks premium content (the full review report). Detection, collectors,
  alerts, evidence and on-demand checks never consult it (tests/test_licence_never_gates_core.py).
- status() is offline. It is licensed only if the certificate's Ed25519 signature verifies under
  a public key this build ships (trust.py) with a known kid, its audience is Argus, it names this
  device's key and this machine's fingerprint, the lease has not ended, and the clock has not
  been turned back past the last time Argus saw it (10 minutes' tolerance).
- Network: HTTPS to the licence service only. activate, refresh, deactivate, claim and content
  are run on purpose; maybe_renew makes one call when the lease has under 7 days left (at most
  every 6 hours after a failure, then daily) unless `argus licence auto-renew off`.
- What is stored (licence.json and licence-device.key, owner-only, written atomically): the key,
  the certificate, the activation id, the device key, the machine-id source name (not the id),
  the last-seen time and renewal state.

What this is not: a determined person who modifies the Argus program can skip these checks.
Licensing here keeps honest customers honest and discourages casual key sharing; it is not DRM.
Value the server delivers (POST /content/<pack>) is the only part a modified client cannot get.
"""

import json
import os
import platform
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from jarvis.licensing import device, ed25519, keys, trust

SERVICE = 'Archymedes licence service'
PAY_ORIGIN = 'https://pay.archymedes.xyz'
SERVER_CHECKOUT = f'{PAY_ORIGIN}/buy/argus-server'
DESKTOP_CHECKOUT = f'{PAY_ORIGIN}/buy/argus-desktop'
MANAGE_URL = f'{PAY_ORIGIN}/manage'
RECOVER_URL = f'{PAY_ORIGIN}/recover'
PRODUCTS = {'SERVER': 'Argus Server', 'DESKTOP': 'Argus Desktop'}
FILENAME = 'licence.json'
TIMEOUT = 15
CLOCK_TOLERANCE = 600
RETRY_FIRST, RETRY_LATER = 6 * 3600, 24 * 3600
REVIEW_PLANS = ('server', 'desktop')
REFRESH_HINT = 'run `argus licence refresh`'


class LicenceError(Exception):
    """The key could not be activated or checked; the message is safe to show."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def api_base():
    """The licence API. ARGUS_LICENCE_API may point at a local test service (loopback http only).
    It cannot make a forged certificate pass: certificates must still verify under trust.py."""
    override = os.environ.get('ARGUS_LICENCE_API', '').rstrip('/')
    if override:
        u = urllib.parse.urlparse(override)
        if u.scheme == 'https' or (u.scheme == 'http' and u.hostname in ('127.0.0.1', 'localhost')):
            return override
    return PAY_ORIGIN


def normalise(key):
    """The canonical key (also from an argus://activate?key=... link), or LicenceError."""
    text = str(key or '').strip()
    if text.lower().startswith('argus://'):
        text = (urllib.parse.parse_qs(urllib.parse.urlparse(text).query).get('key') or [''])[0]
    try:
        return keys.parse(text)[0]
    except keys.KeyFormatError as exc:
        raise LicenceError(str(exc), 'bad_check' if exc.reason == 'check' else 'bad_key') from None


def plan_of(key):
    return keys.parse(key)[1]


def path_for(db_path):
    return os.path.join(os.path.dirname(os.path.abspath(db_path)), FILENAME)


def _dir(path):
    return os.path.dirname(os.path.abspath(path))


# --- storage ---------------------------------------------------------------------------------------
def load(path):
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def save(path, data):
    d = _dir(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.licence-', dir=d)
    try:
        if hasattr(os, 'fchmod'):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=1)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


# --- HTTP ------------------------------------------------------------------------------------------
def _post(endpoint, body, opener=None):
    req = urllib.request.Request(f'{api_base()}/{endpoint}', data=json.dumps(body).encode(), method='POST',
                                 headers={'content-type': 'application/json', 'accept': 'application/json',
                                          'user-agent': 'argus-licence/3'})
    try:
        with (opener or urllib.request.urlopen)(req, timeout=TIMEOUT) as resp:
            return getattr(resp, 'status', 200), json.loads(resp.read(65536) or b'{}')
    except urllib.error.HTTPError as exc:
        try:
            answer = json.loads(exc.read(65536) or b'{}')
        except (ValueError, OSError, AttributeError, TypeError):
            answer = {}
        code = answer.get('code') if isinstance(answer, dict) else None
        text = answer.get('error') if isinstance(answer, dict) else None
        if not text:
            text = f'HTTP {exc.code}; try again later' if exc.code >= 500 else f'HTTP {exc.code}'
        raise LicenceError(f'the {SERVICE} says: {str(text)[:500]}', code or f'http_{exc.code}') from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise LicenceError(f'the {SERVICE} could not be reached ({type(exc).__name__}); '
                           'the stored licence, if any, is unchanged', 'unreachable') from None


# --- certificates ----------------------------------------------------------------------------------
class CertificateError(Exception):
    pass


def verify_certificate(token, trusted=None, typ='argus-licence+jwt'):
    """The claims of a JWS signed by a trusted kid, or CertificateError with the reason."""
    trusted = trust.PUBLIC_KEYS if trusted is None else trusted
    parts = str(token or '').split('.')
    if len(parts) != 3:
        raise CertificateError('the certificate is not in the expected format')
    try:
        header = json.loads(device.unb64url(parts[0]))
        claims = json.loads(device.unb64url(parts[1]))
        sig = device.unb64url(parts[2])
    except (ValueError, TypeError):
        raise CertificateError('the certificate is damaged') from None
    if not isinstance(header, dict) or not isinstance(claims, dict) or header.get('alg') != 'EdDSA' \
            or header.get('typ') != typ:
        raise CertificateError('the certificate is not an Argus licence certificate')
    kid = header.get('kid')
    if not trusted:
        raise CertificateError('this build of Argus has no licence signing key (trust.py is empty)')
    if kid not in trusted:
        raise CertificateError(f'the certificate is signed with a key this version of Argus does not know '
                               f'({str(kid)[:32]}); update Argus')
    try:
        pub = device.unb64url(trusted[kid])
    except ValueError:
        raise CertificateError('this build has a damaged licence signing key') from None
    if not ed25519.verify(pub, f'{parts[0]}.{parts[1]}'.encode(), sig):
        raise CertificateError('the certificate signature does not verify (it was changed or is not genuine)')
    if claims.get('kid') != kid or claims.get('aud') != 'argus':
        raise CertificateError('the certificate is not for Argus')
    return claims


def _when(ts):
    return time.strftime('%Y-%m-%d', time.gmtime(ts)) if isinstance(ts, (int, float)) else 'no end date'


def _install(path, answer, key, label, fp_source, now, trusted):
    """Check a certificate from the service against this device before storing it."""
    dk = device.load_key(_dir(path))
    cert = answer.get('certificate')
    try:
        claims = verify_certificate(cert, trusted)
    except CertificateError as exc:
        raise LicenceError(f'the {SERVICE} answered with a certificate this Argus cannot accept: {exc}',
                           'bad_certificate') from None
    if not dk or claims.get('dpk') != dk.dpk:
        raise LicenceError('the certificate is for another device key', 'bad_certificate')
    old = load(path) or {}
    rec = {'v': 2, 'key': key or old.get('key'), 'plan': claims.get('plan'),
           'product': keys.PRODUCTS.get(claims.get('plan'), 'Argus'), 'activation_id': claims.get('act'),
           'licence_id': claims.get('sub'), 'certificate': cert, 'label': label or old.get('label'),
           'fp_source': fp_source or old.get('fp_source') or device.default_source(),
           'auto_renew': old.get('auto_renew', True), 'checked_at': now}
    _stamp(rec, dk, max(now, claims.get('iat') or 0))
    save(path, rec)
    return rec


def _stamp(rec, dk, when):
    rec['last_seen'] = int(when)
    rec['last_seen_mac'] = dk.mac(f'{rec.get("activation_id")}|{int(when)}')


def _last_seen(rec, dk, claims):
    seen = rec.get('last_seen')
    floor = claims.get('iat') or 0
    if isinstance(seen, int) and dk.mac(f'{rec.get("activation_id")}|{seen}') == rec.get('last_seen_mac'):
        return max(seen, floor)
    return floor  # missing or edited: fall back to the signed issue time


# --- flows -------------------------------------------------------------------------------------------
def _device(path, create):
    dk = device.load_key(_dir(path), create=create)
    if not dk:
        raise LicenceError('this machine has no device key; activate the licence again', 'no_device')
    return dk


def _label(label):
    return (label or platform.node() or 'unnamed')[:60]


def activate(path, key, label=None, now=None, opener=None, trusted=None):
    """Activate `key` for this machine and store the certificate. Returns the record."""
    key = normalise(key)
    now = time.time() if now is None else now
    dk = _device(path, create=True)
    source = device.default_source()
    try:
        dev = device.fingerprint(dk.dpk, device.machine_id(source))
    except device.DeviceError as exc:
        raise LicenceError(str(exc), 'no_machine_id') from None
    _status, answer = _post('licence/activate', {'key': key, 'dev': dev, 'dpk': dk.dpk, 'label': _label(label)}, opener)
    return _install(path, answer, key, _label(label), source, now, trusted)


def refresh(path, now=None, opener=None, trusted=None):
    """Renew the lease now. A revoked, expired or released licence stops at once; no answer changes nothing."""
    rec = load(path)
    if not rec or not rec.get('activation_id'):
        raise LicenceError('no licence is installed on this machine', 'none')
    now = time.time() if now is None else now
    dk = _device(path, create=False)
    act = rec['activation_id']
    try:
        _status, answer = _post('licence/renew', {'act': act, **dk.signed('renew', act, now)}, opener)
    except LicenceError as exc:
        renew = {'failed_at': int(now), 'error': str(exc)[:300], 'code': exc.code}
        if exc.code in ('revoked', 'expired', 'not_activated'):
            rec['status'] = 'released' if exc.code == 'not_activated' else exc.code
        rec['renew'] = renew
        save(path, rec)
        raise
    out = _install(path, answer, rec.get('key'), rec.get('label'), rec.get('fp_source'), now, trusted)
    return out


def maybe_renew(path, now=None, opener=None, trusted=None):
    """When Argus runs: renew if the lease is in its last 7 days. Never raises. True if it renewed."""
    rec = load(path)
    now = time.time() if now is None else now
    if not rec or not rec.get('certificate') or rec.get('status') or rec.get('auto_renew') is False:
        return False
    try:
        claims = verify_certificate(rec['certificate'], trusted)
    except CertificateError:
        return False
    if now < (claims.get('renew_after') or 0):
        return False
    last = (rec.get('renew') or {}).get('failed_at')
    if last and now - last < (RETRY_FIRST if now < (claims.get('exp') or 0) else RETRY_LATER):
        return False
    try:
        refresh(path, now=now, opener=opener, trusted=trusted)
        return True
    except LicenceError:
        return False


def deactivate(path, now=None, opener=None):
    """Free this machine's seat on purpose, then forget the licence here (the device key stays)."""
    rec = load(path)
    if not rec or not rec.get('activation_id'):
        raise LicenceError('no licence is installed on this machine', 'none')
    now = time.time() if now is None else now
    dk = _device(path, create=False)
    act = rec['activation_id']
    _post('licence/release', {'act': act, **dk.signed('release', act, now)}, opener)
    os.unlink(path)
    return rec


def set_auto_renew(path, on):
    rec = load(path)
    if not rec:
        raise LicenceError('no licence is installed on this machine', 'none')
    rec['auto_renew'] = bool(on)
    save(path, rec)
    return rec


def claim_start(path, label=None, now=None, opener=None):
    """Start an in-app purchase or `argus licence login`: returns the claim (buy links, user code)."""
    dk = _device(path, create=True)
    source = device.default_source()
    try:
        dev = device.fingerprint(dk.dpk, device.machine_id(source))
    except device.DeviceError as exc:
        raise LicenceError(str(exc), 'no_machine_id') from None
    _status, answer = _post('licence/claim', {'dev': dev, 'dpk': dk.dpk, 'label': _label(label)}, opener)
    if not str(answer.get('claim_id', '')).startswith('clm_'):
        raise LicenceError(f'the {SERVICE} did not open a claim', 'bad_answer')
    pending = {'claim_id': answer['claim_id'], 'label': _label(label), 'fp_source': source,
               'expires': int((time.time() if now is None else now) + int(answer.get('expires_in') or 1800))}
    rec = load(path) or {}
    rec['claim'] = pending
    save(path, rec)
    return answer


def claim_poll(path, now=None, opener=None, trusted=None):
    """'pending' or 'active' (the licence is installed). LicenceError when the claim is over."""
    rec = load(path) or {}
    claim = rec.get('claim')
    if not claim:
        raise LicenceError('no purchase is waiting on this machine', 'none')
    now = time.time() if now is None else now
    dk = _device(path, create=False)
    status, answer = _post('licence/claim/poll', {'claim_id': claim['claim_id'],
                                                  **dk.signed('poll', claim['claim_id'], now)}, opener)
    if status == 202 or answer.get('status') == 'pending':
        return 'pending'
    _install(path, answer, answer.get('key'), claim.get('label'), claim.get('fp_source'), now, trusted)
    return 'active'


def login(path, label=None, out=print, sleep=time.sleep, opener=None, trusted=None, clock=time.time):
    """Headless activation: show a code, wait while the owner approves it on the web."""
    c = claim_start(path, label, opener=opener)
    out(f'On any device, open {c.get("verify_url")} , sign in with your purchase email and enter this code:')
    out(f'    {c.get("user_code")}')
    out(f'(no licence yet? buy one: {SERVER_CHECKOUT} or {DESKTOP_CHECKOUT})')
    deadline = clock() + int(c.get('expires_in') or 1800)
    while clock() < deadline:
        sleep(int(c.get('interval') or 5))
        if claim_poll(path, opener=opener, trusted=trusted) == 'active':
            return load(path)
    raise LicenceError('the code expired before it was approved; run `argus licence login` again', 'expired')


def fetch_content(path, pack, now=None, opener=None, trusted=None):
    """A premium content pack from the server: only for a live activation; verified before use."""
    rec = load(path)
    if not rec or not rec.get('activation_id'):
        raise LicenceError('content packs need an active licence on this machine', 'none')
    now = time.time() if now is None else now
    dk = _device(path, create=False)
    act = rec['activation_id']
    _status, answer = _post(f'content/{pack}', {'act': act, **dk.signed('content', f'{pack}:{act}', now)}, opener)
    try:
        claims = verify_certificate(answer.get('pack'), trusted, typ='argus-pack+jwt')
    except CertificateError as exc:
        raise LicenceError(f'the content pack could not be verified: {exc}', 'bad_pack') from None
    if claims.get('pack') != pack or claims.get('act') != act:
        raise LicenceError('the content pack is not for this machine', 'bad_pack')
    return claims.get('data')


# --- status --------------------------------------------------------------------------------------------
def status(path, now=None, trusted=None, plans=REVIEW_PLANS):
    """Offline: {'licensed': bool, 'reason': str, ...}. Never touches the network."""
    now = time.time() if now is None else now
    rec = load(path)
    if not rec or not rec.get('certificate'):
        return {'licensed': False, 'reason': 'no licence installed', 'needs_key': True}
    out = {'product': rec.get('product'), 'plan': rec.get('plan'), 'label': rec.get('label'),
           'key_hint': str(rec.get('key') or '')[-4:], 'activation_id': rec.get('activation_id'),
           'auto_renew': rec.get('auto_renew', True), 'renew_error': (rec.get('renew') or {}).get('error')}

    def no(reason, **more):
        return {**out, 'licensed': False, 'reason': reason, **more}

    if rec.get('status') == 'revoked':
        return no(f'the {SERVICE} says this licence was cancelled or refunded', needs_key=True)
    if rec.get('status') == 'expired':
        return no(f'the {SERVICE} says this licence\'s subscription has ended (renew it at {MANAGE_URL})')
    if rec.get('status') == 'released':
        return no('this machine was released from the licence; activate it again', needs_key=True)
    dk = device.load_key(_dir(path))
    if not dk:
        return no('this machine\'s device key is missing; activate the licence again', needs_key=True)
    try:
        claims = verify_certificate(rec['certificate'], trusted)
    except CertificateError as exc:
        return no(str(exc), needs_key=True)
    out.update(expires_at=claims.get('lic_exp'), lease_until=claims.get('exp'), renew_after=claims.get('renew_after'),
               plan=claims.get('plan'), product=keys.PRODUCTS.get(claims.get('plan'), out['product']))
    if claims.get('dpk') != dk.dpk:
        return no('the certificate belongs to another Argus install', needs_key=True)
    try:
        mid = device.machine_id(rec.get('fp_source'))
    except device.DeviceError as exc:
        return no(str(exc))
    if claims.get('dev') != device.fingerprint(dk.dpk, mid):
        return no('the certificate belongs to another machine (was it copied, or the OS reinstalled?); '
                  f'release the old machine at {MANAGE_URL} and activate here', needs_key=True)
    seen = _last_seen(rec, dk, claims)
    if now < seen - CLOCK_TOLERANCE or now < (claims.get('iat') or 0) - CLOCK_TOLERANCE:
        return no(f'the system clock is behind the last time Argus checked the licence '
                  f'({time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(seen))}); correct the clock')
    if now >= (claims.get('exp') or 0):
        why = f' (last renewal: {out["renew_error"]})' if out['renew_error'] else ''
        return no(f'licence needs checking: its offline lease ended on {_when(claims.get("exp"))}{why}; {REFRESH_HINT}',
                  needs_check=True)
    if claims.get('plan') not in plans:
        return no(f'the installed licence is for {out["product"]}')
    if now > seen + 3600:
        try:
            _stamp(rec, dk, now)
            save(path, rec)
        except OSError:
            pass
    return {**out, 'licensed': True, 'reason': f'{out["product"]} licence for this machine, signed by the {SERVICE}'}
