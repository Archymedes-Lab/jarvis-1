"""Ed25519 (RFC 8032) for licence certificates and device-key request signatures.

Uses `cryptography` when it is importable (the Windows build bundles it; see
release/requirements-runtime.txt). The Linux server edition runs on the system Python with
the standard library only (install.sh installs no wheels), so this module falls back to the
RFC 8032 reference arithmetic. That fallback is checked against the RFC's test vectors and
against signatures made by the licence service (tests/test_licence_crypto.py).

Fallback limits, stated plainly: Python integers are not constant-time, so signing with the
fallback could leak timing to a process on the same machine. The only secret it signs with is
the device key, which such a process could read from disk anyway; verification handles only
public data.
"""

import hashlib

try:  # pragma: no cover - which branch runs depends on the machine
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    HAVE_CRYPTOGRAPHY = True
except Exception:  # noqa: BLE001 - any import problem means "use the fallback"
    HAVE_CRYPTOGRAPHY = False

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _equal(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _compress(p):
    zinv = pow(p[2], _P - 2, _P)
    x, y = p[0] * zinv % _P, p[1] * zinv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, 'little')
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _h(*parts):
    return int.from_bytes(hashlib.sha512(b''.join(parts)).digest(), 'little')


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed, force_fallback=False):
    """The 32-byte public key for a 32-byte private seed."""
    if len(seed) != 32:
        raise ValueError('an Ed25519 seed is 32 bytes')
    if HAVE_CRYPTOGRAPHY and not force_fallback:
        return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _compress(_mul(_expand(seed)[0], _G))


def sign(seed, message, force_fallback=False):
    """A 64-byte signature of `message` (bytes) by the key with this seed."""
    if len(seed) != 32:
        raise ValueError('an Ed25519 seed is 32 bytes')
    if HAVE_CRYPTOGRAPHY and not force_fallback:
        return Ed25519PrivateKey.from_private_bytes(seed).sign(message)
    a, prefix = _expand(seed)
    pub = _compress(_mul(a, _G))
    r = _h(prefix, message) % _L
    big_r = _compress(_mul(r, _G))
    k = _h(big_r, pub, message) % _L
    return big_r + ((r + k * a) % _L).to_bytes(32, 'little')


def verify(public, message, signature, force_fallback=False):
    """True only for a valid signature; never raises on bad input."""
    if not isinstance(public, bytes) or not isinstance(signature, bytes) or len(public) != 32 or len(signature) != 64:
        return False
    if HAVE_CRYPTOGRAPHY and not force_fallback:
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    s = int.from_bytes(signature[32:], 'little')
    if a is None or r is None or s >= _L:
        return False
    k = _h(signature[:32], public, message) % _L
    return _equal(_mul(s, _G), _add(r, _mul(k, a)))
