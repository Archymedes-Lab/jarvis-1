"""Keys, sealing, signatures and the pairing code (docs/architecture/ARGUS-NOTIFY.md).

Primitives are the ones browsers ship in WebCrypto, so the phone needs no
crypto library: X25519, HKDF-SHA256, AES-256-GCM, Ed25519. On the server they
come from the distribution's python3-cryptography; when it is missing, every
entry point raises Unavailable and the channel says so.

Protocol strings carry no product name: the packaged editions rename the
product, and a renamed constant would make editions unable to talk to the
same relay.
"""

import base64
import hashlib
import json
import os
import secrets

IDENTITY = os.path.expanduser("~/.jarvis/notify/identity.json")
REQ_CONTEXT = "notify-req/1"
ENV_CONTEXT = "notify-env/1"
SEAL_INFO = b"notify-seal/1"
SAS_CONTEXT = b"notify-sas/1"
REPLY_CONTEXT = "notify-rep/1"      # a phone's signed answer to the server (approvals)
REPLY_INFO = b"notify-reply/1"
PROOF_CONTEXT = b"notify-qr/1"      # keyed proof that a claim came from the phone that scanned the QR
APPROVAL_CONTEXT = "notify-approval/1"
RP_ID = "argus.archymedes.xyz"      # WebAuthn relying party: the phone app's origin
ORIGIN = "https://argus.archymedes.xyz"
CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"      # Crockford base32
CODE_LEN = 10
MAX_PAYLOAD = 4096
ENVELOPE_TTL = 7 * 86400


class Unavailable(RuntimeError):
    """python3-cryptography is not installed."""


def _lib():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError as exc:
        raise Unavailable("python3-cryptography is not installed (apt install python3-cryptography)") from exc
    return ed25519, x25519, AESGCM, HKDF, hashes, serialization


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text):
    text = str(text)
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def key_id(sig_pub):
    """Self-certifying id of an Ed25519 public key (raw 32 bytes)."""
    return b64u(hashlib.sha256(sig_pub).digest())[:22]


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _raw(pub):
    _, _, _, _, _, serialization = _lib()
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _priv_raw(priv):
    _, _, _, _, _, serialization = _lib()
    return priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                              serialization.NoEncryption())


class Identity:
    """The server's two key pairs. `mailbox` is its relay address."""

    def __init__(self, sig_priv, enc_priv):
        self.sig_priv, self.enc_priv = sig_priv, enc_priv
        self.sig_pub = _raw(sig_priv.public_key())
        self.enc_pub = _raw(enc_priv.public_key())
        self.mailbox = key_id(self.sig_pub)

    @classmethod
    def generate(cls):
        ed25519, x25519, *_ = _lib()
        return cls(ed25519.Ed25519PrivateKey.generate(), x25519.X25519PrivateKey.generate())

    @classmethod
    def load(cls, path=None, create=False):
        path = path or IDENTITY
        ed25519, x25519, *_ = _lib()
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                doc = json.load(fh)
            return cls(ed25519.Ed25519PrivateKey.from_private_bytes(unb64u(doc["sig"])),
                       x25519.X25519PrivateKey.from_private_bytes(unb64u(doc["enc"])))
        except FileNotFoundError:
            if not create:
                return None
        ident = cls.generate()
        ident.save(path)
        return ident

    def save(self, path=None):
        path = path or IDENTITY
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        tmp = path + ".new"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"sig": b64u(_priv_raw(self.sig_priv)), "enc": b64u(_priv_raw(self.enc_priv))}, fh)
        os.replace(tmp, path)

    def sign(self, message):
        return self.sig_priv.sign(message)

    def request_headers(self, method, path, body, now):
        return sign_request(self.sig_priv, self.sig_pub, method, path, body, now)


def sign_request(sig_priv, sig_pub, method, path, body, now, nonce=None):
    """Headers proving the holder of sig_priv made this exact request at `now`.

    Ed25519 is deterministic: without the random nonce two identical requests in
    the same second would carry the same signature and the second would be
    refused as a replay."""
    stamp = str(int(now))
    nonce = nonce or b64u(secrets.token_bytes(16))
    digest = hashlib.sha256(body or b"").hexdigest()
    message = "\n".join((REQ_CONTEXT, method.upper(), path, stamp, nonce, digest)).encode("utf-8")
    return {"X-Notify-Key": b64u(sig_pub), "X-Notify-Time": stamp, "X-Notify-Nonce": nonce,
            "X-Notify-Sig": b64u(sig_priv.sign(message))}


def seal(ident, device, payload, now, ttl=ENVELOPE_TTL, envelope_id=None, iv=None, eph=None):
    """One envelope for one device (dict with dev and d_enc). `payload` is a
    dict; its canonical JSON must fit MAX_PAYLOAD."""
    _, x25519, AESGCM, HKDF, hashes, _ = _lib()
    plain = canonical(payload)
    if len(plain) > MAX_PAYLOAD:
        raise ValueError(f"payload is {len(plain)} bytes, over {MAX_PAYLOAD}")
    raw_id = envelope_id or secrets.token_bytes(16)
    eph = eph or x25519.X25519PrivateKey.generate()
    shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(unb64u(device["d_enc"])))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=raw_id, info=SEAL_INFO).derive(shared)
    header = {"v": 1, "id": b64u(raw_id), "mb": ident.mailbox, "dev": device["dev"],
              "sent": int(now), "expires": int(now) + int(ttl), "epk": b64u(_raw(eph.public_key()))}
    aad = canonical(header)
    iv = iv or secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(iv, plain, aad)
    signed = "\n".join((ENV_CONTEXT, aad.decode("utf-8"), b64u(iv), b64u(ct))).encode("utf-8")
    return {**header, "iv": b64u(iv), "ct": b64u(ct), "sig": b64u(ident.sign(signed))}


def open_envelope(envelope, d_enc_priv, s_sig_pub):
    """The phone's side, in Python: for tests and for `notify test --loopback`."""
    ed25519, x25519, AESGCM, HKDF, hashes, _ = _lib()
    header = {k: envelope[k] for k in ("v", "id", "mb", "dev", "sent", "expires", "epk")}
    aad = canonical(header)
    signed = "\n".join((ENV_CONTEXT, aad.decode("utf-8"), envelope["iv"], envelope["ct"])).encode("utf-8")
    ed25519.Ed25519PublicKey.from_public_bytes(s_sig_pub).verify(unb64u(envelope["sig"]), signed)
    shared = d_enc_priv.exchange(x25519.X25519PublicKey.from_public_bytes(unb64u(envelope["epk"])))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=unb64u(envelope["id"]), info=SEAL_INFO).derive(shared)
    return json.loads(AESGCM(key).decrypt(unb64u(envelope["iv"]), unb64u(envelope["ct"]), aad))


def sas(s_sig, s_enc, d_sig, d_enc):
    """The 6-digit code both sides show (raw 32-byte keys)."""
    digest = hashlib.sha256(SAS_CONTEXT + s_sig + s_enc + d_sig + d_enc).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1_000_000:06d}"


def pairing_code():
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LEN))


def format_code(code):
    return f"{code[:5]}-{code[5:]}"


def normalize_code(text):
    """User-typed code -> canonical (Crockford: O->0, I/L->1, case and dashes ignored)."""
    t = "".join(ch for ch in str(text).upper() if ch.isalnum())
    return t.translate(str.maketrans({"O": "0", "I": "1", "L": "1"}))


# --- approvals from the phone -----------------------------------------------------------
#
# The phone answers an approval request with a reply sealed to the SERVER's X25519 key and
# signed by the phone's Ed25519 key (the envelope, reversed). For an "approve" it also carries
# a WebAuthn assertion (Face ID / fingerprint) whose challenge is approval_challenge(): the
# biometric signature is therefore bound to the exact action that was shown.

def approval_challenge(approval_id, eid, action, target, expires):
    """32 bytes the phone's passkey signs. Both sides compute it from the same fields."""
    return hashlib.sha256(canonical({"ctx": APPROVAL_CONTEXT, "approval_id": approval_id, "eid": eid,
                                     "action": action, "target": str(target), "expires": int(expires)})).digest()


def seal_reply(d_sig_priv, dev, mailbox, s_enc_pub_b64, payload, now, ttl=900, reply_id=None, iv=None, eph=None):
    """The phone's side, in Python: for tests. `payload` is a dict."""
    _, x25519, AESGCM, HKDF, hashes, _ = _lib()
    plain = canonical(payload)
    if len(plain) > MAX_PAYLOAD:
        raise ValueError(f"payload is {len(plain)} bytes, over {MAX_PAYLOAD}")
    raw_id = reply_id or secrets.token_bytes(16)
    eph = eph or x25519.X25519PrivateKey.generate()
    shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(unb64u(s_enc_pub_b64)))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=raw_id, info=REPLY_INFO).derive(shared)
    header = {"v": 1, "id": b64u(raw_id), "mb": mailbox, "dev": dev, "sent": int(now),
              "expires": int(now) + int(ttl), "epk": b64u(_raw(eph.public_key()))}
    aad = canonical(header)
    iv = iv or secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(iv, plain, aad)
    signed = "\n".join((REPLY_CONTEXT, aad.decode("utf-8"), b64u(iv), b64u(ct))).encode("utf-8")
    return {**header, "iv": b64u(iv), "ct": b64u(ct), "sig": b64u(d_sig_priv.sign(signed))}


def open_reply(reply, ident, d_sig_pub):
    """The server's side: check the device's signature, then decrypt. Raises on any failure
    (InvalidSignature, InvalidTag, KeyError, ValueError)."""
    ed25519, x25519, AESGCM, HKDF, hashes, _ = _lib()
    header = {k: reply[k] for k in ("v", "id", "mb", "dev", "sent", "expires", "epk")}
    if header["mb"] != ident.mailbox or key_id(d_sig_pub) != header["dev"]:
        raise ValueError("reply is not for this server or not from this device")
    aad = canonical(header)
    signed = "\n".join((REPLY_CONTEXT, aad.decode("utf-8"), reply["iv"], reply["ct"])).encode("utf-8")
    ed25519.Ed25519PublicKey.from_public_bytes(d_sig_pub).verify(unb64u(reply["sig"]), signed)
    shared = ident.enc_priv.exchange(x25519.X25519PublicKey.from_public_bytes(unb64u(reply["epk"])))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=unb64u(reply["id"]), info=REPLY_INFO).derive(shared)
    return json.loads(AESGCM(key).decrypt(unb64u(reply["iv"]), unb64u(reply["ct"]), aad))


def qr_proof(secret, d_sig, d_enc, passkey_spki=b""):
    """HMAC the phone adds to its claim when it paired by scanning the QR. The relay knows the
    pairing code but not `secret` (it is only in the QR), so it cannot inject a device."""
    import hmac
    return b64u(hmac.new(secret, PROOF_CONTEXT + d_sig + d_enc + passkey_spki, hashlib.sha256).digest())


def check_qr_proof(secret, claim_proof, d_sig, d_enc, passkey_spki=b""):
    import hmac
    return hmac.compare_digest(str(claim_proof), qr_proof(secret, d_sig, d_enc, passkey_spki))


def verify_webauthn(spki, assertion, challenge, rp_id=RP_ID, origin=ORIGIN):
    """Verify a WebAuthn assertion (ES256 passkey; `spki` is the DER public key the phone sent at
    pairing). Requires the user-present AND user-verified flags: the biometric/PIN check happened.
    Returns the signature counter. Raises ValueError on anything wrong."""
    _lib()
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        auth = unb64u(assertion["authenticatorData"])
        client = unb64u(assertion["clientDataJSON"])
        sig = unb64u(assertion["signature"])
        info = json.loads(client)
    except (KeyError, ValueError, TypeError):
        raise ValueError("malformed assertion") from None
    if info.get("type") != "webauthn.get":
        raise ValueError("not an assertion")
    if info.get("origin") != origin or info.get("crossOrigin"):
        raise ValueError("wrong origin")
    if info.get("challenge") != b64u(challenge):
        raise ValueError("challenge does not match this action")
    if len(auth) < 37 or auth[:32] != hashlib.sha256(rp_id.encode("ascii")).digest():
        raise ValueError("wrong relying party")
    flags = auth[32]
    if not flags & 0x01 or not flags & 0x04:
        raise ValueError("the user was not verified on the phone")
    try:
        key = serialization.load_der_public_key(spki)
        if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
            raise ValueError("passkey is not ES256")
        key.verify(sig, auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ValueError("bad passkey signature") from None
    return int.from_bytes(auth[33:37], "big")


def valid_passkey(text):
    """A phone's passkey public key (DER SubjectPublicKeyInfo, base64url) -> bytes, or ValueError.
    Only P-256 (ES256) keys are accepted, the one algorithm the phone is asked for."""
    _lib()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        raw = unb64u(text)
        key = serialization.load_der_public_key(raw)
    except Exception:
        raise ValueError("not a passkey public key") from None
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise ValueError("passkey is not ES256")
    return raw
