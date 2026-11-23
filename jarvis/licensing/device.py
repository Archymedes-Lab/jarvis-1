"""This machine's licence identity: a device key and a machine fingerprint.

docs/LICENSING-ARCHITECTURE.md §3. Standard library only (plus `cryptography` when present,
through ed25519.py).

- Device key: an Ed25519 key made on first activation. It signs renew, release, claim-poll and
  content requests, so a copied licence key cannot renew someone else's activation. Stored
  next to licence.json as `licence-device.key`: on native Windows it is protected with DPAPI
  (CurrentUser); elsewhere (the Linux server edition, and the desktop edition's core, which runs
  inside WSL where DPAPI cannot be called directly) it is a file only its owner can read (0600).
- Fingerprint: HMAC-SHA256(key = "argus-fp-v1:" + device public key, message = machine id).
  It is salted with the device key, not the licence id as first drafted, because the app must
  compute it before a licence exists (the in-app purchase claim). The raw machine id never
  leaves the machine and is never stored.
- Machine id: Windows MachineGuid (native: the registry; inside WSL: `reg.exe` through Windows
  interop), else /etc/machine-id. The source used at activation is remembered so the same one
  is read later. What changes it: reinstalling Windows or the Linux OS, cloning a VM without
  resetting its machine id, or (WSL) disabling Windows interop. Recovery: release the old
  machine at https://pay.archymedes.xyz/manage (or `argus licence deactivate` before
  reinstalling) and activate again.
"""

import base64
import hashlib
import hmac
import os
import secrets
import subprocess
import tempfile

from jarvis.licensing import ed25519

KEY_FILE = 'licence-device.key'
_REG = ('HKLM\\SOFTWARE\\Microsoft\\Cryptography', 'MachineGuid')
_WSL_REG_EXE = '/mnt/c/Windows/System32/reg.exe'
_cache = {}


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def unb64url(text):
    text = str(text)
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


class DeviceError(Exception):
    """The machine id or device key cannot be read; the message is safe to show."""


# --- machine id ---------------------------------------------------------------------------------
def _in_wsl():
    try:
        with open('/proc/sys/kernel/osrelease', encoding='ascii', errors='replace') as fh:
            return 'microsoft' in fh.read().lower()
    except OSError:
        return False


def _windows_guid():
    if os.name == 'nt':
        import winreg  # noqa: PLC0415 - Windows only
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Cryptography', 0,
                            winreg.KEY_READ | getattr(winreg, 'KEY_WOW64_64KEY', 0)) as k:
            return str(winreg.QueryValueEx(k, 'MachineGuid')[0]).strip().lower()
    # Windows interop usually answers in ~0.2 s but can stall under load: one retry with a longer wait.
    try:
        out = subprocess.run([_WSL_REG_EXE, 'query', _REG[0], '/v', _REG[1]], capture_output=True,
                             text=True, errors='replace', timeout=8, check=True).stdout
    except subprocess.TimeoutExpired:
        out = subprocess.run([_WSL_REG_EXE, 'query', _REG[0], '/v', _REG[1]], capture_output=True,
                             text=True, errors='replace', timeout=30, check=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0] == _REG[1]:
            return parts[-1].strip().lower()
    raise OSError('MachineGuid not in reg.exe output')


def _linux_id():
    for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
        try:
            with open(path, encoding='ascii', errors='replace') as fh:
                value = fh.read().strip().lower()
            if len(value) >= 16:
                return value
        except OSError:
            continue
    raise OSError('no machine-id')


def default_source():
    return 'windows' if os.name == 'nt' or (_in_wsl() and os.path.exists(_WSL_REG_EXE)) else 'linux'


def machine_id(source=None):
    """The raw machine id from `source` ('windows' or 'linux'). Kept in memory only."""
    source = source or default_source()
    if source in _cache:
        return _cache[source]
    try:
        value = _windows_guid() if source == 'windows' else _linux_id()
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        hint = ('Windows interop may be off in WSL' if source == 'windows' and os.name != 'nt'
                else 'the machine id file is missing')
        raise DeviceError(f'cannot read this machine\'s id ({hint}; {type(exc).__name__})') from None
    _cache[source] = value
    return value


def fingerprint(dpk, mid):
    """64 hex characters; what the licence service and the certificate know of this machine."""
    return hmac.new(b'argus-fp-v1:' + dpk.encode(), mid.encode(), hashlib.sha256).hexdigest()


# --- device key -----------------------------------------------------------------------------------
def _dpapi(data, protect):  # pragma: no cover - native Windows only
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    src, dst = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), Blob()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    if not fn(ctypes.byref(src), None, None, None, None, 0x1, ctypes.byref(dst)):  # UI_FORBIDDEN
        raise OSError('DPAPI refused')
    try:
        return ctypes.string_at(dst.pbData, dst.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(dst.pbData)


def _write_private(path, data):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.licence-', dir=d)
    try:
        if hasattr(os, 'fchmod'):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


class DeviceKey:
    def __init__(self, seed):
        self.seed = seed
        self.dpk = b64url(ed25519.public_key(seed))

    def sign(self, message):
        return b64url(ed25519.sign(self.seed, message.encode()))

    def signed(self, action, subject, now):
        """{nonce, ts, sig} over "argus|v1|<action>|<subject>|<nonce>|<ts>" (src/cert.ts signedMessage)."""
        nonce, ts = secrets.token_urlsafe(18), int(now)
        return {'nonce': nonce, 'ts': ts, 'sig': self.sign(f'argus|v1|{action}|{subject}|{nonce}|{ts}')}

    def mac(self, text):
        """HMAC under a key derived from the device seed (the last-seen clock guard)."""
        return hmac.new(hashlib.sha256(b'argus-lastseen|' + self.seed).digest(), text.encode(),
                        hashlib.sha256).hexdigest()


def key_path(state_dir):
    return os.path.join(state_dir, KEY_FILE)


def load_key(state_dir, create=False):
    """This install's device key; a new one when `create` and none exists. None otherwise."""
    path = key_path(state_dir)
    try:
        with open(path, 'rb') as fh:
            raw = fh.read(4096)
        if raw.startswith(b'dpapi:'):
            raw = _dpapi(base64.b64decode(raw[6:]), protect=False)
        seed = unb64url(raw.decode().strip())
        if len(seed) == 32:
            return DeviceKey(seed)
    except (OSError, ValueError):
        pass
    if not create:
        return None
    seed = secrets.token_bytes(32)
    data = b64url(seed).encode()
    if os.name == 'nt':  # pragma: no cover - native Windows only
        data = b'dpapi:' + base64.b64encode(_dpapi(data, protect=True))
    _write_private(path, data)
    return DeviceKey(seed)
