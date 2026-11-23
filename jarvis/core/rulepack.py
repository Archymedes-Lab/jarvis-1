"""Signed detection content: rule packs that update separately from the program.

Design and threat model: docs/architecture/DETECTION-CONTENT.md.

A rule pack is a JSON document of data-only detection rules (today: process-
creation rules shaped like collectors/telemetry/techniques.Rule), signed with
`ssh-keygen -Y sign -n argus-rules` by a key pinned in this file. The program's
built-in rules always run; a pack can only add rules. Content is never
authority: a pack cannot run code, cannot raise a finding above "high", and its
findings are marked origin=rulepack so the response ladder never acts on them
unasked (response/defense.py).

Invariants (tests/test_rulepack.py holds each, success and failure paths):
    R1  only bytes signed by a pinned key, in the argus-rules namespace, load
    R2  strict schema: unknown keys, duplicate keys, wrong types, non-finite
        numbers, oversize packs or fields are refused
    R3  freeze/rollback: a pack older than the newest one this host accepted is
        refused, the same version with different bytes is refused
        (equivocation), and an expired pack stops matching
    R4  fail safe: any failure leaves the built-in rules, and the previously
        accepted pack if it is still valid, in force; loading never raises
    R5  atomic: the installed bundle is replaced by rename, never written in
        place; a crash leaves the old bundle or the new one, never a mix
    R6  bounded: pack bytes, rule count, field lengths and a safe regex subset
        are checked statically; each pattern is then timed against adversarial
        subjects in a child process with a hard deadline, so a pathological
        regex is refused at load instead of stalling the daemon
    R7  every rule's own sample must fire it and its benign look-alikes must not
    R8  visible: every state other than "builtin" and "active" is a reason the
        selfguard collector reports (missing, rolled back, expired, rejected)
"""

import base64
import hashlib
import importlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from jarvis.core import sshsig

SCHEMA = "argus-rules/1"
BUNDLE_FORMAT = "argus-rules-bundle/1"
NAMESPACE = "argus-rules"
# The keys allowed to sign rule packs, as `<principal> ssh-ed25519 <key>`.
# Deliberately empty: the owner has not created a rules key yet (see the
# design doc, "Keys"). While empty no pack can load and only built-in rules run.
PINNED_SIGNERS = ()

DEFAULT_ROOT = Path(os.path.expanduser("~/.jarvis/rules"))
BUNDLE = "active.json"
STATE = "state.json"

MAX_PACK_BYTES = 256 * 1024
MAX_BUNDLE_BYTES = MAX_PACK_BYTES * 2
MAX_RULES = 500
MAX_PATTERN = 256
MAX_TITLE = 160
MAX_SAMPLE = 1024
MAX_IMAGES = 16
MAX_TIDS = 8
MAX_BENIGN = 8
MAX_LIFETIME_S = 45 * 86400       # a pack must be re-issued; a frozen feed expires
CLOCK_SKEW_S = 86400              # issued_at may be this far in the future (WSL clock steps)
SUBJECT = 4096                    # = techniques.MAX_CMDLINE: pack rules read what built-ins read
UNBOUNDED_LIMIT = 2               # unbounded repeats per pattern (measured: 3 explode at 4 KiB)
BOUNDED_MAX = 16                  # largest {m,n} upper bound treated as bounded
PROBE_LIMIT_MS = 100.0            # worst adversarial search on this host; packs are built to 10 ms
PROBE_DEADLINE_S = 20.0           # the whole probe child; past it the pack is refused
RECHECK_S = 60.0
SEVERITIES = ("low", "medium", "high")   # never critical: content is not authority
PLATFORMS = ("win", "linux")
RULE_KEYS = {"id", "tids", "platform", "images", "pattern", "severity", "title", "sample",
             "benign", "quiet", "parents"}
REQUIRED_RULE_KEYS = {"id", "tids", "platform", "images", "pattern", "severity", "title", "sample"}
PACK_KEYS = {"schema", "version", "issued_at", "expires_at", "rules"}
RULE_ID = re.compile(r"AR-[0-9]{4,6}")
TID = re.compile(r"T[0-9]{4}(\.[0-9]{3})?")
IMAGE = re.compile(r"[a-z0-9][a-z0-9_.+-]{0,63}")
PRINTABLE = re.compile(r"[^\x00-\x1f\x7f]*")

STATUSES = ("builtin", "active", "expired", "rejected", "missing", "rollback", "no-signers")


class PackError(Exception):
    pass


# -- regex safe subset ----------------------------------------------------------

# The standard library's own regex parser, used read-only to walk a pattern's
# structure before it is ever compiled for matching (re._parser from 3.11,
# sre_parse before; both are the module `re` itself compiles with).
try:
    _C = importlib.import_module("re._constants")
    _P = importlib.import_module("re._parser")
except ImportError:                             # Python 3.10
    _C = importlib.import_module("sre_constants")
    _P = importlib.import_module("sre_parse")

_ATOMS = {_C.LITERAL, _C.NOT_LITERAL, _C.ANY, _C.IN}
# POSSESSIVE_REPEAT (3.11+) cannot backtrack, but is held to the same limits.
_REPEATS = {_C.MAX_REPEAT, _C.MIN_REPEAT} | {getattr(_C, n) for n in ("POSSESSIVE_REPEAT",)
                                             if hasattr(_C, n)}
_FLAGS = re.I | re.S


def _fixed_width(items):
    """True when a repeat body is a fixed sequence of single-character atoms."""
    for op, av in items:
        if op in _ATOMS:
            continue
        if op == _C.SUBPATTERN and _fixed_width(av[-1]):
            continue
        return False
    return True


def _walk(items, budget, in_assert=False):
    for op, av in items:
        if op in _ATOMS or op == _C.AT:
            continue
        if op == _C.SUBPATTERN:
            _walk(av[-1], budget, in_assert)
        elif op == _C.BRANCH:
            for alt in av[1]:
                _walk(alt, budget, in_assert)
        elif op in _REPEATS:
            lo, hi, body = av
            if in_assert:
                raise PackError("no repetition inside a lookaround")
            if not _fixed_width(body):
                raise PackError("a repeated group may hold only fixed single characters "
                                "(no nested repeats or alternation under a quantifier)")
            if hi == _C.MAXREPEAT or hi > BOUNDED_MAX:
                budget["unbounded"] += 1
            if budget["unbounded"] > UNBOUNDED_LIMIT:
                raise PackError(f"more than {UNBOUNDED_LIMIT} unbounded repeats")
        elif op in (_C.ASSERT, _C.ASSERT_NOT):
            _walk(av[1], budget, True)
        else:
            raise PackError(f"regex construct {op} is outside the safe subset "
                            "(no backreferences, conditionals or atomic groups)")


def check_pattern(pattern):
    """Raise PackError unless `pattern` is in the safe subset; return its literals."""
    if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_PATTERN:
        raise PackError(f"a pattern must be 1..{MAX_PATTERN} characters")
    if not PRINTABLE.fullmatch(pattern):
        raise PackError("control characters in a pattern")
    try:
        parsed = _P.parse(pattern, _FLAGS)
        re.compile(pattern, _FLAGS)
    except (re.error, OverflowError, RecursionError) as exc:
        raise PackError(f"pattern does not compile: {exc}") from None
    _walk(list(parsed), {"unbounded": 0})
    return pattern


def adversarial_subjects(pattern, n=SUBJECT):
    """A bounded set of subjects that make backtracking regexes slow: long runs
    of the pattern's own literal characters, pairs of them, and generic runs."""
    lits = sorted({chr(c).lower() for c in _literals(_P.parse(pattern, _FLAGS))
                   if 32 <= c < 127})[:6]
    fillers = ["a", " ", "a ", "a1 -", "\\/", "ab"] + lits + [a + b for a in lits[:3] for b in lits[:3] if a != b]
    out = []
    for f in dict.fromkeys(fillers):
        out.append((f * (n // len(f) + 1))[:n])
        if len(out) >= 14:
            break
    return out


def _literals(items):
    for op, av in items:
        if op == _C.LITERAL:
            yield av
        elif op == _C.SUBPATTERN:
            yield from _literals(av[-1])
        elif op == _C.BRANCH:
            for alt in av[1]:
                yield from _literals(alt)
        elif op in _REPEATS:
            yield from _literals(av[2])


def _probe_patterns(patterns):
    """{pattern: worst ms} over adversarial subjects, measured in this process.
    Called only inside the probe child (or by tests on known-safe patterns)."""
    out = {}
    for p in patterns:
        rx = re.compile(p, _FLAGS)
        worst = 0.0
        for s in adversarial_subjects(p):
            t = time.perf_counter()
            rx.search(s)
            worst = max(worst, (time.perf_counter() - t) * 1000.0)
        out[p] = round(worst, 3)
    return out


def probe(patterns, deadline=PROBE_DEADLINE_S):
    """Time every pattern in a child process with a hard deadline.

    -> {pattern: worst ms}. Raises PackError when the child cannot run, dies,
    or runs past the deadline: a regex that would stall the daemon stalls a
    child that is killed instead."""
    patterns = sorted(set(patterns))
    if not patterns:
        return {}
    # Launched like scheduler._isolated_job: `-m` from the package root. The
    # compiled server dispatches this module by name (release/launcher.py).
    from jarvis.core.paths import PACKAGE_DIR, self_executable
    command = [self_executable(), "-m", "jarvis.core.rulepack", "probe"]
    try:
        done = subprocess.run(command, input=json.dumps(patterns), capture_output=True, text=True,
                              errors="replace", cwd=str(PACKAGE_DIR.parent), timeout=deadline, check=False)
    except subprocess.TimeoutExpired:
        raise PackError(f"pattern timing exceeded its {deadline:.0f}s deadline: a pattern "
                        "backtracks pathologically") from None
    except OSError as exc:
        raise PackError(f"pattern timing could not start: {exc.strerror or exc}") from None
    try:
        result = json.loads(done.stdout)
        if done.returncode != 0 or not isinstance(result, dict) or set(result) != set(patterns):
            raise ValueError
        return {p: float(result[p]) for p in patterns}
    except (ValueError, TypeError):
        raise PackError("pattern timing returned no usable result") from None


# -- schema ---------------------------------------------------------------------

def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise PackError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _no_float(text):
    raise PackError("numbers in a pack are integers")


def _text(value, limit, what):
    if not isinstance(value, str) or not value.strip() or len(value) > limit \
            or not PRINTABLE.fullmatch(value):
        raise PackError(f"{what} must be printable text of 1..{limit} characters")
    return value


def _pair(value, what):
    if not (isinstance(value, list) and len(value) == 2):
        raise PackError(f"{what} must be [image, command line]")
    return (_text(value[0], MAX_SAMPLE, what), _text(value[1], MAX_SAMPLE, what))


def _int(value, what, lo=0):
    if type(value) is not int or value < lo or value > 2 ** 53:
        raise PackError(f"{what} must be an integer >= {lo}")
    return value


def _rule(raw, index):
    where = f"rule {index}"
    if not isinstance(raw, dict):
        raise PackError(f"{where} is not an object")
    if set(raw) - RULE_KEYS or REQUIRED_RULE_KEYS - set(raw):
        raise PackError(f"{where}: keys must be {sorted(REQUIRED_RULE_KEYS)} plus optional "
                        f"{sorted(RULE_KEYS - REQUIRED_RULE_KEYS)}")
    rid = raw["id"]
    if not (isinstance(rid, str) and RULE_ID.fullmatch(rid)):
        raise PackError(f"{where}: id must look like AR-0001")
    where = f"rule {rid}"
    tids = raw["tids"]
    if not (isinstance(tids, list) and 1 <= len(tids) <= MAX_TIDS
            and all(isinstance(t, str) and TID.fullmatch(t) for t in tids)):
        raise PackError(f"{where}: tids must be 1..{MAX_TIDS} ATT&CK ids")
    if raw["platform"] not in PLATFORMS:
        raise PackError(f"{where}: platform must be one of {PLATFORMS}")
    images = raw["images"]
    # No image-less rules from a pack: every pack rule is bounded to the
    # processes it names, so its cost and its blast radius stay small.
    if not (isinstance(images, list) and 1 <= len(images) <= MAX_IMAGES
            and all(isinstance(i, str) and IMAGE.fullmatch(i) for i in images)):
        raise PackError(f"{where}: images must be 1..{MAX_IMAGES} lower-case base names")
    parents = raw.get("parents", [])
    if not (isinstance(parents, list) and len(parents) <= MAX_IMAGES
            and all(isinstance(i, str) and IMAGE.fullmatch(i) for i in parents)):
        raise PackError(f"{where}: parents must be lower-case base names")
    if raw["severity"] not in SEVERITIES:
        raise PackError(f"{where}: severity must be one of {SEVERITIES} (a pack cannot raise critical)")
    quiet = raw.get("quiet", False)
    if type(quiet) is not bool:
        raise PackError(f"{where}: quiet must be true or false")
    try:
        check_pattern(raw["pattern"])
    except PackError as exc:
        raise PackError(f"{where}: {exc}") from None
    benign = raw.get("benign", [])
    if not (isinstance(benign, list) and len(benign) <= MAX_BENIGN):
        raise PackError(f"{where}: at most {MAX_BENIGN} benign samples")
    return {"id": rid, "tids": tuple(tids), "platform": raw["platform"], "images": tuple(images),
            "parents": tuple(parents), "pattern": raw["pattern"], "severity": raw["severity"],
            "title": _text(raw["title"], MAX_TITLE, f"{where}: title"),
            "sample": _pair(raw["sample"], f"{where}: sample"),
            "benign": tuple(_pair(b, f"{where}: benign") for b in benign), "quiet": quiet}


def parse(data):
    """Validate pack bytes against the schema. -> pack dict. Raises PackError.
    Static checks only: signature, freshness and timing are separate steps."""
    if not isinstance(data, (bytes, bytearray)) or not data or len(data) > MAX_PACK_BYTES:
        raise PackError(f"a pack is 1..{MAX_PACK_BYTES} bytes")
    try:
        raw = json.loads(bytes(data).decode("utf-8"), object_pairs_hook=_no_duplicates,
                         parse_float=_no_float, parse_constant=_no_float)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, PackError):
            raise
        raise PackError("a pack is UTF-8 JSON") from None
    if not isinstance(raw, dict) or set(raw) != PACK_KEYS:
        raise PackError(f"a pack has exactly the keys {sorted(PACK_KEYS)}")
    if raw["schema"] != SCHEMA:
        raise PackError(f"unknown schema {str(raw['schema'])[:40]!r}; this program reads {SCHEMA}")
    version = _int(raw["version"], "version", 1)
    issued, expires = _int(raw["issued_at"], "issued_at"), _int(raw["expires_at"], "expires_at")
    if not 0 < expires - issued <= MAX_LIFETIME_S:
        raise PackError(f"a pack lives at most {MAX_LIFETIME_S // 86400} days after it is issued")
    rules = raw["rules"]
    if not (isinstance(rules, list) and len(rules) <= MAX_RULES):
        raise PackError(f"a pack holds at most {MAX_RULES} rules")
    parsed = [_rule(r, i) for i, r in enumerate(rules)]
    ids = [r["id"] for r in parsed]
    if len(set(ids)) != len(ids):
        raise PackError("rule ids repeat")
    return {"schema": SCHEMA, "version": version, "issued_at": issued, "expires_at": expires,
            "rules": tuple(parsed), "digest": hashlib.sha256(bytes(data)).hexdigest()}


def _base(image):
    name = (image or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name[:-4] if name.endswith((".exe", ".com")) else name


def check_samples(pack):
    """Raise PackError unless each rule fires on its sample and not on its benign
    look-alikes (R7). Run after timing, so these searches are known to be fast."""
    for r in pack["rules"]:
        rx = re.compile(r["pattern"], _FLAGS)
        image, cmd = r["sample"]
        if _base(image) not in r["images"] or not rx.search(cmd[:SUBJECT]):
            raise PackError(f"rule {r['id']}: its sample does not fire it")
        for b_image, b_cmd in r["benign"]:
            if _base(b_image) in r["images"] and rx.search(b_cmd[:SUBJECT]):
                raise PackError(f"rule {r['id']}: a benign sample fires it")


def check_timing(pack, timer=probe):
    """Raise PackError when any pattern's worst adversarial search is over the limit."""
    worst = timer([r["pattern"] for r in pack["rules"]])
    slow = sorted((ms, r["id"]) for r in pack["rules"] if (ms := worst.get(r["pattern"], 1e9)) > PROBE_LIMIT_MS)
    if slow:
        ms, rid = slow[-1]
        raise PackError(f"rule {rid}: worst-case match took {ms:.0f} ms (limit {PROBE_LIMIT_MS:.0f} ms)")
    return worst


def verify(data, signature, *, signers=None, now=None, floor=None, timer=probe):
    """The full acceptance path for one pack. -> pack. Raises PackError.

    floor: (highest accepted version, its digest) on this host, or None."""
    signers = PINNED_SIGNERS if signers is None else signers
    now = time.time() if now is None else now
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_PACK_BYTES:
        raise PackError(f"a pack is at most {MAX_PACK_BYTES} bytes")
    try:
        principal, fp = sshsig.verify(bytes(data), signature, signers, NAMESPACE)
    except sshsig.SignatureError as exc:
        raise PackError(f"signature refused: {exc}") from None
    pack = parse(data)
    if pack["issued_at"] > now + CLOCK_SKEW_S:
        raise PackError("the pack is issued in the future: check the clock")
    if pack["expires_at"] <= now:
        raise PackError("the pack has expired")
    if floor:
        highest, digest = floor
        if pack["version"] < highest:
            raise PackError(f"version {pack['version']} is older than version {highest} "
                            "already accepted here (rollback refused)")
        if pack["version"] == highest and digest and pack["digest"] != digest:
            raise PackError(f"version {highest} with different contents (equivocation refused)")
    check_timing(pack, timer)
    check_samples(pack)
    pack["signer"], pack["fingerprint"] = principal, fp
    return pack


# -- installed bundle and state -------------------------------------------------

def _atomic_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def read_state(root=DEFAULT_ROOT):
    """{"highest": int, "digest": str, "accepted_at": int} or {} (never raises)."""
    try:
        with open(Path(root) / STATE, encoding="utf-8", errors="replace") as fh:
            state = json.loads(fh.read(4096))
        if isinstance(state, dict) and type(state.get("highest")) is int:
            return state
    except (OSError, ValueError):
        pass
    return {}


def _read_bundle(root):
    p = Path(root) / BUNDLE
    try:
        if p.is_symlink():
            raise PackError("the installed bundle is a symlink")
        with open(p, "rb") as fh:
            raw = fh.read(MAX_BUNDLE_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PackError(f"the installed bundle cannot be read: {exc.strerror or exc}") from None
    if len(raw) > MAX_BUNDLE_BYTES:
        raise PackError("the installed bundle is oversize")
    try:
        b = json.loads(raw)
        if b.get("format") != BUNDLE_FORMAT:
            raise ValueError
        return base64.b64decode(b["pack"], validate=True), str(b["sig"])
    except (ValueError, KeyError, TypeError, AttributeError):
        raise PackError("the installed bundle is malformed") from None


def install(data, signature, *, root=DEFAULT_ROOT, signers=None, now=None, timer=probe):
    """Verify, then atomically make this pack the installed one. -> pack.

    Raises PackError and changes nothing when the pack is refused (R4, R5)."""
    now = time.time() if now is None else now
    state = read_state(root)
    floor = (state["highest"], state.get("digest", "")) if state else None
    pack = verify(data, signature, signers=signers, now=now, floor=floor, timer=timer)
    bundle = json.dumps({"format": BUNDLE_FORMAT, "pack": base64.b64encode(bytes(data)).decode(),
                         "sig": signature})
    _atomic_write(Path(root) / BUNDLE, bundle)
    _atomic_write(Path(root) / STATE, json.dumps({"highest": pack["version"], "digest": pack["digest"],
                                                   "accepted_at": int(now)}))
    _CACHE.clear()
    return pack


def load(root=DEFAULT_ROOT, *, signers=None, now=None, timer=probe):
    """{"status", "pack" (or None), "problem", "version"}: never raises (R4).

    The installed bundle is re-verified from disk every time it changes:
    nothing on disk is trusted because it was trusted when it was written."""
    signers = PINNED_SIGNERS if signers is None else signers
    now = time.time() if now is None else now
    state = read_state(root)
    highest = state.get("highest", 0)
    out = {"status": "builtin", "pack": None, "problem": "", "version": highest or None}
    try:
        found = _read_bundle(root)
    except PackError as exc:
        return {**out, "status": "rejected", "problem": str(exc)}
    if found is None:
        if highest:
            out.update(status="missing", problem=f"rule pack version {highest} was accepted here "
                                                 "but its installed copy is gone")
        return out
    if not signers:
        return {**out, "status": "no-signers",
                "problem": "a rule pack is installed but this program pins no rule-pack keys"}
    data, sig = found
    try:
        # floor None: verify() checks freshness and signature; the version
        # comparison below names rollback separately from other refusals.
        pack = verify(data, sig, signers=signers, now=now, floor=None, timer=timer)
    except PackError as exc:
        status = "expired" if "expired" in str(exc) else "rejected"
        return {**out, "status": status, "problem": str(exc)}
    if highest and pack["version"] < highest:
        return {**out, "status": "rollback",
                "problem": f"installed pack version {pack['version']} is older than version "
                           f"{highest} already accepted here"}
    if highest and pack["version"] == highest and state.get("digest") not in ("", None, pack["digest"]):
        return {**out, "status": "rejected", "problem": "installed pack differs from the accepted one"}
    return {"status": "active", "pack": pack, "problem": "", "version": pack["version"]}


_CACHE = {}
_LOCK = threading.Lock()


def _stamp(root):
    stamp = []
    for name in (BUNDLE, STATE):
        try:
            st = os.stat(Path(root) / name)
            stamp.append((st.st_mtime_ns, st.st_size, st.st_ino))
        except OSError:
            stamp.append(None)
    return tuple(stamp)


def _expiry(result, now):
    pack = result.get("pack")
    if pack and pack["expires_at"] <= now:
        return {"status": "expired", "pack": None, "version": pack["version"],
                "problem": "the pack has expired"}
    return result


def _refresh(key, root, signers):
    """Background verification for non-blocking callers (one per key at a time)."""
    try:
        stamp = _stamp(root)
        result = load(root, signers=signers)
        with _LOCK:
            _CACHE[key] = {"checked": time.time(), "stamp": stamp, "result": result}
    finally:
        with _LOCK:
            _PENDING.discard(key)


_PENDING = set()
PENDING = {"status": "builtin", "pack": None, "problem": "rule-pack verification pending", "version": None}


def current(root=DEFAULT_ROOT, *, signers=None, now=None, block=True):
    """load() with a cache: re-stat at most every RECHECK_S, re-verify only when
    the bundle or state changed, and re-check expiry on every call.

    block=False is for hot consumers (the technique matcher runs per process
    event inside tier-0 collectors): a changed bundle is verified on a
    background thread while the last verified result, still expiry-checked,
    keeps serving, so verification (ssh-keygen and the timing child, up to
    PROBE_DEADLINE_S) never stalls detection (R4)."""
    now = time.time() if now is None else now
    signers = PINNED_SIGNERS if signers is None else tuple(signers)
    key = (str(root), signers)
    with _LOCK:
        hit = _CACHE.get(key)
        if hit and now - hit["checked"] < RECHECK_S:
            return _expiry(hit["result"], now)
        stamp = _stamp(root)
        if hit and hit["stamp"] == stamp:
            hit["checked"] = now
            return _expiry(hit["result"], now)
        if not block:
            if key not in _PENDING:
                _PENDING.add(key)
                threading.Thread(target=_refresh, args=(key, root, signers),
                                 name="rulepack-verify", daemon=True).start()
            return _expiry(hit["result"], now) if hit else PENDING
    result = load(root, signers=signers, now=now)
    with _LOCK:
        _CACHE[key] = {"checked": now, "stamp": stamp, "result": result}
    return result


def active_rules(root=DEFAULT_ROOT):
    """The rules of the valid installed pack, or () — never raises."""
    try:
        pack = current(root, block=False).get("pack")
    except Exception:
        return ()
    return pack["rules"] if pack else ()


# -- distribution -----------------------------------------------------------------

def fetch(base_url, *, timeout=20.0, opener=None):
    """(pack bytes, signature text) from `<base_url>/rules.json(.sig)`.

    HTTPS only, redirects only to HTTPS, no query string, cookies or host
    details: every host asks for the same two files with the same headers, so
    the request reveals only that an Argus install fetched rules."""
    import urllib.parse
    import urllib.request

    u = urllib.parse.urlsplit(base_url)
    if u.scheme != "https" or not u.hostname or u.query or u.fragment or u.username:
        raise PackError("the rule-pack URL must be a plain https:// address")

    class _HttpsOnly(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if urllib.parse.urlsplit(newurl).scheme != "https":
                raise PackError("redirect away from HTTPS refused")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = opener or urllib.request.build_opener(_HttpsOnly())
    out = []
    for name, cap in (("rules.json", MAX_PACK_BYTES), ("rules.json.sig", sshsig.MAX_SIGNATURE)):
        req = urllib.request.Request(base_url.rstrip("/") + "/" + name,
                                     headers={"User-Agent": "argus-rules", "Accept": "*/*"})
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(cap + 1)
        except PackError:
            raise
        except Exception as exc:
            raise PackError(f"fetching {name} failed: {type(exc).__name__}") from None
        if len(body) > cap:
            raise PackError(f"{name} is over {cap} bytes")
        out.append(body)
    return out[0], out[1].decode("ascii", "replace")


def _main(argv):
    if argv[:1] == ["probe"]:
        patterns = json.loads(sys.stdin.read(MAX_PACK_BYTES))
        if not (isinstance(patterns, list) and all(isinstance(p, str) for p in patterns)):
            return 2
        for p in patterns:
            check_pattern(p)                     # the child re-checks: it trusts no caller
        sys.stdout.write(json.dumps(_probe_patterns(patterns)))
        return 0
    sys.stderr.write("usage: python -m jarvis.core.rulepack probe < patterns.json\n")
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
