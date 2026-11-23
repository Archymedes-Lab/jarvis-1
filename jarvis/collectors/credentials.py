"""What a credential looks like: the patterns, the filters that reject placeholders
and examples, and scanning one file.

Shared by the secrets collector (identity/secrets) and the application-code
scanner (appcode), so it sits directly under collectors/ like signatures.py."""

import base64
import hashlib
import math
import os
import re

from jarvis.core import safeio

# (name, regex, severity floor). Ordered most-specific first: a match on a
# vendor-prefixed token is a fact, while a generic assignment is a guess.
PATTERNS = [
    ("AWS access key id", re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), "low"),
    ("GitHub token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b"), "critical"),
    ("GitHub fine-grained token", re.compile(r"\b(github_pat_[A-Za-z0-9_]{50,})\b"), "critical"),
    ("Slack token", re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b"), "critical"),
    ("Stripe live key", re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b"), "critical"),
    ("Anthropic API key", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"), "critical"),
    ("OpenAI API key", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})\b"), "critical"),
    ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), "high"),
    ("npm token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), "critical"),
    ("SendGrid key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), "critical"),
    ("Twilio key", re.compile(r"\b(SK[0-9a-fA-F]{32})\b"), "high"),
    ("JSON web token", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"), "high"),
    ("database URL with password",
     re.compile(r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]{4,}@[^\s/]+)"), "critical"),
    ("Convex deploy key", re.compile(r"\b(prod:[a-z0-9\-]+\|[A-Za-z0-9+/=]{24,})\b"), "critical"),
    # The keyword has to be allowed *inside* a longer identifier: `\bsecret\b`
    # never matches SECRET_TOKEN, because underscore is a word character, and
    # SCREAMING_SNAKE_CASE is exactly how environment files name these.
    ("generic secret assignment",
     # Generic detection is intentionally limited to a quoted literal. The old
     # optional quote accepted any long identifier on the right-hand side, so
     # ordinary code such as `password: credentials.password` and
     # `input_tokens: completed.inputTokens` became critical "secrets". Bare
     # values in .env/YAML/config files are handled separately in scan_file,
     # where the file type gives that syntax meaning.
     re.compile(r"(?i)[A-Za-z0-9_\-]{0,40}?(?:api[_\-]?key|secret|token|passwd|"
                r"password|access[_\-]?key|client[_\-]?secret|auth[_\-]?token|"
                r"private[_\-]?key|credential)[A-Za-z0-9_\-]{0,40}\s*[:=]\s*"
                r"([\"'])([A-Za-z0-9_\-+/=\.]{16,})\1"), "medium"),
]


# Unquoted assignments are normal in environment and data/config files, but in
# source code they are almost always references or expressions. Keep this path
# anchored to the whole line and enable it only for formats where a bare scalar
# is actually a stored value.
GENERIC_BARE = re.compile(
    r"(?i)^\s*(?:export\s+)?[A-Za-z0-9_\-]{0,40}?(?:api[_\-]?key|secret|token|"
    r"passwd|password|access[_\-]?key|client[_\-]?secret|auth[_\-]?token|"
    r"private[_\-]?key|credential)[A-Za-z0-9_\-]{0,40}\s*[:=]\s*"
    r"([A-Za-z0-9_\-+/=\.]{16,})\s*(?:#.*)?$")


BARE_VALUE_EXTS = {
    ".env", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg",
    ".properties", ".service",
}


# Values that match the generic pattern but say nothing.
PLACEHOLDER = re.compile(
    r"^(?:changeme|change[_\-]?[\w\-]*|placeholder|"
    r"(?:[a-z0-9]+[_\-])?your[_\-]?\w*|"
    r"(?:replace|insert|generate|output)[_\-][\w\-]*|example\w*|xxx+|<[^>]*>|\.{3,}|"
    r"legacy[_\-][\w\-]*|null|none|undefined|true|false|test|dummy|sample|redacted|secret|"
    r"password|token|abcdef\w*|0+|1234\w*|process\.env\.\w+|\$\{?\w+\}?)$",
    re.I)


def _entropy(s):
    """Shannon entropy per character. Real keys are near-random; words are not."""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def fingerprint(secret):
    """A stable, non-reversible id for a credential.

    Enough to notice the same key in two files, or to confirm a rotation
    happened. Not enough to be a leak in its own right — which matters,
    because this report is itself written to disk.
    """
    return hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()[:12]


def _mask(secret):
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}{'*' * 8}{secret[-2:]}"


def _looks_real(name, value):
    if PLACEHOLDER.match(value.strip()):
        return False
    if name == "database URL with password":
        # Judge the password component, not the whole URL. Documentation often
        # uses otherwise-valid URLs such as user:password@host, and the URL as a
        # whole naturally defeats the generic placeholder check above.
        match = re.match(r"^[a-z+]+://[^:@/]+:([^@/]+)@", value, re.I)
        if match and PLACEHOLDER.match(match.group(1)):
            return False
    if name == "generic secret assignment":
        # A quoted SCREAMING_SNAKE_CASE value is the *name* of the environment
        # variable to read, not its value (for example webhookSecretEnv:
        # "CARD_ACQUIRER_WEBHOOK_SECRET").
        if re.fullmatch(r"[A-Z][A-Z0-9_]{15,}", value):
            return False
        # Browser storage/cookie namespaces are often assigned to fields named
        # tokenKey or sessionSecret even though the string is only a lookup
        # name (`product.oidc_access.token`), not credential material.
        if "." in value and re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+",
                                         value):
            return False
        # Only trust the generic pattern when the value looks random.
        if len(value) < 20 or _entropy(value) < 3.6:
            return False
        if re.match(r"^[A-Za-z]+$", value):      # a word, however long
            return False
    return True


_PRIVATE_BLOCK = re.compile(
    r"-----BEGIN ((?:ENCRYPTED |RSA |EC |OPENSSH |DSA )?PRIVATE KEY)-----"
    r"(.*?)-----END \1-----", re.S)
_PRIVATE_BEGIN = re.compile(r"-----BEGIN ((?:ENCRYPTED |RSA |EC |OPENSSH |DSA )?PRIVATE KEY)-----")


class _Block:
    """The slice of one BEGIN..END block, shaped like the regex match it replaces."""

    def __init__(self, text, start, body_start, body_end, end, label):
        self._text, self._start, self._end = text, start, end
        self._groups = {1: label, 2: text[body_start:body_end]}

    def start(self):
        return self._start

    def group(self, *ids):
        if ids == (0,):
            return self._text[self._start:self._end]
        return tuple(self._groups[i] for i in ids) if len(ids) > 1 else self._groups[ids[0]]


def _block_matches(text):
    """What _PRIVATE_BLOCK.finditer(text) finds, in linear time.

    The lazy `(.*?)` retried from every BEGIN that has no END: a file of
    unterminated BEGIN lines took minutes (quadratic). Once a label's END is
    known to be absent past some point, later BEGINs of that label are skipped."""
    pos, no_end_after = 0, {}
    while True:
        m = _PRIVATE_BEGIN.search(text, pos)
        if not m:
            return
        label = m.group(1)
        if label in no_end_after and m.end() >= no_end_after[label]:
            pos = m.start() + 1
            continue
        end_marker = f"-----END {label}-----"
        q = text.find(end_marker, m.end())
        if q < 0:
            no_end_after[label] = m.end()
            pos = m.start() + 1
            continue
        yield _Block(text, m.start(), m.end(), q, q + len(end_marker), label)
        pos = q + len(end_marker)


def _private_blocks(text):
    line, counted = 1, 0            # line numbers counted incrementally, not from 0 per block
    for match in _block_matches(text):
        label, body = match.group(1, 2)
        protection = "unknown"
        if label == "ENCRYPTED PRIVATE KEY" or "Proc-Type: 4,ENCRYPTED" in body:
            protection = "encrypted"
        elif label == "OPENSSH PRIVATE KEY":
            try:
                raw = base64.b64decode("".join(body.split()), validate=True)
                magic = b"openssh-key-v1\x00"
                if raw.startswith(magic):
                    offset = len(magic)
                    size = int.from_bytes(raw[offset:offset + 4], "big")
                    cipher = raw[offset + 4:offset + 4 + size]
                    if size and len(cipher) == size:
                        protection = "unencrypted" if cipher == b"none" else "encrypted"
            except ValueError:
                pass
        elif label in ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY"):
            protection = "unencrypted"
        # Hash the whole block, normalized for wrapping; never the shared header.
        value = "".join(match.group(0).split())
        line += text.count("\n", counted, match.start())
        counted = match.start()
        yield (f"private key block ({protection})", value, line,
               "low" if protection == "encrypted" else "high")


def scan_file(path, max_bytes=2 * 1024 * 1024, follow=True):
    """Return [(kind, secret, lineno, severity)] without keeping any of it.

    The read is bounded and refuses FIFOs and devices whatever the size the
    path claimed (safeio); follow=False also refuses a symlink, for walks
    that decided not to follow links."""
    out = []
    try:
        text = safeio.read_text(path, max_bytes, follow=follow, errors="strict")
    except (OSError, UnicodeDecodeError, ValueError):
        return out          # binary or unreadable: not our business
    if text is None:
        return out

    out.extend(_private_blocks(text))
    for lineno, line in enumerate(text.splitlines(), 1):
        # Long lines are minified bundles and base64 blobs — no human puts a
        # credential there, and they are exactly where an unbounded regex goes
        # quadratic. The first full scan never finished; this cap is why it now
        # takes seconds.
        if len(line) > 800:
            continue
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "*", "<!--")) and "BEGIN" not in line:
            continue
        for name, rx, sev in PATTERNS:
            m = rx.search(line)
            if not m:
                continue
            # The generic quoted rule captures its quote delimiter first so it
            # can require a matching close quote; every specific rule captures
            # the credential itself in group 1.
            value = m.group(2) if name == "generic secret assignment" else m.group(1)
            if not _looks_real(name, value):
                continue
            out.append((name, value, lineno, sev))
            break               # one finding per line is enough
        else:
            ext = os.path.splitext(path)[1].lower()
            basename = os.path.basename(path).lower()
            env_like = (ext in BARE_VALUE_EXTS or basename == ".env"
                        or basename.startswith(".env."))
            if env_like:
                m = GENERIC_BARE.search(line)
                if m and _looks_real("generic secret assignment", m.group(1)):
                    out.append(("generic secret assignment", m.group(1), lineno,
                                "medium"))
    return out
