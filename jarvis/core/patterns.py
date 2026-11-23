"""File-content rules: a strict subset of YARA, evaluated by literal search.

Command lines never show what a file contains. Community YARA rules do, but a
YARA engine is native code this program does not ship. So, as with Sigma rules
(core/sigma.py), rules are compiled ahead of time by
scripts/security/yara_compile.py into a small JSON form and evaluated here with
nothing but `bytes.find`: text and plain-byte strings (ascii, wide, nocase,
fullword), boolean conditions, `N of`, file size and fixed bytes at an offset.
There is no regular expression and no rule code at run time. A rule that needs
anything else is left out by the compiler, never approximated.

Content is not authority: a match is a finding for a person to judge, capped
below critical, and nothing is acted on because a rule matched.

Licence: rules come from signature-base under the Detection Rule License 1.1;
every finding built from a rule must name its author (`attribution()`).
"""

import json

from jarvis.core.paths import PACKAGE_DIR

SCHEMA = "argus-patterns/1"
DATA = PACKAGE_DIR / "intel" / "data" / "content_rules.json"
LICENSE = "Detection Rule License 1.1"
LICENSE_URL = "https://github.com/SigmaHQ/Detection-Rule-License"

MAX_BYTES = 16 * 1024 * 1024
MAX_RULES = 8000
MAX_STRINGS = 300
MIN_PATTERN = 4               # shorter literals match by accident
MAX_PATTERN = 512
MAX_DEPTH = 16
MAX_OFFSET = 4096
HIGH_SCORE = 90               # rule score -> severity: >= 90 high, otherwise medium; never critical


class PatternError(ValueError):
    """The compiled rule file is not in the form this program evaluates."""


class Rule:
    __slots__ = ("id", "title", "author", "ref", "score", "severity", "strings", "condition", "gate")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def _text(value, limit, what):
    if not isinstance(value, str) or len(value) > limit:
        raise PatternError(f"{what} must be text of at most {limit} characters")
    return value


def _condition(node, names, depth=0):
    if depth > MAX_DEPTH or not isinstance(node, list) or not node:
        raise PatternError("condition is malformed or too deep")
    op = node[0]
    if op == "str":
        if len(node) != 2 or node[1] not in names:
            raise PatternError("condition names an unknown string")
        return ("str", node[1])
    if op == "not":
        if len(node) != 2:
            raise PatternError("not takes one operand")
        return ("not", _condition(node[1], names, depth + 1))
    if op in ("and", "or"):
        if len(node) < 3:
            raise PatternError(f"{op} takes at least two operands")
        return (op,) + tuple(_condition(n, names, depth + 1) for n in node[1:])
    if op == "of":
        if len(node) != 3 or not isinstance(node[2], list) or not node[2] or any(n not in names for n in node[2]):
            raise PatternError("a count names an unknown string")
        count = node[1]
        if count not in ("all", "any") and not (isinstance(count, int) and not isinstance(count, bool)
                                                and 0 < count <= len(node[2])):
            raise PatternError("a count is all, any, or 1..the size of its set")
        return ("of", count, tuple(node[2]))
    if op == "size":
        if len(node) != 3 or node[1] not in ("<", ">", "<=", ">=") or not isinstance(node[2], int) \
                or isinstance(node[2], bool) or node[2] < 0:
            raise PatternError("a size test is [size, comparison, bytes]")
        return ("size", node[1], node[2])
    if op == "bytes":
        if len(node) != 3 or not isinstance(node[1], int) or isinstance(node[1], bool) \
                or not 0 <= node[1] <= MAX_OFFSET:
            raise PatternError("a bytes test is [bytes, offset, hex]")
        try:
            value = bytes.fromhex(_text(node[2], 16, "bytes value"))
        except ValueError:
            raise PatternError("a bytes test holds hex") from None
        if not 0 < len(value) <= 8:
            raise PatternError("a bytes test compares 1..8 bytes")
        return ("bytes", node[1], value)
    raise PatternError(f"unknown condition operator {str(op)[:20]!r}")


def _string(raw):
    if not isinstance(raw, dict) or set(raw) != {"b", "nocase", "fullword", "wide", "ascii"}:
        raise PatternError("a string is {b, nocase, fullword, wide, ascii}")
    if not all(isinstance(raw[k], bool) for k in ("nocase", "fullword", "wide", "ascii")):
        raise PatternError("string flags are true or false")
    try:
        data = bytes.fromhex(_text(raw["b"], MAX_PATTERN * 2, "string"))
    except ValueError:
        raise PatternError("a string is stored as hex") from None
    if not MIN_PATTERN <= len(data) <= MAX_PATTERN:
        raise PatternError(f"a string is {MIN_PATTERN}..{MAX_PATTERN} bytes")
    if not (raw["ascii"] or raw["wide"]):
        raise PatternError("a string is ascii, wide or both")
    if raw["nocase"] and data != data.lower():
        raise PatternError("a case-insensitive string is stored lower-case")
    forms = []
    if raw["ascii"]:
        forms.append((data, False))
    if raw["wide"]:
        forms.append((b"".join(bytes((c, 0)) for c in data), True))
    return (tuple(forms), raw["nocase"], raw["fullword"])


def _gate(cond):
    """Cheap tests the whole rule depends on (top-level `and` only): fixed bytes and size."""
    parts = cond[1:] if cond[0] == "and" else (cond,)
    return tuple(p for p in parts if p[0] in ("bytes", "size"))


def parse(data):
    """Validate compiled rule bytes. -> {"source": {...}, "rules": (Rule, ...)}"""
    if not isinstance(data, (bytes, bytearray)) or not data or len(data) > MAX_BYTES:
        raise PatternError(f"the rule file is 1..{MAX_BYTES} bytes")
    try:
        doc = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise PatternError("the rule file is UTF-8 JSON") from None
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise PatternError(f"this program reads {SCHEMA}")
    source = doc.get("source")
    if not isinstance(source, dict) or not all(isinstance(source.get(k), str) and source.get(k)
                                               for k in ("repo", "commit", "license")):
        raise PatternError("the rule file must say where its rules come from and their licence")
    raw_rules = doc.get("rules")
    if not isinstance(raw_rules, list) or len(raw_rules) > MAX_RULES:
        raise PatternError(f"at most {MAX_RULES} rules")
    out, seen = [], set()
    for r in raw_rules:
        if not isinstance(r, dict):
            raise PatternError("a rule is an object")
        rid = _text(r.get("id"), 128, "rule id")
        if not rid or rid in seen:
            raise PatternError("rule ids are unique and not empty")
        seen.add(rid)
        author = _text(r.get("author"), 300, "author").strip()
        if not author:
            raise PatternError(f"rule {rid} names no author")     # DRL 1.1: every alert names one
        score = r.get("score")
        if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 100:
            raise PatternError("score is 0..100")
        strings = r.get("strings")
        if not isinstance(strings, dict) or not 0 < len(strings) <= MAX_STRINGS:
            raise PatternError("a rule has 1..%d strings" % MAX_STRINGS)
        parsed = {_text(n, 64, "string name"): _string(s) for n, s in strings.items()}
        cond = _condition(r.get("cond"), parsed)
        out.append(Rule(id=rid, title=_text(r.get("title"), 200, "title"), author=author,
                        ref=_text(r.get("ref") or "", 300, "reference"), score=score,
                        severity="high" if score >= HIGH_SCORE else "medium",
                        strings=parsed, condition=cond, gate=_gate(cond)))
    return {"source": {k: source[k] for k in ("repo", "commit", "license")}, "rules": tuple(out)}


def _alnum(b):
    return 48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122


def _whole_word(data, at, length, wide):
    step = 2 if wide else 1
    before = at - step
    if before >= 0 and _alnum(data[before]) and (not wide or data[before + 1] == 0):
        return False
    after = at + length
    if after < len(data) and _alnum(data[after]) and (not wide or (after + 1 < len(data) and data[after + 1] == 0)):
        return False
    return True


class File:
    """One file's bytes, with the lower-cased copy made only if a rule needs it."""

    __slots__ = ("data", "size", "_lower", "_found")

    def __init__(self, data, size=None):
        self.data = data
        self.size = len(data) if size is None else size
        self._lower = None
        self._found = {}

    def has(self, string):
        if string in self._found:
            return self._found[string]
        forms, nocase, fullword = string
        if nocase and self._lower is None:
            self._lower = self.data.lower()
        hay = self._lower if nocase else self.data
        hit = False
        for pattern, wide in forms:
            at = hay.find(pattern)
            while at >= 0:
                if not fullword or _whole_word(hay, at, len(pattern), wide):
                    hit = True
                    break
                at = hay.find(pattern, at + 1)
            if hit:
                break
        self._found[string] = hit
        return hit


_CMP = {"<": lambda a, b: a < b, ">": lambda a, b: a > b, "<=": lambda a, b: a <= b, ">=": lambda a, b: a >= b}


def _holds(node, rule, f):
    op = node[0]
    if op == "str":
        return f.has(rule.strings[node[1]])
    if op == "size":
        return _CMP[node[1]](f.size, node[2])
    if op == "bytes":
        if node[1] + len(node[2]) > len(f.data):
            return None
        return f.data[node[1]:node[1] + len(node[2])] == node[2]
    if op == "not":
        value = _holds(node[1], rule, f)
        return None if value is None else not value
    if op == "and":
        values = [_holds(n, rule, f) for n in node[1:]]
        return False if False in values else (None if None in values else True)
    if op == "or":
        values = [_holds(n, rule, f) for n in node[1:]]
        return True if True in values else (None if None in values else False)
    count, names = node[1], node[2]
    if count == "any":
        return any(f.has(rule.strings[n]) for n in names)
    need = len(names) if count == "all" else count
    got, left = 0, len(names)
    for n in names:
        if f.has(rule.strings[n]):
            got += 1
            if got >= need:
                return True
        left -= 1
        if got + left < need:
            return False
    return False


def match(rules, data, size=None):
    """Rules satisfied by a complete file. A partial read yields no verdict."""
    if size is not None and size != len(data):
        return []  # Absence predicates require complete evidence.
    f = File(data, size)
    out = []
    for rule in rules:
        if all(_holds(g, rule, f) for g in rule.gate) and _holds(rule.condition, rule, f):
            out.append(rule)
    return out


def attribution(rule):
    """The credit a finding must carry (DRL 1.1): author, rule name, licence."""
    return f"YARA rule {rule.id} by {rule.author} ({LICENSE})"


_LOADED = {}


def load(path=None):
    """(rules, source dict or None, error text). A missing file is no rules; a file
    that does not validate is an error the caller reports, never 'no rules'."""
    path = DATA if path is None else path
    key = str(path)
    try:
        st = path.stat()
        signature = (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_ctime_ns, st.st_size)
    except FileNotFoundError:
        return (), None, ""
    except OSError as exc:
        return (), None, f"cannot read the rule file: {type(exc).__name__}"
    cached = _LOADED.get(key)
    if cached and cached[0] == signature:
        return cached[1]
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        doc = parse(data)
        result = (doc["rules"], doc["source"], "")
    except OSError as exc:
        result = ((), None, f"cannot read the rule file: {type(exc).__name__}")
    except (PatternError, TypeError, RecursionError) as exc:
        result = ((), None, "invalid compiled rule data: " + type(exc).__name__)
    _LOADED[key] = (signature, result)
    return result
