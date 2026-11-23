"""Community detection rules (Sigma), evaluated without a rule language at run time.

Sigma rules (https://github.com/SigmaHQ/sigma, Detection Rule License 1.1) are
compiled ahead of time by scripts/security/sigma_compile.py into a small JSON
form: per rule, named selections of field tests and a boolean condition over
them. This module validates that form and evaluates it. There is no YAML, no
regular expression and no code from the rule at run time: a field test is a
case-insensitive equals / contains / starts-with / ends-with over literal
segments (the `*` wildcard splits a value into segments), so the cost of one
test is linear in the text and a rule cannot stall the matcher.

What is not supported is not translated: a rule that uses a field this program
does not record, a regular expression, a keyword list or an aggregation is left
out by the compiler and counted there. A rule that is present here means what
its Sigma source means, for the fields named in FIELDS.

Content is not authority. A match is a finding for a person to judge; severity
is capped (see LEVEL) and nothing is acted on because a community rule matched.

Licence: every finding built from a rule must name the rule's author (DRL 1.1).
`attribution()` returns the text; callers put it in the finding detail.
"""

import json

from jarvis.core.paths import PACKAGE_DIR

SCHEMA = "argus-sigma/1"
DATA = PACKAGE_DIR / "intel" / "data" / "sigma_rules.json"
LICENSE = "Detection Rule License 1.1"
LICENSE_URL = "https://github.com/SigmaHQ/Detection-Rule-License"

WIN_PROC, WIN_REG, LINUX_PROC, WIN_PS = "win_proc", "win_reg", "linux_proc", "win_ps"
# Sigma field -> the key of the event row this program records, per category.
# A rule naming any other field is not compiled.
FIELDS = {
    WIN_PROC: {"Image": "image", "CommandLine": "cmdline", "ParentImage": "parent",
               "ParentCommandLine": "parent_cmdline", "OriginalFileName": "original_name"},
    WIN_REG: {"TargetObject": "reg_key", "Details": "reg_details", "Image": "image",
              "EventType": "event_type"},
    LINUX_PROC: {"Image": "Image", "CommandLine": "CommandLine", "ParentImage": "ParentImage",
                 "ParentCommandLine": "ParentCommandLine", "User": "User",
                 "CurrentDirectory": "CurrentDirectory"},
    # PowerShell script blocks (event 4104), read by collectors/telemetry/psscript.py.
    WIN_PS: {"ScriptBlockText": "text", "Path": "path"},
}
OPS = ("eq", "contains", "startswith", "endswith", "null")
# Sigma level -> finding severity. Never critical: one community rule is one
# signal, and a critical needs corroboration (ALERT-QUALITY-2026-11-08 rule 4).
# Only high and critical rules are used: medium rules flag single ordinary administrative
# commands (one `whoami`), which this product reports only as a burst (measured against
# the existing discovery tests, 2026-11-10).
LEVEL = {"critical": "high", "high": "medium"}

MAX_BYTES = 8 * 1024 * 1024
MAX_RULES = 6000
MAX_SELECTIONS = 40
MAX_MAPS = 200
MAX_TESTS = 40
MAX_VALUES = 600
MAX_SEGMENTS = 12
MAX_SEGMENT = 600
MAX_DEPTH = 12
MAX_TEXT = 4096              # = techniques.MAX_CMDLINE: read what the built-in rules read
MAX_TEXT_BY_CATEGORY = {WIN_PS: 65536}        # a script block is a whole script, not a command line


class SigmaError(ValueError):
    """The compiled rule file is not in the form this program evaluates."""


class Rule:
    __slots__ = ("id", "title", "level", "severity", "author", "tids", "category", "selections", "condition")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def _str(value, limit, what):
    if not isinstance(value, str) or len(value) > limit:
        raise SigmaError(f"{what} must be text of at most {limit} characters")
    return value


def _condition(node, names, depth=0):
    if depth > MAX_DEPTH or not isinstance(node, list) or not node:
        raise SigmaError("condition is malformed or too deep")
    op = node[0]
    if op == "sel":
        if len(node) != 2 or node[1] not in names:
            raise SigmaError("condition names an unknown selection")
        return ("sel", node[1])
    if op == "not":
        if len(node) != 2:
            raise SigmaError("not takes one operand")
        return ("not", _condition(node[1], names, depth + 1))
    if op in ("and", "or"):
        if len(node) < 3:
            raise SigmaError(f"{op} takes at least two operands")
        return (op,) + tuple(_condition(n, names, depth + 1) for n in node[1:])
    if op in ("any", "all"):
        if len(node) != 2 or not isinstance(node[1], list) or not node[1] \
                or any(n not in names for n in node[1]):
            raise SigmaError("quantifier names an unknown selection")
        return (op, tuple(node[1]))
    raise SigmaError(f"unknown condition operator {str(op)[:20]!r}")


def _selection(raw, fields):
    if not isinstance(raw, list) or not 0 < len(raw) <= MAX_MAPS:
        raise SigmaError("a selection is a non-empty list of maps")
    maps = []
    for m in raw:
        if not isinstance(m, list) or not 0 < len(m) <= MAX_TESTS:
            raise SigmaError("a selection map is a non-empty list of tests")
        tests = []
        for t in m:
            if not (isinstance(t, list) and len(t) == 4):
                raise SigmaError("a test is [field, op, all, values]")
            field, op, every, values = t
            if field not in fields.values() or op not in OPS or not isinstance(every, bool):
                raise SigmaError("a test names an unknown field or operator")
            if op == "null":
                if values != []:
                    raise SigmaError("a null test takes no values")
                tests.append((field, op, False, ()))
                continue
            if not isinstance(values, list) or not 0 < len(values) <= MAX_VALUES:
                raise SigmaError("a test needs 1..%d values" % MAX_VALUES)
            parsed = []
            for v in values:
                if not isinstance(v, list) or not 0 < len(v) <= MAX_SEGMENTS:
                    raise SigmaError("a value is a list of literal segments")
                segs = tuple(_str(s, MAX_SEGMENT, "segment") for s in v)
                if any(s != s.lower() for s in segs):
                    raise SigmaError("segments are stored lower-case")
                parsed.append(segs)
            tests.append((field, op, every, tuple(parsed)))
        maps.append(tuple(tests))
    return tuple(maps)


def parse(data):
    """Validate compiled rule bytes. -> {"source": {...}, "rules": {category: (Rule, ...)}}"""
    if not isinstance(data, (bytes, bytearray)) or not data or len(data) > MAX_BYTES:
        raise SigmaError(f"the rule file is 1..{MAX_BYTES} bytes")
    try:
        doc = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise SigmaError("the rule file is UTF-8 JSON") from None
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise SigmaError(f"this program reads {SCHEMA}")
    source = doc.get("source")
    if not isinstance(source, dict) or not all(isinstance(source.get(k), str) and source.get(k)
                                               for k in ("repo", "commit", "license")):
        raise SigmaError("the rule file must say where its rules come from and their licence")
    raw_rules = doc.get("rules")
    if not isinstance(raw_rules, list) or len(raw_rules) > MAX_RULES:
        raise SigmaError(f"at most {MAX_RULES} rules")
    out, seen = {c: [] for c in FIELDS}, set()
    for r in raw_rules:
        if not isinstance(r, dict):
            raise SigmaError("a rule is an object")
        rid = _str(r.get("id"), 64, "rule id")
        if not rid or rid in seen:
            raise SigmaError("rule ids are unique and not empty")
        seen.add(rid)
        category = r.get("cat")
        if category not in FIELDS:
            raise SigmaError("unknown rule category")
        level = r.get("level")
        if level not in LEVEL:
            raise SigmaError("unknown rule level")
        # DRL 1.1: a message based on a match names the author. A rule without one is refused
        # here so that no finding can be built that would have to leave it out.
        author = _str(r.get("author"), 300, "author").strip()
        if not author:
            raise SigmaError(f"rule {rid} names no author")
        tids = r.get("tids")
        if not isinstance(tids, list) or len(tids) > 16 or not all(isinstance(t, str) and len(t) <= 9 for t in tids):
            raise SigmaError("tids is a short list of technique ids")
        sels = r.get("sels")
        if not isinstance(sels, dict) or not 0 < len(sels) <= MAX_SELECTIONS:
            raise SigmaError("a rule has 1..%d selections" % MAX_SELECTIONS)
        selections = {_str(n, 80, "selection name"): _selection(s, FIELDS[category]) for n, s in sels.items()}
        out[category].append(Rule(id=rid, title=_str(r.get("title"), 200, "title"), level=level,
                                  severity=LEVEL[level], author=author, tids=tuple(tids), category=category,
                                  selections=selections, condition=_condition(r.get("cond"), selections)))
    return {"source": {k: source[k] for k in ("repo", "commit", "license")},
            "rules": {c: tuple(v) for c, v in out.items()}}


def _segments(text, segs, at_start, at_end):
    """`segs` occur in `text` in order; the first anchored at the start and the
    last at the end when asked. One left-to-right pass."""
    first, last = segs[0], segs[-1]
    if len(segs) == 1:
        if at_start and at_end:
            return text == first
        if at_start:
            return text.startswith(first)
        if at_end:
            return text.endswith(first)
        return first in text
    pos = 0
    if at_start:
        if not text.startswith(first):
            return False
        pos = len(first)
        middle = segs[1:-1]
    else:
        middle = segs[:-1]
    for seg in middle:
        found = text.find(seg, pos)
        if found < 0:
            return False
        pos = found + len(seg)
    if at_end:
        return len(text) - len(last) >= pos and text.endswith(last)
    return text.find(last, pos) >= 0


_ANCHOR = {"eq": (True, True), "contains": (False, False), "startswith": (True, False), "endswith": (False, True)}


def _test(test, event):
    field, op, every, values = test
    text = event.get(field) or ""
    if op == "null":
        return not text
    at_start, at_end = _ANCHOR[op]
    if every:
        return all(_segments(text, v, at_start, at_end) for v in values)
    return any(_segments(text, v, at_start, at_end) for v in values)


def _selected(maps, event):
    return any(all(_test(t, event) for t in m) for m in maps)


def _holds(node, rule, event, memo):
    op = node[0]
    if op == "sel":
        name = node[1]
        if name not in memo:
            memo[name] = _selected(rule.selections[name], event)
        return memo[name]
    if op == "not":
        return not _holds(node[1], rule, event, memo)
    if op == "and":
        return all(_holds(n, rule, event, memo) for n in node[1:])
    if op == "or":
        return any(_holds(n, rule, event, memo) for n in node[1:])
    names = node[1]
    if op == "any":
        return any(_holds(("sel", n), rule, event, memo) for n in names)
    return all(_holds(("sel", n), rule, event, memo) for n in names)


def prepare(category, row):
    """The lower-cased, length-capped fields of one event row that rules of
    `category` may test. Anything else in the row is not visible to a rule."""
    cap = MAX_TEXT_BY_CATEGORY.get(category, MAX_TEXT)
    return {key: str(row.get(key) or "")[:cap].lower() for key in FIELDS[category].values()}


def match(rules, event):
    """Rules of one category that `event` (from prepare()) satisfies."""
    return [r for r in rules if _holds(r.condition, r, event, {})]


def attribution(rule):
    """The credit a finding must carry (DRL 1.1): author, rule id, licence."""
    return f"Sigma rule {rule.id} by {rule.author} ({LICENSE})"


_LOADED = {}


def load(path=None):
    """The compiled rules shipped with this program, parsed once.

    A missing file means no community rules (an install without them); a file
    that does not validate is an error the caller reports: it is never read as
    'no rules'. -> (rules by category, source dict or None, error text or '')"""
    path = DATA if path is None else path
    key = str(path)
    if key not in _LOADED:
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            _LOADED[key] = ({c: () for c in FIELDS}, None, "")
        except OSError as exc:
            _LOADED[key] = ({c: () for c in FIELDS}, None, f"cannot read the rule file: {type(exc).__name__}")
        else:
            try:
                doc = parse(data)
                _LOADED[key] = (doc["rules"], doc["source"], "")
            except SigmaError as exc:
                _LOADED[key] = ({c: () for c in FIELDS}, None, str(exc))
    return _LOADED[key]


# ── candidate index ─────────────────────────────────────────────────────────
# Evaluating every rule on every event costs milliseconds per event (measured:
# 2.8 ms for 841 rules). Almost every rule needs some literal to be present, so
# one substring check per distinct literal finds the few rules worth evaluating.
# The literal is a *necessary* condition derived from the rule; a rule for which
# none can be derived is always evaluated. The index never decides a match.

def _test_needles(test):
    _field, op, every, values = test
    if op == "null":
        return None
    longest = [max(v, key=len) for v in values]
    if any(not s for s in longest):
        return None
    if every:
        return frozenset([max(longest, key=len)])
    return frozenset(longest)


def _best(options):
    known = [o for o in options if o is not None]
    if not known:
        return None
    return min(known, key=lambda o: (len(o), -min(len(s) for s in o)))


def _union(options):
    if any(o is None for o in options):
        return None
    out = frozenset()
    for o in options:
        out |= o
    return out


def _needles(node, rule):
    op = node[0]
    if op == "sel":
        return _union([_best([_test_needles(t) for t in m]) for m in rule.selections[node[1]]])
    if op == "not":
        return None
    if op == "and":
        return _best([_needles(n, rule) for n in node[1:]])
    if op == "or":
        return _union([_needles(n, rule) for n in node[1:]])
    parts = [_needles(("sel", n), rule) for n in node[1]]
    return _union(parts) if op == "any" else _best(parts)


class Index:
    """Rules of one category, with the literals that make each worth evaluating."""

    def __init__(self, rules):
        self.rules = tuple(rules)
        self.always = []
        self.by_needle = {}
        for rule in self.rules:
            needles = _needles(rule.condition, rule)
            if needles is None:
                self.always.append(rule)
            else:
                for n in needles:
                    self.by_needle.setdefault(n, []).append(rule)

    def match(self, event):
        hay = "\x00".join(event.values())
        seen, out = set(), []
        for needle, rules in self.by_needle.items():
            if needle in hay:
                for rule in rules:
                    if rule.id not in seen:
                        seen.add(rule.id)
                        if _holds(rule.condition, rule, event, {}):
                            out.append(rule)
        for rule in self.always:
            if _holds(rule.condition, rule, event, {}):
                out.append(rule)
        return out


_INDEXES = {}


def index(category, path=None):
    """(Index for `category`, error text). Built once per rule file."""
    rules, _source, error = load(path)
    key = (str(DATA if path is None else path), category)
    if key not in _INDEXES:
        _INDEXES[key] = Index(rules[category])
    return _INDEXES[key], error
