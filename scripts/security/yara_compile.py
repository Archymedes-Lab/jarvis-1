"""Compile a strict subset of YARA rules into the JSON form jarvis/core/patterns.py evaluates.

    python3 -m scripts.security.yara_compile SIGNATURE_BASE_CHECKOUT --commit SHA [--out FILE] [--report]

The input is a checkout of https://github.com/Neo23x0/signature-base (Detection Rule
License 1.1 unless a rule says otherwise). It is data: read as text, never compiled by
a YARA engine and never run. Nothing here ships.

A rule is compiled only when all of it can be evaluated exactly by literal search:
  * strings: text strings with ascii / wide / nocase / fullword, and hex strings made of
    plain bytes (no wildcards, jumps or alternatives). No regular expressions.
  * condition: and / or / not, parentheses, a string identifier, `N of them`,
    `all|any of them`, `N of ($a*, $b)`, `filesize <|>|<=|>= N[KB|MB]`, and
    `uint16|uint32|uint16be|uint32be(OFFSET) == VALUE`.
Anything else (modules such as pe. or math., counts, offsets, `at`, `in`, other rules,
xor or base64 strings) leaves the whole rule out, counted by reason. Nothing is
approximated.

Kept: rules under DRL 1.1 (a rule naming another licence is left out), with an author
(the licence requires naming one in every alert) and a score of at least MIN_SCORE.
"""
import argparse
import collections
import json
import re
import subprocess
import sys
from pathlib import Path

from jarvis.core import patterns

MIN_SCORE = 75
RULE_HEAD = re.compile(r"^[ \t]*((?:private|global)\s+)*rule\s+([A-Za-z_]\w*)\s*(?::[^{\n]*)?\{?\s*$", re.M)
SECTION = re.compile(r"^[ \t]*(meta|strings|condition)[ \t]*:[ \t]*(.*)$")
META = re.compile(r'^\s*(\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+)|(true|false))\s*$')
STRING = re.compile(r'^\s*(\$\w*)\s*=\s*(.*)$')
TEXT = re.compile(r'^"((?:[^"\\]|\\.)*)"\s*(.*)$')
HEX = re.compile(r'^\{([^}]*)\}\s*(.*)$')
SIZE_UNIT = {"": 1, "KB": 1024, "MB": 1024 * 1024}
ESCAPES = {"n": b"\n", "t": b"\t", "r": b"\r", "\\": b"\\", '"': b'"'}


class Unsupported(Exception):
    pass


def strip_comments(text):
    """Remove // and /* */ comments that are outside string literals and regexes."""
    out, i, n = [], 0, len(text)
    quote = None
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote or ch == "\n":
                quote = None
            i += 1
            continue
        if ch == '"':
            quote = '"'
            out.append(ch)
        elif ch == "/" and text[i + 1:i + 2] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif ch == "/" and text[i + 1:i + 2] == "*":
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def unescape(raw):
    out, i = bytearray(), 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\":
            nxt = raw[i + 1:i + 2]
            if nxt == "x":
                out += bytes([int(raw[i + 2:i + 4], 16)])
                i += 4
                continue
            if nxt in ESCAPES:
                out += ESCAPES[nxt]
                i += 2
                continue
            raise Unsupported("string escape")
        try:
            out += ch.encode("latin-1")
        except UnicodeEncodeError:
            raise Unsupported("non-latin string") from None
        i += 1
    return bytes(out)


def compile_string(value):
    """-> {"b": hex, "nocase", "fullword", "wide", "ascii"}"""
    value = value.strip()
    m = TEXT.match(value)
    if m:
        try:
            data = unescape(m.group(1))
        except ValueError:
            raise Unsupported("string escape") from None
        mods = m.group(2).split()
        if set(mods) - {"ascii", "wide", "nocase", "fullword"}:
            raise Unsupported("string modifier " + " ".join(sorted(set(mods) - {"ascii", "wide", "nocase", "fullword"})))
        wide = "wide" in mods
        ascii_ = "ascii" in mods or not wide
        nocase = "nocase" in mods
        if nocase:
            data = data.lower()
    else:
        m = HEX.match(value)
        if not m:
            raise Unsupported("regular expression" if value.startswith("/") else "string form")
        body = re.sub(r"\s+", "", m.group(1))
        if m.group(2).strip():
            raise Unsupported("hex string modifier")
        if not re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", body):
            raise Unsupported("hex wildcard or jump")
        data, wide, ascii_, nocase, mods = bytes.fromhex(body), False, True, False, ()
    if len(data) < patterns.MIN_PATTERN:
        raise Unsupported("string too short to search for")
    if len(data) > patterns.MAX_PATTERN:
        raise Unsupported("string too long")
    return {"b": data.hex(), "nocase": nocase, "fullword": "fullword" in mods, "wide": wide, "ascii": ascii_}


TOKEN = re.compile(r"\s*(\(|\)|,|==|<=|>=|<|>|\$\w*\*?|0x[0-9A-Fa-f]+|\d+(?:KB|MB)?|[A-Za-z_]\w*)")


def tokens(text):
    out, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m:
            raise Unsupported("condition syntax")
        out.append(m.group(1))
        pos = m.end()
    return out


def compile_condition(text, names):
    toks = tokens(text)
    pos = 0

    def peek(k=0):
        return toks[pos + k] if pos + k < len(toks) else None

    def take():
        nonlocal pos
        if pos >= len(toks):
            raise Unsupported("condition ends early")
        pos += 1
        return toks[pos - 1]

    def number(tok):
        m = re.fullmatch(r"(\d+)(KB|MB)?", tok or "")
        if m:
            return int(m.group(1)) * SIZE_UNIT[m.group(2) or ""]
        if tok and re.fullmatch(r"0x[0-9A-Fa-f]+", tok):
            return int(tok, 16)
        raise Unsupported("condition number")

    def string_set():
        if peek() == "them":
            take()
            found = list(names)
        else:
            if take() != "(":
                raise Unsupported("condition set")
            found = []
            while True:
                tok = take()
                if tok is None or not tok.startswith("$"):
                    raise Unsupported("condition set")
                if tok.endswith("*"):
                    found += [n for n in names if n.startswith(tok[:-1])]
                elif tok in names:
                    found.append(tok)
                else:
                    raise Unsupported("unknown string in set")
                tok = take()
                if tok == ")":
                    break
                if tok != ",":
                    raise Unsupported("condition set")
        found = list(dict.fromkeys(found))
        if not found:
            raise Unsupported("empty string set")
        return found

    def atom():
        tok = take()
        if tok is None:
            raise Unsupported("condition ends early")
        if tok == "(":
            node = either()
            if take() != ")":
                raise Unsupported("unbalanced parenthesis")
            return node
        if tok in ("all", "any") and peek() == "of":
            take()
            return ["of", tok, string_set()]
        if re.fullmatch(r"\d+", tok) and peek() == "of":
            take()
            count = int(tok)
            found = string_set()
            if not 0 < count <= len(found):
                raise Unsupported("count larger than the set")
            return ["of", count, found]
        if tok == "filesize":
            op = take()
            if op not in ("<", ">", "<=", ">="):
                raise Unsupported("filesize comparison")
            return ["size", op, number(take())]
        if tok in ("uint16", "uint32", "uint16be", "uint32be"):
            if take() != "(":
                raise Unsupported("uint form")
            offset = number(take())
            if take() != ")" or take() != "==":
                raise Unsupported("uint form")
            width = 2 if "16" in tok else 4
            value = number(take())
            if value >= 1 << (8 * width) or offset > patterns.MAX_OFFSET:
                raise Unsupported("uint range")
            return ["bytes", offset, value.to_bytes(width, "big" if tok.endswith("be") else "little").hex()]
        if tok.startswith("$") and not tok.endswith("*"):
            if tok not in names:
                raise Unsupported("unknown string")
            if peek() in ("at", "in"):
                raise Unsupported("string position")
            return ["str", tok]
        raise Unsupported("condition term " + re.sub(r"\d+", "N", tok)[:24])

    def negation():
        if peek() == "not":
            take()
            return ["not", negation()]
        return atom()

    def both():
        parts = [negation()]
        while peek() == "and":
            take()
            parts.append(negation())
        return parts[0] if len(parts) == 1 else ["and"] + parts

    def either():
        parts = [both()]
        while peek() == "or":
            take()
            parts.append(both())
        return parts[0] if len(parts) == 1 else ["or"] + parts

    node = either()
    if pos != len(toks):
        raise Unsupported("condition trailing tokens")
    return node


def split_rules(text):
    """[(name, body text)] for every rule in one file (comments already stripped)."""
    heads = list(RULE_HEAD.finditer(text))
    return [(m.group(2), text[m.end():heads[i + 1].start() if i + 1 < len(heads) else len(text)], bool(m.group(1)))
            for i, m in enumerate(heads)]


def compile_rule(name, body, modified=False):
    if modified:
        raise Unsupported("private or global rule")
    sections = {"meta": [], "strings": [], "condition": []}
    current = None
    for line in body.splitlines():
        m = SECTION.match(line)
        if m:
            current = m.group(1)
            line = m.group(2)
        if current and line.strip():
            sections[current].append(line)
    meta = {}
    for line in sections["meta"]:
        m = META.match(line)
        if m:
            meta[m.group(1).lower()] = m.group(2) if m.group(2) is not None else (m.group(3) or m.group(4))
    licence = (meta.get("license") or "").lower()
    if licence and licence not in {"detection rule license 1.1", "drl-1.1", "drl 1.1"}:
        raise Unsupported("rule under another licence")
    author = (meta.get("author") or "").strip()
    if not author:
        raise Unsupported("no author")
    try:
        score = int(meta.get("score") or 0)
    except ValueError:
        score = 0
    if score < MIN_SCORE:
        raise Unsupported(f"score below {MIN_SCORE}")
    strings = {}
    for line in sections["strings"]:
        m = STRING.match(line)
        if not m:
            raise Unsupported("string line form")
        if m.group(1) == "$" or m.group(1) in strings:
            raise Unsupported("anonymous or repeated string")
        strings[m.group(1)] = compile_string(m.group(2))
    if not strings:
        raise Unsupported("no strings")
    cond_text = " ".join(sections["condition"]).strip()
    if cond_text.endswith("}"):
        cond_text = cond_text[:-1].strip()
    if not cond_text:
        raise Unsupported("no condition")
    return {"id": name, "title": (meta.get("description") or name)[:200], "author": author[:300],
            "ref": (meta.get("reference") or "")[:300], "score": min(score, 100), "strings": strings,
            "cond": compile_condition(cond_text, list(strings))}


def compile_tree(root, commit):
    rules, skipped, seen = [], collections.Counter(), set()
    for path in sorted((Path(root) / "yara").glob("*.yar*")):
        try:
            text = strip_comments(path.read_text(encoding="utf-8", errors="strict"))
        except (UnicodeDecodeError, OSError):
            skipped["unreadable file"] += 1
            continue
        if any("global" in (m.group(1) or "").split() for m in RULE_HEAD.finditer(text)):
            skipped["file contains global rule"] += len(split_rules(text))
            continue
        for name, body, modified in split_rules(text):
            try:
                rule = compile_rule(name, body, modified)
                if rule["id"] in seen:
                    raise Unsupported("duplicate name")
                try:
                    patterns.parse(json.dumps({"schema": patterns.SCHEMA, "rules": [rule], "source": {
                        "repo": "x", "commit": "x", "license": "x"}}).encode("utf-8"))
                except patterns.PatternError as exc:
                    raise Unsupported(f"over a bound: {exc}") from None
                seen.add(rule["id"])
                rules.append(rule)
            except Unsupported as exc:
                skipped[str(exc)] += 1
    doc = {"schema": patterns.SCHEMA,
           "source": {"repo": "https://github.com/Neo23x0/signature-base", "commit": commit,
                      "license": patterns.LICENSE, "license_url": patterns.LICENSE_URL},
           "rules": rules}
    return doc, skipped


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("checkout")
    ap.add_argument("--commit", required=True)
    ap.add_argument("--out", default=str(patterns.DATA))
    ap.add_argument("--report", action="store_true")
    args = ap.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        ap.error("--commit is a full 40-character commit id")
    actual = subprocess.check_output(["git", "-C", args.checkout, "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", args.checkout, "status", "--porcelain", "--", "yara", "LICENSE"], text=True)
    if actual != args.commit or dirty:
        ap.error("checkout must be clean and match --commit")
    doc, skipped = compile_tree(args.checkout, args.commit)
    data = json.dumps(doc, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    patterns.parse(data)
    Path(args.out).write_bytes(data + b"\n")
    print(f"compiled {len(doc['rules'])} rules, {len(data)} bytes -> {args.out}")
    print(f"left out {sum(skipped.values())}")
    if args.report:
        for reason, n in skipped.most_common(30):
            print(f"  {n:5d}  {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
