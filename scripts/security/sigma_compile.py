"""Compile Sigma rules into the JSON form jarvis/core/sigma.py evaluates.

    python3 -m scripts.security.sigma_compile SIGMA_CHECKOUT --commit SHA [--out FILE] [--report]

SIGMA_CHECKOUT is a checkout of https://github.com/SigmaHQ/sigma (rules under the
Detection Rule License 1.1). It is data: parsed with yaml.safe_load, never run.
PyYAML is a development-only dependency of this tool; nothing here ships.

A rule is compiled only when every part of it can be evaluated exactly:
  * log source: Windows process creation, Windows registry value set, Linux process creation,
    PowerShell script blocks;
  * fields this program records (jarvis.core.sigma.FIELDS);
  * modifiers contains, startswith, endswith, all, windash, and the `*` wildcard;
  * conditions built from and / or / not, parentheses, and `1 of` / `all of`.
Anything else (regular expressions, keyword lists, aggregations, `?` wildcards,
other fields) leaves the whole rule out, counted by reason in the report. Nothing
is translated approximately.

Kept: status stable or test, level critical or high, with an author (the licence
requires naming one in every alert).
"""
import argparse
import collections
import fnmatch
import json
import re
import sys
from pathlib import Path

import yaml

from jarvis.core import sigma

FOLDERS = {
    "rules/windows/process_creation": sigma.WIN_PROC,
    "rules/windows/registry/registry_set": sigma.WIN_REG,
    "rules/windows/registry/registry_event": sigma.WIN_REG,
    "rules/linux/process_creation": sigma.LINUX_PROC,
    "rules/windows/powershell/powershell_script": sigma.WIN_PS,
}
LOGSOURCE = {
    sigma.WIN_PROC: {("process_creation", "windows")},
    sigma.WIN_REG: {("registry_set", "windows"), ("registry_event", "windows")},
    sigma.LINUX_PROC: {("process_creation", "linux")},
    sigma.WIN_PS: {("ps_script", "windows")},
}
STATUSES = ("stable", "test")
DASHES = ("-", "/", "–", "—", "―")
TID = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)$")


class Unsupported(Exception):
    pass


def segments(value):
    """A Sigma string -> literal segments split at unescaped `*`. `\\\\` is one
    backslash, `\\*` a literal star; a backslash before anything else is itself."""
    out, cur, i = [], [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "\\*?":
            cur.append(value[i + 1])
            i += 2
            continue
        if ch == "?":
            raise Unsupported("single-character wildcard")
        if ch == "*":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    out.append("".join(cur))
    return [s.lower() for s in out]


def windash(value):
    """Every spelling of a parameter dash Windows tools accept."""
    out = []
    for d in DASHES:
        v = re.sub(r"(?:(?<=\s)|^)-", lambda _m, d=d: d, value)
        if v not in out:
            out.append(v)
    return out


def value_test(op, segs):
    """One Sigma value under `op` as (op, segments) with redundant wildcards folded in."""
    if len(segs) > sigma.MAX_SEGMENTS:
        raise Unsupported("too many wildcards in one value")
    at_start, at_end = sigma._ANCHOR[op]
    # A leading or trailing `*` only loosens the anchor.
    while len(segs) > 1 and segs[0] == "":
        segs, at_start = segs[1:], False
    while len(segs) > 1 and segs[-1] == "":
        segs, at_end = segs[:-1], False
    if any(s == "" for s in segs) and len(segs) > 1:
        raise Unsupported("adjacent wildcards")
    op = {(True, True): "eq", (False, False): "contains", (True, False): "startswith", (False, True): "endswith"}[
        (at_start, at_end)]
    return op, segs


def compile_map(raw, fields):
    tests = []
    for key, value in raw.items():
        name, *mods = str(key).split("|")
        if name not in fields:
            raise Unsupported(f"field {name}")
        every = "all" in mods
        dash = "windash" in mods
        kinds = [m for m in mods if m not in ("all", "windash")]
        if len(kinds) > 1 or (kinds and kinds[0] not in ("contains", "startswith", "endswith")):
            raise Unsupported(f"modifier {'|'.join(mods)}")
        op = kinds[0] if kinds else "eq"
        values = value if isinstance(value, list) else [value]
        if not values:
            raise Unsupported("empty value list")
        if any(v is None for v in values):
            if len(values) != 1 or mods:
                raise Unsupported("null mixed with values")
            tests.append([fields[name], "null", False, []])
            continue
        by_op = collections.OrderedDict()
        for v in values:
            if isinstance(v, bool) or not isinstance(v, (str, int)):
                raise Unsupported("value type")
            for text in (windash(str(v)) if dash else [str(v)]):
                real_op, segs = value_test(op, segments(text))
                by_op.setdefault(real_op, []).append(segs)
        if every and (len(by_op) > 1 or dash):
            # `all` over values that ended up under different operators, or over dash
            # variants (any variant of each value), is not one flat test.
            raise Unsupported("all over mixed forms")
        if every:
            (real_op, segs_list), = by_op.items()
            tests.append([fields[name], real_op, True, segs_list])
        elif len(by_op) == 1:
            (real_op, segs_list), = by_op.items()
            tests.append([fields[name], real_op, False, segs_list])
        else:
            raise Unsupported("values need different operators in one test")
    if not tests:
        raise Unsupported("empty selection")
    return tests


def compile_selection(raw, fields):
    if isinstance(raw, dict):
        return [compile_map(raw, fields)]
    if isinstance(raw, list) and raw and all(isinstance(x, dict) for x in raw):
        return [compile_map(x, fields) for x in raw]
    raise Unsupported("keyword list")


def compile_condition(text, names):
    if not isinstance(text, str):
        raise Unsupported("condition list")
    if "|" in text:
        raise Unsupported("aggregation")
    tokens = re.findall(r"\(|\)|[^\s()]+", text)
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take():
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def pattern(p):
        if p == "them":
            found = [n for n in names if not n.startswith("_")]
        else:
            found = [n for n in names if fnmatch.fnmatchcase(n, p)]
        if not found:
            raise Unsupported("quantifier matches no selection")
        return found

    def atom():
        tok = take() if peek() is not None else None
        if tok is None:
            raise Unsupported("condition ends early")
        if tok == "(":
            node = either()
            if peek() != ")":
                raise Unsupported("unbalanced parenthesis")
            take()
            return node
        if tok in ("1", "all", "any") and peek() == "of":
            take()
            return ["all" if tok == "all" else "any", pattern(take())]
        if tok in names:
            return ["sel", tok]
        raise Unsupported("condition token")

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
    if pos != len(tokens):
        raise Unsupported("condition trailing tokens")
    return node


def compile_rule(doc, category):
    if doc.get("status") not in STATUSES:
        raise Unsupported(f"status {doc.get('status')}")
    if doc.get("level") not in sigma.LEVEL:
        raise Unsupported(f"level {doc.get('level')}")
    source = doc.get("logsource") or {}
    if (source.get("category"), source.get("product")) not in LOGSOURCE[category] or source.get("service"):
        raise Unsupported("log source")
    author = doc.get("author")
    author = ", ".join(str(a) for a in author) if isinstance(author, list) else str(author or "")
    if not author.strip():
        raise Unsupported("no author")
    detection = dict(doc.get("detection") or {})
    condition = detection.pop("condition", None)
    if detection.pop("timeframe", None) is not None:
        raise Unsupported("timeframe")
    fields = dict(sigma.FIELDS[category])
    sels = {str(name): compile_selection(raw, fields) for name, raw in detection.items()}
    if not sels:
        raise Unsupported("no selections")
    tids = sorted({m.group(1).upper() for tag in doc.get("tags") or () if (m := TID.match(str(tag)))})
    return {"id": str(doc["id"]), "title": str(doc["title"])[:200], "level": doc["level"],
            "author": author.strip()[:300], "tids": tids[:16], "cat": category, "sels": sels,
            "cond": compile_condition(condition, list(sels))}


def compile_tree(root, commit):
    rules, skipped, seen = [], collections.Counter(), set()
    for folder, category in FOLDERS.items():
        for path in sorted((Path(root) / folder).rglob("*.yml")):
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8"))
                if not isinstance(doc, dict) or not doc.get("id") or not doc.get("title"):
                    raise Unsupported("not a rule")
                rule = compile_rule(doc, category)
                if rule["id"] in seen:
                    raise Unsupported("duplicate id")
                try:                  # a rule past the evaluator's bounds is left out, not trimmed
                    sigma.parse(json.dumps({"schema": sigma.SCHEMA, "rules": [rule], "source": {
                        "repo": "x", "commit": "x", "license": "x"}}).encode("utf-8"))
                except sigma.SigmaError as exc:
                    raise Unsupported(f"over a bound: {exc}") from None
                seen.add(rule["id"])
                rules.append(rule)
            except Unsupported as exc:
                skipped[str(exc)] += 1
            except (yaml.YAMLError, UnicodeDecodeError):
                skipped["unreadable"] += 1
    doc = {"schema": sigma.SCHEMA,
           "source": {"repo": "https://github.com/SigmaHQ/sigma", "commit": commit,
                      "license": sigma.LICENSE, "license_url": sigma.LICENSE_URL},
           "rules": rules}
    return doc, skipped


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("checkout")
    ap.add_argument("--commit", required=True, help="the Sigma commit the checkout is at")
    ap.add_argument("--out", default=str(sigma.DATA))
    ap.add_argument("--report", action="store_true")
    args = ap.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        ap.error("--commit is a full 40-character commit id")
    doc, skipped = compile_tree(args.checkout, args.commit)
    # ASCII only: some rules look for bidirectional and other control characters, and the
    # repository refuses those characters in tracked files. Escaped, the parsed content is the same.
    data = json.dumps(doc, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    sigma.parse(data)                      # what ships must be what the program accepts
    Path(args.out).write_bytes(data + b"\n")
    by = collections.Counter(r["cat"] for r in doc["rules"])
    print(f"compiled {len(doc['rules'])} rules ({dict(by)}), {len(data)} bytes -> {args.out}")
    print(f"left out {sum(skipped.values())}")
    if args.report:
        for reason, n in skipped.most_common():
            print(f"  {n:5d}  {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
