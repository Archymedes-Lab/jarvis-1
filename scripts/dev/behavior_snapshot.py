"""Freeze-check for refactors: CLI help and every string literal in the package.

Finding titles, details, SQL, config and store-meta keys are all string
literals, so a refactor that is meant to change structure only should leave
this snapshot identical (moving a module changes nothing here; renaming a
finding title does). Take one before, one after, and compare:

    python3 scripts/dev/behavior_snapshot.py /tmp/before
    ...refactor...
    python3 scripts/dev/behavior_snapshot.py /tmp/after --compare /tmp/before

Docstrings are included, so new or edited docstrings show up in the diff;
they are easy to tell apart from behavioural strings when reviewing it.
"""

import argparse
import ast
import collections
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def help_pages():
    sys.path.insert(0, str(ROOT))
    from jarvis.cli import build_parser

    parser = build_parser()
    pages = {"": parser.format_help()}

    def walk(prefix, p):
        for action in p._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, sub in sorted(action.choices.items()):
                    key = f"{prefix} {name}".strip()
                    pages[key] = sub.format_help()
                    walk(key, sub)

    walk("", parser)
    return pages


def string_literals():
    counts = collections.Counter()
    for path in sorted((ROOT / "jarvis").rglob("*")):
        if "__pycache__" in path.parts or path.is_dir():
            continue
        if path.suffix == ".py":
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    counts[node.value] += 1
        else:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            counts[f"<data file> {path.name} {digest}"] += 1
    return counts


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out", type=pathlib.Path)
    ap.add_argument("--compare", type=pathlib.Path, metavar="BEFORE")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    pages, strings = help_pages(), string_literals()
    (args.out / "help.json").write_text(json.dumps(pages, indent=1, sort_keys=True))
    (args.out / "strings.json").write_text(json.dumps(sorted(strings.items()), indent=0))
    print(f"{len(pages)} help pages, {sum(strings.values())} string literals")
    if not args.compare:
        return 0
    before_pages = json.loads((args.compare / "help.json").read_text())
    before = dict(map(tuple, json.loads((args.compare / "strings.json").read_text())))
    changed = 0
    for name in sorted(set(before_pages) | set(pages)):
        if before_pages.get(name) != pages.get(name):
            print(f"help changed: jarvis {name}".rstrip())
            changed += 1
    for text in sorted(set(before) | set(strings)):
        if before.get(text) != strings.get(text):
            print(f"{before.get(text, 0)} -> {strings.get(text, 0)}  {text[:100]!r}")
            changed += 1
    print("identical" if not changed else f"{changed} difference(s)")
    return 1 if changed else 0


if __name__ == "__main__":
    sys.exit(main())
