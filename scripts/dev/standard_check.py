#!/usr/bin/env python3
"""Check this repository against the machine-verifiable rules of the
Archymedes Security Engineering Standard (docs/security/ARCHYMEDES-SECURITY-STANDARD.md, §23).

    python3 scripts/dev/standard_check.py [--root DIR] [--json]

Checks (standard requirement in brackets):
  SC-1   every workflow has a top-level `permissions:` block, never write-all   [SC-1]
  SC-4   every remote `uses:` is pinned to a full 40-hex commit SHA            [SC-4]
  SC-5   no `pull_request_target` trigger                                       [SC-5]
  SC-6   `actions/checkout` sets persist-credentials: false (or `# ases: push`) [SC-6]
  SC-7   no untrusted event text interpolated inside a `run:` script           [SC-7]
  SC-10  no private-key material or live-looking tokens in tracked files        [SEC-1]
  SC-20  lockfiles beside package manifests; release requirements hash-pinned   [SUP-1]

A finding is waived only by an entry in docs/security/exceptions.md naming the
check id and the path (`SC-4 .github/workflows/x.yml`), with an expiry date in
the future (`expires: YYYY-MM-DD`). Expired waivers are findings themselves.
Standard library only; exits 1 on any unwaived finding.
"""

import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40}$")
# Untrusted, attacker-controllable event fields (GitHub's script-injection list).
UNTRUSTED = re.compile(
    r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|discussion|"
    r"head_commit|commits|pages)[^}]*\.(title|body|message|label|name|email|ref|head_ref|default_branch|page_name)"
    r"|github\.head_ref|github\.event\.workflow_run\.head_branch)[^}]*\}\}")
SECRET_PATTERNS = [
    ("private-key", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----\r?\n(?:[A-Za-z0-9-]+: [^\n]*\r?\n)*\r?\n?"
                               rb"[A-Za-z0-9+/=]{64}")),
    ("github-token", re.compile(rb"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("aws-access-key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(rb"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("npm-token", re.compile(rb"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi-token", re.compile(rb"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}")),
    ("anthropic-key", re.compile(rb"\bsk-ant-[A-Za-z0-9_-]{40,}")),
    ("openai-key", re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9]{40,}")),
]
# Documentation and fixtures that describe secret formats on purpose.
SECRET_SCAN_SKIP = ("tests/", "docs/")
LOCKS = {"package.json": ("bun.lock", "bun.lockb", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"),
         "Cargo.toml": ("Cargo.lock",)}


def tracked(root):
    out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True).stdout
    return [p for p in out.decode().split("\0") if p]


def strip_comment(line):
    return line.split(" #", 1)[0] if not line.lstrip().startswith("#") else ""


def check_workflow(rel, text):
    findings = []
    lines = text.splitlines()
    top_perm = any(re.match(r"^permissions:", ln) for ln in lines)
    if not top_perm:
        findings.append(("SC-1", rel, "no top-level permissions: block"))
    for i, ln in enumerate(lines, 1):
        code = strip_comment(ln)
        if re.match(r"^permissions:\s*write-all", code) or re.match(r"^\s+permissions:\s*write-all", code):
            findings.append(("SC-1", f"{rel}:{i}", "permissions: write-all"))
        m = re.match(r"^\s*-?\s*uses:\s*([^\s#]+)", code)
        if m:
            ref = m.group(1).strip("'\"")
            if not ref.startswith(("./", "docker://")):
                at = ref.rsplit("@", 1)
                if len(at) != 2 or not SHA.match(at[1]):
                    findings.append(("SC-4", f"{rel}:{i}", f"{ref} is not pinned to a commit SHA"))
        if re.search(r"\bpull_request_target\b", code):
            findings.append(("SC-5", f"{rel}:{i}", "pull_request_target trigger"))
    # checkout steps: look ahead within the step for persist-credentials: false
    for i, ln in enumerate(lines):
        if re.search(r"uses:\s*actions/checkout@", ln):
            indent = len(ln) - len(ln.lstrip(" -"))
            step = [ln]
            for nxt in lines[i + 1:]:
                if nxt.strip() and (len(nxt) - len(nxt.lstrip(" "))) < indent:
                    break
                if re.match(r"^\s*-\s", nxt) and (len(nxt) - len(nxt.lstrip(" "))) <= indent - 2:
                    break
                step.append(nxt)
            body = "\n".join(step)
            # A justification comment may sit on the lines directly above the step.
            above = []
            for prev in reversed(lines[:i]):
                if not prev.strip().startswith("#"):
                    break
                above.append(prev)
            if not re.search(r"persist-credentials:\s*false", body) and "ases: push" not in body + "".join(above):
                findings.append(("SC-6", f"{rel}:{i + 1}", "checkout keeps credentials (set persist-credentials: false)"))
    # run: blocks with untrusted interpolation. A one-line `run: cmd` ends on its
    # line; a block scalar (`run: |`) holds the lines indented past the `run` key.
    in_run, key_col = False, 0
    for i, ln in enumerate(lines, 1):
        m = re.match(r"^(\s*(?:-\s*)?)run:\s*(.*)$", ln)
        if m:
            value = m.group(2).strip()
            if UNTRUSTED.search(value):
                findings.append(("SC-7", f"{rel}:{i}", "untrusted event text interpolated in run:"))
            in_run, key_col = value in ("|", ">", "|-", ">-", "|+", ">+"), len(m.group(1))
            continue
        if in_run:
            if ln.strip() and (len(ln) - len(ln.lstrip())) <= key_col:
                in_run = False
            elif UNTRUSTED.search(ln):
                findings.append(("SC-7", f"{rel}:{i}", "untrusted event text interpolated in run:"))
    return findings


def check_secrets(root, files):
    findings = []
    for rel in files:
        if rel.startswith(SECRET_SCAN_SKIP):
            continue
        p = root / rel
        try:
            if p.is_symlink() or not p.is_file() or p.stat().st_size > 5_000_000:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        for name, rx in SECRET_PATTERNS:
            m = rx.search(data)
            if m:
                line = data[:m.start()].count(b"\n") + 1
                findings.append(("SC-10", f"{rel}:{line}", f"looks like a {name}"))
    return findings


def check_locks(root, files):
    findings = []
    fileset = set(files)
    for rel in files:
        name = rel.rsplit("/", 1)[-1]
        if name not in LOCKS or "/node_modules/" in f"/{rel}":
            continue
        folder = rel[: -len(name)]
        if name == "Cargo.toml" and _in_cargo_workspace(root, folder, fileset):
            continue
        if not any(folder + lock in fileset for lock in LOCKS[name]):
            findings.append(("SC-20", rel, f"no lockfile beside {name}"))
    for rel in files:
        if re.match(r"^release/requirements[^/]*\.txt$", rel):
            for i, ln in enumerate((root / rel).read_text().splitlines(), 1):
                s = ln.strip()
                if not s or s.startswith(("#", "-r ", "--")) or s.startswith("--hash"):
                    continue
                if re.match(r"^[A-Za-z0-9_.\[\]-]+==", s):
                    block = _requirement_block((root / rel).read_text().splitlines(), i - 1)
                    if "--hash=sha256:" not in block:
                        findings.append(("SC-20", f"{rel}:{i}", "requirement without --hash"))
                elif not s.startswith("\\"):
                    findings.append(("SC-20", f"{rel}:{i}", "requirement not pinned with =="))
    return findings


def _requirement_block(lines, idx):
    block = lines[idx]
    j = idx
    while block.rstrip().endswith("\\") and j + 1 < len(lines):
        j += 1
        block += lines[j]
    return block


def _in_cargo_workspace(root, folder, fileset):
    parts = folder.rstrip("/").split("/") if folder else []
    for k in range(len(parts) - 1, -1, -1):
        parent = "/".join(parts[:k])
        prefix = parent + "/" if parent else ""
        manifest = prefix + "Cargo.toml"
        if manifest in fileset and "[workspace]" in (root / manifest).read_text(errors="replace"):
            return prefix + "Cargo.lock" in fileset
    return False


def waivers(root, today):
    path = root / "docs" / "security" / "exceptions.md"
    active, expired = set(), []
    if not path.exists():
        return active, expired
    for ln in path.read_text().splitlines():
        m = re.search(r"\b(SC-\d+)\s+(\S+).*expires:\s*(\d{4}-\d{2}-\d{2})", ln)
        if not m:
            continue
        key = (m.group(1), m.group(2))
        if datetime.date.fromisoformat(m.group(3)) >= today:
            active.add(key)
        else:
            expired.append(("EXC", f"{m.group(1)} {m.group(2)}", f"waiver expired {m.group(3)}"))
    return active, expired


def run(root, today=None):
    root = Path(root)
    files = tracked(root)
    findings = []
    for rel in files:
        if re.match(r"^\.github/workflows/[^/]+\.ya?ml$", rel):
            findings += check_workflow(rel, (root / rel).read_text())
    findings += check_secrets(root, files)
    findings += check_locks(root, files)
    active, expired = waivers(root, today or datetime.date.today())
    kept = [f for f in findings if (f[0], f[1].split(":")[0]) not in active]
    return kept + expired


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[2]))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    found = run(args.root)
    if args.json:
        print(json.dumps([{"check": c, "where": w, "what": m} for c, w, m in found], indent=1))
    else:
        for c, w, m in found:
            print(f"{c:6} {w}: {m}")
        print(f"standard_check: {'PASSED' if not found else 'FAILED'} ({len(found)} findings)")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
