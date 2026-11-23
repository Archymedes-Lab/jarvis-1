#!/usr/bin/env python3
"""The release content gate: nothing leaves unless policy.json allows it.

    python3 release/gate.py DIR [--previous MANIFEST] [--report FILE]

DIR is a release folder: the published artifacts plus manifest.json,
SHA256SUMS and the signature files. The gate exits non-zero, listing every
problem, unless all of these hold:

  * every file in DIR is a known release file or matches exactly one artifact
    rule (an unknown download is refused, not ignored);
  * every member of every artifact (zip, tar, .deb, NSIS installer) matches
    that rule's allow list and none has a denied suffix or path part
    (source, tests, docs, source maps, keys, lock files);
  * no member is a symlink, hard link, device or absolute/parent path, and only
    the listed members are executable;
  * no file's bytes (binaries included) contain a denied marker: a
    build-machine home path, a private key, a token, a source map reference;
  * no file starts with Python bytecode magic, and no zip archive is hidden
    inside a binary with a denied member (the PyInstaller pattern);
  * manifest.json lists exactly the artifacts, with matching sizes and
    SHA-256, and SHA256SUMS agrees with it;
  * the file count of each artifact grew by no more than the policy allows over
    the previous release (an unexplained jump is how a whole tree slips in).

It runs three times per release (after the CI build, before publishing, and in
the site's deploy job over what is about to go live) and on the owner's
machine against the live site (release/audit.py). Standard library only, so
every one of those places runs the same code.
"""

import argparse
import fnmatch
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY = HERE / "policy.json"
# Release metadata that sits next to the artifacts; checked, not unpacked.
META = {"manifest.json", "SHA256SUMS", "SHA256SUMS.txt", "SHA256SUMS.sig", "allowed_signers",
        "release-report.json", "release-report.md", "sbom.cdx.json",
        # The licence and third-party notices travel beside every artifact, including
        # the Windows .exe, which cannot carry files of its own.
        "LICENSE.txt", "THIRD-PARTY-NOTICES.txt"}
SIGS = re.compile(r"^SHA256SUMS\.[A-Za-z0-9_-]+\.sig$")  # one signature per releaser
MAX_MEMBER = 512 * 1024 * 1024
# Aggregate bytes held for one archive's members (FZ-14), ~2.9x the largest real
# artifact (~89 MiB unpacked server tarball, 2026-11-10). Members past the
# budget are listed as "over-budget" without being read, and refused.
MAX_TOTAL = 256 * 1024 * 1024
CHUNK = 8 * 1024 * 1024
OVERLAP = 4096


def load_policy(path=POLICY, proposals=()):
    """The policy at `path`. `proposals` are changes under review (release/proposals/),
    loaded only by dry runs (release-test/* branches) and never by a tagged build:

      * `artifacts`: new artifact rules (a name that already has a rule is refused);
      * `deny_markers`: a replacement regex for a marker that already exists, by id
        (a marker cannot be added or removed this way).

    Nothing else can be touched: not the suffix, folder or bytecode lists, and not
    the other markers. Each active proposal is recorded in policy["_proposals"] so
    the caller can print it."""
    policy = json.loads(Path(path).read_text())
    policy["_proposals"] = []
    for prop in proposals:
        extra = json.loads(Path(prop).read_text())
        stray = sorted(k for k in extra if k not in ("artifacts", "deny_markers", "marker_exemptions")
                       and not k.startswith("_"))
        if stray:
            raise ValueError(f"{prop}: a proposal may only add artifact rules, replace named markers or add "
                             f"marker exemptions, not {', '.join(stray)}")
        known = {r["name"] for r in policy["artifacts"]}
        for rule in extra.get("artifacts", []):
            if rule["name"] in known:
                raise ValueError(f"{prop}: {rule['name']} already has a rule; a proposal cannot replace it")
            policy["artifacts"].append(rule)
            policy["_proposals"].append(f"{Path(prop).name}: adds artifact rule {rule['name']}")
        for ex in extra.get("marker_exemptions", []):
            policy.setdefault("marker_exemptions", []).append(ex)
            policy["_proposals"].append(f"{Path(prop).name}: exempts {ex['marker']} in {ex['member']} (sha256 pinned)")
        by_id = {m["id"]: i for i, m in enumerate(policy["deny_markers"])}
        for marker in extra.get("deny_markers", []):
            if marker["id"] not in by_id:
                raise ValueError(f"{prop}: marker {marker['id']} does not exist; a proposal cannot add one")
            policy["deny_markers"][by_id[marker["id"]]] = {**policy["deny_markers"][by_id[marker["id"]]], **marker}
            policy["_proposals"].append(f"{Path(prop).name}: REPLACES marker {marker['id']}")
    policy["_markers"] = [(m["id"], re.compile(m["regex"].encode())) for m in policy["deny_markers"]
                          if m["id"] != "python-source-header"]
    policy["_magic"] = [bytes.fromhex(h) for h in policy["deny_bytecode_magic"]]
    policy["_third_party"] = [(t["marker"], t["text"].encode(), tuple(t["members"]))
                              for t in policy.get("third_party_markers", [])]
    return policy


def _exempt(policy, member, marker_id, found):
    """True when `found` is a reviewed upstream build path inside exactly this
    third-party file (policy third_party_markers): the marker, the exact text and
    the member must all match. Never for an artifact-level binary (member None)."""
    if member is None:
        return False
    return any(marker_id == mid and found == text and any(glob_match(member, g) for g in members)
               for mid, text, members in policy.get("_third_party", ()))



def exempt(label, marker_id, data, policy):
    """True when this exact file is exempted from this marker by its SHA-256.

    A `marker_exemptions` entry names a member path, one marker and the SHA-256 of
    the file's bytes; it applies to those bytes only. Stricter than
    `third_party_markers` (which pins the matched text): use it for a vendor's
    signed binary that cannot be altered.
    """
    for ex in policy.get("marker_exemptions", ()):
        member = ex["member"]
        if ex["marker"] == marker_id and (label == member or label.endswith(":" + member)
                                          or label.endswith("/" + member)):
            if hashlib.sha256(data).hexdigest() == ex["sha256"]:
                return True
    return False

def glob_match(path, pattern):
    """fnmatch where * stays inside one path segment and ** spans segments."""
    rx = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            rx += "(?:[^/]+/)*"
            i += 3
        elif pattern[i] == "*":
            rx += "[^/]*"
            i += 1
        else:
            rx += re.escape(pattern[i])
            i += 1
    return re.fullmatch(rx, path) is not None


def rule_for(name, policy):
    hits = [r for r in policy["artifacts"] if fnmatch.fnmatchcase(name, r["name"])]
    return hits[0] if len(hits) == 1 else None


class Member:
    __slots__ = ("path", "data", "mode", "kind")

    def __init__(self, path, data, mode=0o644, kind="file"):
        self.path, self.data, self.mode, self.kind = path, data, mode, kind


def _norm(name):
    name = name.replace("\\", "/")
    while name.startswith("./"):
        name = name[2:]
    return name


def _tar_members(data):
    out, total = [], 0
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for ti in tf.getmembers():
            path = _norm(ti.name)
            if ti.isdir():
                out.append(Member(path.rstrip("/"), b"", ti.mode, "dir"))
            elif ti.isfile():
                if ti.size > MAX_MEMBER:
                    out.append(Member(path, b"", ti.mode, "oversize"))
                    continue
                total += ti.size
                if total > MAX_TOTAL:
                    out.append(Member(path, b"", ti.mode, "over-budget"))
                    continue
                out.append(Member(path, tf.extractfile(ti).read(MAX_MEMBER + 1), ti.mode, "file"))
            else:
                out.append(Member(path, b"", ti.mode, "link" if (ti.issym() or ti.islnk()) else "special"))
    return out


def _zip_members(data):
    out, total = [], 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for zi in zf.infolist():
            path = _norm(zi.filename)
            mode = (zi.external_attr >> 16) & 0o777777
            if zi.is_dir():
                out.append(Member(path.rstrip("/"), b"", mode, "dir"))
            elif (mode & 0o170000) == 0o120000:
                out.append(Member(path, b"", mode, "link"))
            elif zi.file_size > MAX_MEMBER:
                out.append(Member(path, b"", mode, "oversize"))
            elif total + zi.file_size > MAX_TOTAL:
                total += zi.file_size
                out.append(Member(path, b"", mode, "over-budget"))
            else:
                # zipfile stops at the declared size and checks the CRC, so the
                # declared size bounds what is held.
                total += zi.file_size
                out.append(Member(path, zf.read(zi), mode or 0o644, "file"))
    return out


def _ar_members(data):
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("not an ar archive")
    pos, out = 8, {}
    while pos + 60 <= len(data):
        header = data[pos:pos + 60]
        name = header[:16].decode().strip().rstrip("/")
        size = int(header[48:58].decode().strip())
        # A negative size moved pos backwards and looped for ever (FZ-01). A
        # repeated name was overwritten here while dpkg-deb unpacks the first
        # one, so the gate checked a different data.tar than dpkg installs (FZ-02).
        if size < 0 or pos + 60 + size > len(data):
            raise ValueError(f"ar member {name!r}: size {size} is outside the archive")
        if name in out:
            raise ValueError(f"ar member {name!r} appears twice")
        out[name] = data[pos + 60:pos + 60 + size]
        pos += 60 + size + (size % 2)
    return out


def _deb_members(data):
    ar = _ar_members(data)
    out = []
    for name, blob in ar.items():
        if name == "debian-binary":
            continue
        if name.startswith("control.tar"):
            prefix = "DEBIAN/"
        elif name.startswith("data.tar"):
            prefix = ""
        else:
            out.append(Member(name, blob, 0o644, "unknown-ar-member"))
            continue
        if name.endswith((".xz", ".zst")):
            blob = _decompress(name, blob)
        for m in _tar_members(blob):
            if prefix and m.path in ("", "."):
                continue
            m.path = prefix + m.path if prefix else m.path
            out.append(m)
    return out


def _decompress(name, blob):
    if name.endswith(".xz"):
        import lzma
        return lzma.decompress(blob)
    tool = shutil.which("zstd")
    if not tool:
        raise ValueError("zstd member and no zstd tool to open it")
    return subprocess.run([tool, "-dc"], input=blob, capture_output=True, check=True).stdout


def _nsis_members(path):
    tool = shutil.which("7z") or shutil.which("7zz")
    if not tool:
        raise ValueError("an NSIS installer cannot be opened without 7z, so it cannot be checked")
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([tool, "x", "-y", f"-o{tmp}", str(path)], capture_output=True, check=True)
        out = []
        for p in sorted(Path(tmp).rglob("*")):
            rel = p.relative_to(tmp).as_posix()
            if p.is_symlink():
                out.append(Member(rel, b"", 0o777, "link"))
            elif p.is_dir():
                out.append(Member(rel, b"", 0o755, "dir"))
            else:
                out.append(Member(rel, p.read_bytes(), 0o644, "file"))
        return out


def members_of(path, kind):
    data = path.read_bytes()
    if kind == "tar":
        return _tar_members(data)
    if kind == "zip":
        return _zip_members(data)
    if kind == "deb":
        return _deb_members(data)
    if kind == "nsis":
        return _nsis_members(path)
    if kind == "binary":
        return [Member(path.name, data, 0o755, "file")]
    raise ValueError(f"unknown artifact kind {kind!r}")


def marker_texts(data, policy):
    """Every distinct marker match in the bytes, as {marker: [evidence]} (build diagnostics)."""
    found = {}
    for mid, rx in policy["_markers"]:
        texts = sorted({m.group(0) for m in rx.finditer(data)})
        if texts:
            found[mid] = [evidence(mid, t) for t in texts[:20]]
    return found


def scan_bytes(label, data, policy, member=None):
    """Problems found in one file's bytes, whatever the file is. `member` is the
    file's path inside its artifact, for the reviewed third-party exemptions:
    every match is checked, and the first one that is not exempt is reported."""
    problems = []
    for magic in policy["_magic"]:
        if data.startswith(magic):
            problems.append(f"{label}: Python bytecode")
    if data.startswith((b"#!/usr/bin/env python", b"#!/usr/bin/python", b"# -*- coding")):
        problems.append(f"{label}: Python source")
    seen = set()
    for start in range(0, max(len(data), 1), CHUNK):
        window = data[max(0, start - OVERLAP):start + CHUNK]
        for mid, rx in policy["_markers"]:
            if mid in seen:
                continue
            for m in rx.finditer(window):
                if _exempt(policy, member, mid, m.group(0)):
                    continue
                seen.add(mid)
                if exempt(label, mid, data, policy):
                    continue
                problems.append(f"{label}: contains {mid} ({evidence(mid, m.group(0))})")
                break
    # A zip member that is itself an archive: denied members inside it must not
    # hide behind the outer member's allow rule (FZ-11).
    if data.startswith(b"PK\x03\x04"):
        problems += _check_nested_zips(data, label, policy)
    # A zip appended to or embedded in a binary (PyInstaller, a self-extractor).
    if b"PK\x01\x02" in data and not data.startswith(b"PK\x03\x04"):
        problems += [f"{label}: embedded archive member {n}" for n in embedded_zip_names(data)
                     if denied_path(n, policy)]
    return problems


def evidence(marker_id, found):
    """What matched, safe to print in a public CI log: a path is shown up to its
    user name; a key or token never, only its kind, length and first characters."""
    if marker_id.endswith("path") or marker_id == "source-map":
        text = found[:80].decode("ascii", "replace")
        return repr("".join(c if c.isprintable() else "?" for c in text))
    head = found.split(b"-----", 2)[1] if marker_id == "private-key" and b"-----" in found else found[:4]
    return f"{head.decode('ascii', 'replace')}... {len(found)} bytes, redacted"


def _walk_central_directory(data, end, entries, size):
    """Names listed by the central directory of `entries` records and `size` bytes that
    ends at `end`, or None when the bytes there are not a consistent directory."""
    start = end - size
    if entries <= 0 or start < 0 or data[start:start + 4] != b"PK\x01\x02":
        return None
    names, pos = [], start
    for _ in range(entries):
        if data[pos:pos + 4] != b"PK\x01\x02" or pos + 46 > end:
            return None
        n_len = int.from_bytes(data[pos + 28:pos + 30], "little")
        extra = int.from_bytes(data[pos + 30:pos + 32], "little")
        comment = int.from_bytes(data[pos + 32:pos + 34], "little")
        names.append(_norm(data[pos + 46:pos + 46 + n_len].decode("utf-8", "replace")))
        pos += 46 + n_len + extra + comment
    return names if pos == end else None


def embedded_zip_names(data):
    """File names of every real zip archive appended to or embedded in the bytes.

    A real archive has a central directory that is consistent with its
    end-of-directory record. Finding the four bytes `PK\x01\x02` is not enough: a
    Python runtime (python3*.dll) carries those bytes, and the end-record and
    zip64 signatures too, as constants in its built-in zipimport code, and decoding
    what follows them reported garbage as "archive members". The check stays strict
    for what it is for: a zip after or inside a binary (the PyInstaller pattern) is
    found wherever it sits, in the classic layout and in zip64 (whose sizes are in the
    zip64 end record, not the classic one).
    """
    names = []
    pos = data.find(b"PK\x05\x06")
    while pos != -1:
        if pos + 22 <= len(data):
            entries = int.from_bytes(data[pos + 10:pos + 12], "little")
            size = int.from_bytes(data[pos + 12:pos + 16], "little")
            if entries != 0xFFFF and size != 0xFFFFFFFF:
                names += _walk_central_directory(data, pos, entries, size) or []
        pos = data.find(b"PK\x05\x06", pos + 4)
    pos = data.find(b"PK\x06\x06")
    while pos != -1:
        if pos + 56 <= len(data):
            entries = int.from_bytes(data[pos + 32:pos + 40], "little")
            size = int.from_bytes(data[pos + 40:pos + 48], "little")
            names += _walk_central_directory(data, pos, entries, size) or []
        pos = data.find(b"PK\x06\x06", pos + 4)
    return names


def denied_path(path, policy):
    # Windows extracts files case-insensitively and drops trailing dots and
    # spaces from every path segment, so a member spelled `APP/X.PY ` or
    # `app/SRC./main.dll` lands on disk as `app/x.py` / `app/src/main.dll`.
    # Check the canonical form so no spelling slips past the deny list.
    norm = "/".join(seg.rstrip(". ") for seg in path.replace("\\", "/").lower().split("/"))
    parts = norm.split("/")
    if any(norm.endswith(s) for s in policy["deny_suffixes"]):
        return "denied file type"
    if any(p in policy["deny_path_parts"] for p in parts[:-1]):
        return "denied folder"
    if any(fnmatch.fnmatchcase(parts[-1], pat) for pat in policy.get("deny_copyleft_names", [])):
        return "copyleft library requires a separate license and source-obligations review"
    return None


_NESTED_ZIP_DEPTH = 4
_NESTED_ZIP_BYTES = 64 * 1024 * 1024


def _check_nested_zips(data, label, policy, depth=0):
    """Problems in zip archives nested inside an allowed member.

    A denied member (source, key, source map, ...) must not hide inside a zip
    that is itself a member of an allowed artifact. Recursion is bounded by
    depth and decompressed bytes so a zip bomb cannot blow the read budget.
    """
    if depth >= _NESTED_ZIP_DEPTH:
        return []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            total = 0
            out = []
            for zi in zf.infolist():
                npath = _norm(zi.filename)
                if zi.is_dir() or npath.startswith("/") or ".." in npath.split("/"):
                    continue
                if zi.file_size > MAX_MEMBER:
                    out.append(f"{label}:{npath}: oversize nested member")
                    continue
                # Budget on the declared size, before reading (FZ-14).
                total += zi.file_size
                if total > _NESTED_ZIP_BYTES:
                    out.append(f"{label}: nested archive exceeds read budget")
                    return out
                ndata = zf.read(zi)
                nlabel = f"{label}:{npath}"
                why = denied_path(npath, policy)
                if why:
                    out.append(f"{nlabel}: {why}")
                else:
                    out += scan_bytes(nlabel, ndata, policy, member=npath)
                if ndata.startswith(b"PK\x03\x04"):
                    out += _check_nested_zips(ndata, nlabel, policy, depth + 1)
            return out
    except Exception:
        # An unreadable nested archive is refused, not silently passed.
        return [f"{label}: nested archive cannot be checked"]


def check_artifact(path, rule, policy):
    problems, count = [], 0
    try:
        members = members_of(path, rule["kind"])
    except Exception as exc:  # noqa: BLE001 - any unreadable container fails closed
        return [f"{path.name}: cannot be opened for checking ({type(exc).__name__}: {exc})"], 0
    if rule["kind"] == "binary":
        return scan_bytes(path.name, members[0].data, policy), 1
    for m in members:
        label = f"{path.name}:{m.path}"
        if m.path.startswith("/") or ".." in m.path.split("/"):
            problems.append(f"{label}: absolute or parent path")
            continue
        if m.kind == "dir":
            continue
        if m.kind != "file":
            problems.append(f"{label}: {m.kind} is not allowed")
            continue
        count += 1
        why = denied_path(m.path, policy)
        if why:
            problems.append(f"{label}: {why}")
        elif not any(glob_match(m.path, pat) for pat in rule["allow"]):
            problems.append(f"{label}: not in the allow list")
        if m.mode & 0o111 and m.path not in rule.get("executables", []) \
                and not m.path.endswith((".so",)) and ".so." not in m.path:
            problems.append(f"{label}: executable but not listed as one")
        problems += scan_bytes(label, m.data, policy, member=m.path)
    return problems, count


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def check_release(folder, policy, previous=None):
    folder = Path(folder)
    problems, counts = [], {}
    files = sorted(p for p in folder.iterdir() if p.is_file())
    artifacts = []
    for p in files:
        if p.name in META or SIGS.match(p.name):
            continue
        rule = rule_for(p.name, policy)
        if rule is None:
            problems.append(f"{p.name}: no policy rule (or more than one) allows this download")
            continue
        artifacts.append(p.name)
        found, counts[p.name] = check_artifact(p, rule, policy)
        problems += found
    for d in (p for p in folder.iterdir() if p.is_dir()):
        problems.append(f"{d.name}/: folders are not published")
    manifest_path = folder / "manifest.json"
    if not manifest_path.exists():
        problems.append("manifest.json is missing")
    else:
        manifest = json.loads(manifest_path.read_text())
        listed = manifest.get("files") or {}
        if sorted(listed) != sorted(artifacts):
            problems.append(f"manifest lists {sorted(listed)} but the folder holds {sorted(artifacts)}")
        for name in set(listed) & set(artifacts):
            p = folder / name
            if listed[name].get("bytes") != p.stat().st_size or listed[name].get("sha256") != sha256(p):
                problems.append(f"{name}: size or SHA-256 differs from the manifest")
        sums = "".join(f"{listed[k]['sha256']}  {k}\n" for k in listed)
        for s in ("SHA256SUMS", "SHA256SUMS.txt"):
            if (folder / s).exists() and (folder / s).read_text() != sums:
                problems.append(f"{s} does not match the manifest")
        if not (folder / "SHA256SUMS").exists():
            problems.append("SHA256SUMS is missing")
    if previous:
        def unversioned(n):
            return re.sub(r"_\d[\w.]*?_", "_*_", n)
        # Both sides without their version: a versioned name (the .deb) was
        # never compared while only the new side was normalised.
        prev = {unversioned(k): v for k, v in
                (json.loads(Path(previous).read_text()).get("member_counts") or {}).items()}
        growth = policy["max_file_count_growth"]
        explained = {(e["artifact"], e["previous"]): e for e in policy.get("explained_growth", ())}
        for name, n in counts.items():
            key = unversioned(name)
            before = prev.get(key)
            if before and n > before * (1 + growth):
                # An explanation names the artifact, the exact previous count it
                # applies to and the most files it allows: it covers one jump only.
                ex = explained.get((key, before))
                if ex and n <= ex["max"]:
                    continue
                problems.append(f"{name}: {n} files, up from {before} in the previous release "
                                f"(more than {growth:.0%}); explain it in the policy or the build")
    return problems, counts


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("folder")
    ap.add_argument("--policy", default=str(POLICY))
    ap.add_argument("--previous", help="the previous release's manifest.json (member counts)")
    ap.add_argument("--report", help="write a JSON report here")
    args = ap.parse_args()
    policy = load_policy(args.policy)
    problems, counts = check_release(args.folder, policy, args.previous)
    report = {"ok": not problems, "policy_sha256": sha256(args.policy), "member_counts": counts,
              "problems": problems}
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    for p in problems:
        print("REFUSED  " + p)
    print(f"gate: {'PASSED' if not problems else 'FAILED'} "
          f"({len(counts)} artifacts, {sum(counts.values())} files, {len(problems)} problems)")
    sys.exit(0 if not problems else 1)


if __name__ == "__main__":
    main()
