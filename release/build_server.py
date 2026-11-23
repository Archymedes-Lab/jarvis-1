#!/usr/bin/env python3
"""Build the Argus server edition as a native program: no source, no bytecode.

    python3 release/build_server.py --version V --out DIR [--ref HEAD] [--jobs 2]

Runs in CI (.github/workflows/release.yml) inside the pinned manylinux_2_28
image, so the program needs glibc 2.28 or newer (RHEL 8+, Debian 10+, Ubuntu
20.04+). Steps:

  1. export the commit and rename jarvis -> argus (release/rename.py);
  2. compile the package and release/launcher.py with Nuitka into a standalone
     program, bin/argus-server, plus the shared libraries it needs and the
     package's data files (web pages, rules data); no .py or .pyc is written
     to the output, and the Windows payloads are left out;
  3. pack argus-server-linux-x86_64.tar.gz and argus-server_<ver>_amd64.deb
     with fixed timestamps and root ownership;
  4. run the content gate over the result (release/gate.py) and refuse to
     finish on any problem.

The Nuitka compilation report (every module and file that went in, with the
build paths) is written next to the packages as nuitka-report.xml: a CI
artifact for review, never published.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import gate  # noqa: E402
import rename  # noqa: E402

EPOCH = 1767225600  # 2026-01-01T00:00:00Z, for reproducible archive entries
DEB_MAINTAINER = "Archymedes <releases@archymedes.xyz>"
DEB_DEPENDS = "systemd, util-linux, passwd, sudo, libc6 (>= 2.28)"
DEB_SUGGESTS = "nftables, curl"
# Package data that ships: everything else in the package (the Windows
# PowerShell payloads, notes) stays out. Patterns are relative to argus/.
DATA_KEEP = ("web/static/**", "web/styles/*.css", "intel/data/*.json", "lab/scenarios/*.json")
# Repository-level files the code reads through REPO_ROOT on a server.
# systemd/service-user.conf is the developer workstation's WSL drop-in (its paths name one
# Windows account); no server reads it, and the content gate refuses its path, so it stays out.
REPO_DATA = ("systemd/capabilities.conf", "systemd/hardening.conf",
             "systemd/journald-sysmon.conf", "systemd/rsyslog-sysmon.conf",
             "systemd/argus-selfcheck.service", "systemd/argus-selfcheck.timer", "sysmon/config.xml")



SOURCE_MAP_COMMENT = re.compile(rb"\r?\n?[ \t]*(?://|/\*)[#@] sourceMappingURL=[^\r\n]*")


def data_files(tree, clean_dir):
    """[(source path, path inside the program)] for the package data that ships.

    The same on every Python: `Path.glob("dir/**")` returns only directories up
    to Python 3.12 and files as well from 3.13, so a 3.12 build shipped no
    web/static file at all (found by the windows-installer branch, 2026-11-03;
    the published 2026.11.03-0 server and Windows engine have none). A pattern
    ending in /** is every file below the directory.

    Vendored web libraries end with a `sourceMappingURL` comment pointing at a
    map that is not shipped. The release policy denies that marker, so the
    comment (not the code) is removed from a copy; the build stops if it survives.
    """
    pkg = Path(tree) / "argus"
    out = []
    for pattern in DATA_KEEP:
        if pattern.endswith("/**"):
            found = sorted(p for p in (pkg / pattern[:-3]).rglob("*") if p.is_file())
        else:
            found = sorted(p for p in pkg.glob(pattern) if p.is_file())
        for f in found:
            rel = f.relative_to(tree).as_posix()
            data = f.read_bytes()
            if f.suffix in (".js", ".css") and b"sourceMappingURL=" in data:
                data = SOURCE_MAP_COMMENT.sub(b"", data)
                if b"sourceMappingURL=" in data:
                    sys.exit(f"{rel}: a sourceMappingURL reference remains after cleaning")
                f = Path(clean_dir) / rel
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_bytes(data)
            out.append((f, rel))
    if not any(rel.startswith("argus/web/static/") for _f, rel in out):
        sys.exit("no web/static file found: the dashboard would ship empty")
    return out

def nuitka(tree, work, jobs):
    """Compile tree/release/launcher.py; returns the standalone folder."""
    cmd = [sys.executable, "-m", "nuitka", "--standalone", "--assume-yes-for-downloads",
           f"--output-dir={work}", "--output-filename=argus-server",
           "--include-package=argus", "--nofollow-import-to=argus.platform.win",
           # GNU Readline remains excluded pending dependency/source-obligations review
           # (found bundled in v2026.10.30-2). The daemon never edits lines interactively;
           # the content gate refuses any release that still carries it.
           "--nofollow-import-to=readline", "--nofollow-import-to=rlcompleter",
           "--noinclude-dlls=libreadline.so*",
           "--include-package=cryptography",
           "--python-flag=isolated", "--python-flag=safe_path",
           "--file-reference-choice=runtime", "--lto=no", f"--jobs={jobs}",
           f"--report={work}/nuitka-report.xml", "--remove-output",
           # The daemon runs its collector workers and the self-check by calling this program
           # with `-m <module>`. Nuitka refuses any such self-call unless told otherwise; the
           # launcher itself allows only the four modules in launcher.CHILD_MODULES
           # (tests/test_release_signing.py: "-m os" exits 2), so the guard is not what limits it.
           "--no-deployment-flag=self-execution",
           # C accelerators the daemon leans on (Nuitka's anti-bloat drops them).
           "--include-module=_json", "--include-module=_bisect"]
    for f, rel in data_files(tree, Path(work) / "data-clean"):
        cmd.append(f"--include-data-files={f}={rel}")
    for rel in REPO_DATA:
        if (tree / rel).is_file():
            cmd.append(f"--include-data-files={tree / rel}={rel}")
    cmd.append(str(tree / "release" / "launcher.py"))
    print("$ " + " ".join(cmd[:12]) + " ...", flush=True)
    subprocess.run(cmd, cwd=tree, check=True)
    dist = work / "launcher.dist"
    if not (dist / "argus-server").is_file():
        sys.exit(f"Nuitka produced no {dist}/argus-server")
    return dist


def smoke(dist):
    """The program starts, refuses arbitrary -m modules and passes its own checks."""
    env = {**os.environ, "ARGUS_QUIET_SEAL": "1", "HOME": tempfile.mkdtemp(prefix="argus-smoke-")}
    exe = str(dist / "argus-server")
    r = subprocess.run([exe, "--help"], capture_output=True, text=True, env=env, timeout=120)
    if r.returncode != 0:
        sys.exit(f"argus-server --help failed:\n{r.stdout}{r.stderr}")
    r = subprocess.run([exe, "-m", "os"], capture_output=True, text=True, env=env, timeout=60)
    if r.returncode != 2:
        sys.exit("argus-server ran an arbitrary -m module")
    report = Path(env["HOME"]) / "verification.json"
    r = subprocess.run([exe, "-m", "argus.verify", "--json", str(report)], capture_output=True,
                       text=True, env=env, timeout=900)
    if r.returncode != 0:
        sys.exit(f"the compiled program fails its own verification:\n{(r.stdout + r.stderr)[-3000:]}")
    return json.loads(report.read_text())


def entries(dist, version, commit):
    """(path inside the package, bytes, mode) of the server edition."""
    out = []
    for f in sorted(dist.rglob("*")):
        if f.is_symlink():
            sys.exit(f"{f}: the program folder must hold no symlinks")
        if not f.is_file():
            continue
        rel = f.relative_to(dist).as_posix()
        exe = rel == "argus-server" or ".so" in rel.rsplit("/", 1)[-1]
        out.append((f"bin/{rel}", f.read_bytes(), 0o755 if exe else 0o644))
    server = HERE / "server"
    for name in ("argus.service", "argus-netsensor.service", "argus-netstate.service", "argus-netstate.timer"):
        out.append((f"units/{name}", (server / name).read_bytes(), 0o644))
    out.append(("install.sh", (server / "install.sh").read_bytes(), 0o755))
    out.append(("uninstall.sh", (server / "uninstall.sh").read_bytes(), 0o755))
    out.append(("README.txt", (server / "README.txt").read_bytes(), 0o644))
    out.append(("LICENSE.txt", (REPO_ROOT / "LICENSE.txt").read_bytes(), 0o644))
    out.append(("THIRD-PARTY-NOTICES.txt", (REPO_ROOT / "THIRD-PARTY-NOTICES.txt").read_bytes(), 0o644))
    out.append(("VERSION", f"{version} ({commit})\n".encode(), 0o644))
    return out


def _tar_add(tar, arcname, data, mode):
    info = tarfile.TarInfo(arcname)
    info.size, info.mode, info.mtime = len(data), mode, EPOCH
    info.uname = info.gname = "root"
    tar.addfile(info, io.BytesIO(data))


def _tar_dirs(tar, path, made):
    parts = path.split("/")[:-1]
    for i in range(1, len(parts) + 1):
        d = "/".join(parts[:i]) + "/"
        if d not in made:
            info = tarfile.TarInfo(d)
            info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, EPOCH
            info.uname = info.gname = "root"
            tar.addfile(info)
            made.add(d)


def _gzip(data):
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode="wb", mtime=EPOCH, filename="") as gz:
        gz.write(data)
    return raw.getvalue()


def _tar(files, prefix):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        made = set()
        for rel, data, mode in files:
            path = prefix + rel
            _tar_dirs(tar, path, made)
            _tar_add(tar, path, data, mode)
    return raw.getvalue()


def ar_archive(members):
    out = [b"!<arch>\n"]
    for name, data in members:
        header = f"{name:<16}{EPOCH:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode()
        out += [header, data, b"\n" if len(data) % 2 else b""]
    return b"".join(out)


def build_tar(files, out):
    name = "argus-server-linux-x86_64.tar.gz"
    (out / name).write_bytes(_gzip(_tar(files, "argus-server/")))
    return name


def build_deb(files, out, version, commit):
    ver = version.replace("-", ".")
    name = f"argus-server_{ver}_amd64.deb"
    size = sum(len(d) for _, d, _ in files)
    control = (
        f"Package: argus-server\nVersion: {ver}\nArchitecture: amd64\n"
        f"Maintainer: {DEB_MAINTAINER}\nInstalled-Size: {size // 1024 + 1}\n"
        f"Depends: {DEB_DEPENDS}\nSuggests: {DEB_SUGGESTS}\nSection: admin\nPriority: optional\n"
        "Homepage: https://www.archymedes.xyz/en/solutions/argus/\n"
        f"Description: Argus server security monitor ({commit})\n"
        " Watches a Linux server for the ways something could take or keep control\n"
        " of it: SSH keys and logins, sudo, accounts, systemd and cron persistence,\n"
        " hidden processes, web shells, exposure and package integrity. One native\n"
        " program, run as its own unprivileged account; evidence stays on the server.\n").encode()
    ctrl = io.BytesIO()
    with tarfile.open(fileobj=ctrl, mode="w", format=tarfile.GNU_FORMAT) as tar:
        _tar_add(tar, "control", control, 0o644)
        for script in ("postinst", "prerm", "postrm"):
            _tar_add(tar, script, (HERE / "deb" / script).read_bytes(), 0o755)
    data = _tar(files, "usr/share/argus-server/")
    (out / name).write_bytes(ar_archive([("debian-binary", b"2.0\n"),
                                         ("control.tar.gz", _gzip(ctrl.getvalue())),
                                         ("data.tar.gz", _gzip(data))]))
    return name


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--ref", default="HEAD")
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--work", help="build folder (default: a temporary one)")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    repo = HERE.parent
    with tempfile.TemporaryDirectory(prefix="argus-server-") as tmp:
        work = Path(args.work or tmp)
        tree = work / "tree"
        shutil.rmtree(tree, ignore_errors=True)
        commit = rename.export(repo, args.ref, tree)
        print(f"exported {commit} as Argus", flush=True)
        dist = nuitka(tree, work / "nuitka", args.jobs)
        shutil.copy(work / "nuitka" / "nuitka-report.xml", out / "nuitka-report.xml")
        verification = smoke(dist)
        print(f"compiled program passes its own verification: {verification.get('ok', verification)!s:.200}")
        files = entries(dist, args.version, commit)
        built = [build_tar(files, out), build_deb(files, out, args.version, commit)]
    record = {"edition": "server", "version": args.version, "commit": commit,
              "files": {n: {"bytes": (out / n).stat().st_size,
                            "sha256": hashlib.sha256((out / n).read_bytes()).hexdigest()} for n in built}}
    (out / "server-build.json").write_text(json.dumps(record, indent=2) + "\n")
    policy = gate.load_policy()
    problems = []
    for name in built:
        problems += gate.check_artifact(out / name, gate.rule_for(name, policy), policy)[0]
    for p in problems:
        print("REFUSED  " + p)
    if problems:
        sys.exit(f"the server packages fail the content gate ({len(problems)} problems)")
    print("server packages pass the content gate: " + ", ".join(built))


if __name__ == "__main__":
    main()
