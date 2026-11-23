"""Build and switch a root-owned JARVIS release, so the service can hold
visibility capabilities without running code its user can edit.

  sudo python3 -I scripts/deploy_root_runtime.py --enable   # first install
  sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py   # update
  sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py --rollback
  sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py --disable

After the first install, run the root-owned copy in /opt/jarvis/current:
running a script from the checkout with sudo trusts a file anything running
as you could have edited. Review the change list each deploy prints.

Root never runs git or reads paths inside the checkout. A child running as
the checkout's owner packs the files (git's list: tracked plus untracked,
not ignored; plus the built Rust runtime) into a tar stream, so a symlink or
a git hook in the checkout reaches only what that user could already read or
run. Root unpacks the stream with the tarfile "data" filter (no links,
devices or paths outside the release), makes it root-owned and unwritable,
precompiles it, records RELEASE.json (source, commit, per-file SHA-256),
checks the tree is sealed, then switches /opt/jarvis/current atomically.

The systemd drop-in grants the capabilities only together with the
release's ExecStart, so they can never apply to the checkout.

Release controller (docs/architecture/EVIDENCE-FABRIC.md, P1/P5/P6):
  * A release is identified by release_id, the SHA-256 of its file manifest,
    never by the directory it was built from.
  * One writer: a deploy holds /opt/jarvis/.deploy.lock for its whole run.
    With --expect-base, it refuses unless the live release is still the
    base the candidate was staged from (`jarvis release stage` prints it),
    so a narrow release cannot silently drop another one's changes.
  * The checkout a release belongs to is an installation property kept in
    root-owned /opt/jarvis/INSTALL.json. It is never guessed from a
    temporary build source: that guess made JARVIS's own watchdog tasks read
    as critical on 2026-09-24.
  * A source under a world-writable directory (/tmp, /var/tmp) is refused.
"""

import argparse
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import pwd
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

BASE = "/opt/jarvis"
KEEP = 5
INSTALL = "INSTALL.json"
LOCK = ".deploy.lock"
MAX_BYTES = 512 << 20
PACK_META = "__jarvis_pack__.json"
RUNTIME_BINARY = "rust-runtime/target/release/jarvis-runtime"
DROPIN = "/etc/systemd/system/jarvis.service.d/root-runtime.conf"
# A release missing these cannot start, and systemd would restart it forever.
REQUIRED = ("jarvis-release.py", "jarvis/cli/__init__.py", "jarvis/platform/privilege.py")
CAPABILITIES = "CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_SYSLOG"


def dropin_text(base=BASE, port=8787):
    return f"""# Installed by scripts/deploy_root_runtime.py. Do not edit; rerun it.
#
# Runs the root-owned release under python3 -I and grants only the
# visibility capabilities (see jarvis/platform/privilege.py). The launcher
# drops them if the release is not root-owned and sealed.
[Service]
WorkingDirectory={base}/current
ExecStart=
ExecStart=/usr/bin/python3 -I {base}/current/jarvis-release.py serve --port {port}
AmbientCapabilities={CAPABILITIES}
"""


def _own_module(name):
    """jarvis/platform/provenance/<name>.py from this script's own tree, loaded by
    path so no package __init__ runs as root. In production this tree is
    the sealed, root-owned release."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(here, "jarvis", "platform", "provenance", name + ".py")
    spec = importlib.util.spec_from_file_location("_jarvis_provenance_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


identity = _own_module("release")
PROVENANCE_KEYS = "/etc/jarvis/provenance"


def ensure_provenance_key(key_dir=PROVENANCE_KEYS):
    """Create the execution-identity signing key once (root 0400, public 0444).

    Only the capability-holding daemon can read the private key (through
    CAP_DAC_READ_SEARCH). Any failure leaves JARVIS without issuance, which
    it reports. That is never a reason to refuse a deploy."""
    try:
        return _own_module("identity").generate_keypair(key_dir, owner=0)
    except Exception as exc:
        print(f"  provenance key not provisioned: {type(exc).__name__}: {exc}")
        return None


# -- packing: runs as the checkout's owner ------------------------------------

def _git(source, *args):
    return subprocess.run(
        ["git", "-C", source, "-c", "core.fsmonitor=false", *args],
        capture_output=True, check=True).stdout


def pack(source, out):
    """Write the checkout as a tar stream. Runs unprivileged."""
    names = [n.decode("utf-8", "surrogateescape") for n in
             _git(source, "ls-files", "-z", "--cached", "--others",
                  "--exclude-standard").split(b"\0") if n]
    names.append(RUNTIME_BINARY)
    commit = _git(source, "rev-parse", "HEAD").decode().strip()
    dirty = bool(_git(source, "status", "--porcelain").strip())
    with tarfile.open(fileobj=out, mode="w|") as tar:
        meta = json.dumps({"source": source, "commit": commit, "dirty": dirty}).encode()
        info = tarfile.TarInfo(PACK_META)
        info.size = len(meta)
        tar.addfile(info, io.BytesIO(meta))
        for name in sorted(set(names)):
            if "__pycache__" in name.split("/"):
                continue
            full = os.path.join(source, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue        # links and deleted-but-tracked files are not shipped
            tar.add(full, arcname=name, recursive=False)


def _as_owner(source, command, cwd="/", extra_env=None):
    """Run `command` as the checkout's owner, never as root."""
    st = os.stat(source)
    user = pwd.getpwuid(st.st_uid)

    def demote():
        os.setgroups([])
        os.setgid(st.st_gid)
        os.setuid(st.st_uid)
        os.makedirs((extra_env or {}).get("TMPDIR") or "/", mode=0o700, exist_ok=True)

    env = {"PATH": "/usr/bin:/bin", "HOME": user.pw_dir, "LANG": "C.UTF-8",
           **(extra_env or {})}
    return subprocess.run(command, capture_output=True, preexec_fn=demote, env=env,
                          cwd=cwd, check=False)


def tests_pass(source):
    """The checkout's own suite, run unprivileged in the checkout."""
    # A private temp root: the suite builds and runs binaries, systemd units
    # and git repositories in temp dirs, which under world-writable /tmp are
    # exactly what the host's own Sysmon rules report.
    home = pwd.getpwuid(os.stat(source).st_uid).pw_dir
    done = _as_owner(source, ["/usr/bin/python3", "-m", "unittest", "discover",
                              "-s", "tests", "-q"], cwd=source,
                     extra_env={"TMPDIR": os.path.join(home, ".cache", "jarvis-tests")})
    if done.returncode != 0:
        tail = (done.stdout + done.stderr).decode(errors="replace").strip().splitlines()
        raise SystemExit("refusing: the checkout's tests fail\n  " + "\n  ".join(tail[-12:]))


def packed_as_owner(source):
    """Run pack() in a child that has dropped to the checkout owner's uid."""
    done = _as_owner(source, [sys.executable, "-I", os.path.abspath(__file__), "--pack", source])
    if done.returncode != 0:
        raise SystemExit("packing failed: " + done.stderr.decode(errors="replace")[-800:])
    if len(done.stdout) > MAX_BYTES:
        raise SystemExit("release is larger than the limit; refusing")
    return done.stdout


# -- building: runs as root ----------------------------------------------------

def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build(stream, releases, owner=0, checkout=None, base_release_id=None):
    """Unpack a pack() stream into a new sealed release directory under
    `releases`. Returns (path, manifest). `owner` is 0 in production and
    the test user's uid in tests. `checkout` is the editable checkout the
    release belongs to (see resolve_checkout); it defaults to the source."""
    tmp = tempfile.mkdtemp(prefix=".building-", dir=releases)
    try:
        with tarfile.open(fileobj=io.BytesIO(stream), mode="r:") as tar:
            members = tar.getmembers()
            for m in members:
                if not (m.isfile() or m.isdir()):
                    raise SystemExit(f"refusing non-regular member {m.name!r}")
            meta = json.loads(tar.extractfile(PACK_META).read())
            tar.extractall(tmp, members=[m for m in members if m.name != PACK_META],
                           filter="data")
        files = {}
        for dirpath, dirnames, filenames in os.walk(tmp):
            os.chown(dirpath, owner, owner)
            os.chmod(dirpath, 0o755)
            for name in filenames:
                full = os.path.join(dirpath, name)
                os.chown(full, owner, owner)
                executable = os.stat(full).st_mode & 0o111
                os.chmod(full, 0o755 if executable else 0o644)
                files[os.path.relpath(full, tmp)] = _sha256(full)
        missing = [f for f in REQUIRED if f not in files]
        if missing:
            raise SystemExit("refusing: release lacks " + ", ".join(missing))
        files = dict(sorted(files.items()))
        rid = identity.release_id(files)
        manifest = {"release_id": rid, "base_release_id": base_release_id,
                    "source": meta["source"], "checkout": checkout or meta["source"],
                    "commit": meta["commit"],
                    "dirty": bool(meta["dirty"]), "built_at": int(time.time()),
                    "files": files}
        with open(os.path.join(tmp, "RELEASE.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=1)
        if os.path.isdir(os.path.join(tmp, "jarvis")):
            subprocess.run(["/usr/bin/python3", "-I", "-m", "compileall", "-q",
                            os.path.join(tmp, "jarvis")], check=True)
        for dirpath, dirnames, filenames in os.walk(tmp):
            for name in dirnames + filenames:
                full = os.path.join(dirpath, name)
                os.chown(full, owner, owner)
                os.chmod(full, (os.stat(full).st_mode & 0o755) | 0o444)
        os.chown(tmp, owner, owner)
        os.chmod(tmp, 0o755)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        name = f"{stamp}-{identity.short(rid)}{'-dirty' if meta['dirty'] else ''}"
        final, n = os.path.join(releases, name), 1
        while os.path.lexists(final):
            n += 1
            final = os.path.join(releases, f"{name}-{n}")
        os.rename(tmp, final)
        return final, manifest
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def resolve_checkout(requested, previous, source, installed=None, first_install=False):
    """The editable checkout a release belongs to.

    Differs from `source` when a narrow release is built from a temporary
    clone: Windows tasks and the selfcheck unit were installed from the
    checkout and are verified against it. An explicit --checkout wins, then
    the installation's recorded checkout, then the current release's. The
    source itself is used only on a first install (--enable with nothing
    recorded), which by definition runs from the checkout. Otherwise the
    deploy refuses rather than guess: guessing the staging clone is what
    turned JARVIS's own tasks critical on 2026-09-24."""
    chosen = (requested or (installed or {}).get("checkout")
              or (previous or {}).get("checkout")
              or (source if first_install else None))
    if not chosen:
        raise SystemExit("refusing: no checkout is recorded for this installation; "
                         "pass --checkout /path/to/the/editable/checkout once")
    chosen = os.path.abspath(chosen)
    if not os.path.isdir(chosen):
        raise SystemExit(f"refusing: checkout {chosen} is not a directory")
    return chosen


def read_install(base):
    try:
        with open(os.path.join(base, INSTALL), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def write_install(base, checkout, owner=0):
    """Record the installation's checkout, root-owned and unwritable by others."""
    path = os.path.join(base, INSTALL)
    tmp = path + ".new"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"checkout": checkout, "recorded_at": int(time.time())}, fh, indent=1)
    os.chown(tmp, owner, owner)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def check_source_location(source):
    """Refuse a build source anyone could write next to (P6)."""
    bad = identity.world_writable_ancestor(source)
    if bad:
        raise SystemExit(f"refusing: source {source} is under world-writable {bad}; "
                         "stage releases in a private directory such as ~/.cache")


def check_expected_base(expected, previous):
    """Optimistic single-writer check: the live release must still be the
    base the candidate was staged from. Returns the live release_id."""
    live = None
    if previous and previous.get("files"):
        try:
            live = identity.manifest_release_id(previous)
        except ValueError as exc:
            raise SystemExit(f"refusing: the live release manifest is inconsistent: {exc}")
    if expected and expected != live:
        raise SystemExit(f"refusing: the live release is {live or 'none'}, not the expected "
                         f"base {expected}. Another release was switched in since this "
                         "candidate was staged; restage it on the live release.")
    return live


class DeployLock:
    """Exclusive, non-blocking: a second concurrent deploy refuses at once."""

    def __init__(self, base):
        self.path = os.path.join(base, LOCK)
        self.fd = None

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            raise SystemExit("refusing: another deploy holds " + self.path) from None
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


def changes(old, new):
    old_files = (old or {}).get("files", {})
    new_files = new["files"]
    return {"added": sorted(set(new_files) - set(old_files)),
            "removed": sorted(set(old_files) - set(new_files)),
            "changed": sorted(f for f in set(new_files) & set(old_files)
                              if new_files[f] != old_files[f])}


def switch(base, release):
    """Point base/current at `release` atomically."""
    link = os.path.join(base, "current")
    tmp = link + ".new"
    if os.path.lexists(tmp):
        os.unlink(tmp)
    os.symlink(os.path.relpath(release, base), tmp)
    os.replace(tmp, link)


def current_manifest(base):
    try:
        with open(os.path.join(base, "current", "RELEASE.json"), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def prune(base, keep=KEEP):
    releases = os.path.join(base, "releases")
    live = os.path.realpath(os.path.join(base, "current"))
    names = sorted(n for n in os.listdir(releases) if not n.startswith("."))
    for name in names[:-keep]:
        path = os.path.join(releases, name)
        if os.path.realpath(path) != live:
            shutil.rmtree(path)


def _seal_base(base):
    for path in (base, os.path.join(base, "releases")):
        os.makedirs(path, mode=0o755, exist_ok=True)
        st = os.lstat(path)
        if os.path.islink(path) or st.st_uid != 0 or st.st_mode & 0o022:
            raise SystemExit(f"refusing: {path} is not a root-owned, unwritable directory")


def _systemctl(*args):
    subprocess.run(["systemctl", *args], check=True)


def _write_dropin():
    os.makedirs(os.path.dirname(DROPIN), exist_ok=True)
    tmp = DROPIN + ".new"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(dropin_text())
    os.chmod(tmp, 0o644)
    os.replace(tmp, DROPIN)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--pack", metavar="CHECKOUT", help=argparse.SUPPRESS)
    ap.add_argument("--source", help="checkout to deploy (default: recorded source "
                                     "of the current release, else this script's checkout)")
    ap.add_argument("--checkout", help="editable checkout this release belongs to, when "
                                       "--source is a temporary clone (default: the one "
                                       "recorded in /opt/jarvis/INSTALL.json, else the "
                                       "current release's; never guessed from the source)")
    ap.add_argument("--enable", action="store_true", help="install the systemd drop-in")
    ap.add_argument("--disable", action="store_true",
                    help="remove the drop-in: run unprivileged from the checkout again")
    ap.add_argument("--rollback", action="store_true", help="switch to the previous release")
    ap.add_argument("--expect-base", metavar="RELEASE_ID",
                    help="refuse unless the live release is this release_id (printed by "
                         "`jarvis release stage`)")
    ap.add_argument("--no-restart", action="store_true")
    ap.add_argument("--skip-tests", action="store_true",
                    help="deploy without running the checkout's tests first")
    args = ap.parse_args(argv)

    if args.pack:
        pack(args.pack, sys.stdout.buffer)
        return 0
    if os.geteuid() != 0:
        raise SystemExit("run with sudo")
    if not sys.flags.isolated:
        raise SystemExit("run as: sudo python3 -I " + os.path.abspath(__file__))

    if args.disable:
        if os.path.exists(DROPIN):
            os.unlink(DROPIN)
        _systemctl("daemon-reload")
        if not args.no_restart:
            _systemctl("restart", "jarvis.service")
        print("Drop-in removed; JARVIS runs unprivileged from its checkout. "
              f"Releases are kept in {BASE}/releases.")
        return 0

    _seal_base(BASE)
    with DeployLock(BASE):
        return _deploy_locked(args)


def _deploy_locked(args):
    releases = os.path.join(BASE, "releases")
    if args.rollback:
        names = sorted(n for n in os.listdir(releases) if not n.startswith("."))
        live = os.path.basename(os.path.realpath(os.path.join(BASE, "current")))
        older = [n for n in names if n < live]
        if not older:
            raise SystemExit("no earlier release to roll back to")
        switch(BASE, os.path.join(releases, older[-1]))
        print(f"Switched to {older[-1]}.")
    else:
        previous = current_manifest(BASE)
        installed = read_install(BASE)
        source = os.path.abspath(args.source or (previous or {}).get("source")
                                 or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        check_source_location(source)
        base_id = check_expected_base(args.expect_base, previous)
        checkout = resolve_checkout(args.checkout, previous, source, installed,
                                    first_install=bool(args.enable and not previous
                                                       and not installed))
        if not args.skip_tests:
            print(f"Running the tests in {source} as its owner…", flush=True)
            tests_pass(source)
        release, manifest = build(packed_as_owner(source), releases, checkout=checkout,
                                  base_release_id=base_id)
        sys.path.insert(0, release)
        from jarvis.platform.privilege import code_tree_problems
        problems = code_tree_problems(release)
        if problems:
            shutil.rmtree(release)
            raise SystemExit("release is not sealed: " + "; ".join(problems))
        diff = changes(previous, manifest)
        print(f"Built {release}\n  release {manifest['release_id']}"
              f"\n  from {source} at {manifest['commit'][:12]}"
              + (" with uncommitted changes" if manifest["dirty"] else "")
              + (f"\n  for checkout {checkout}" if checkout != source else ""))
        for kind in ("added", "changed", "removed"):
            items = diff[kind]
            if items:
                print(f"  {kind} {len(items)}: " + ", ".join(items[:25])
                      + (" …" if len(items) > 25 else ""))
        switch(BASE, release)
        if (installed or {}).get("checkout") != checkout:
            write_install(BASE, checkout)
        key = ensure_provenance_key()
        if key:
            print(f"  provenance key {key} in {PROVENANCE_KEYS}")
        prune(BASE)
    if args.enable:
        _write_dropin()
    if os.path.exists(DROPIN):
        _systemctl("daemon-reload")
        if not args.no_restart:
            _systemctl("restart", "jarvis.service")
            print("jarvis.service restarted on the release.")
    else:
        print("Release built but not in use: rerun with --enable to run it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
