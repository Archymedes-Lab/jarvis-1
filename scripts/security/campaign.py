#!/usr/bin/env python3
"""Bounded, metadata-only ARGUS-1 security campaign; no production targets."""

import argparse
import datetime
import hashlib
import json
import os
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
METHODS = ("sast", "taint", "dast", "iast", "sanitizers", "model", "formal",
           "manual", "binary", "sca", "secrets", "configuration", "pentest", "threat")
MAX_OUTPUT = 1024 * 1024
TIMEOUT = 300


@dataclass(frozen=True)
class Step:
    name: str
    method: str
    argv: tuple[str, ...] = ()
    cwd: str = "."
    gap: str = ""
    timeout: int = TIMEOUT


def tests(name, method, *modules):
    return Step(name, method, (sys.executable, "scripts/security/checks.py", "tests", *modules))


def plan(options=None):
    steps = [
        Step("bandit", "sast", ("bandit", "-r", "jarvis", "release", "-q")),
        tests("ast-policy", "sast", "tests.test_verify_static"),
        Step("semgrep", "taint", ("semgrep", "scan", "--config", "scripts/security/taint.yml",
                                    "--metrics=off", "--disable-version-check", "--jobs=1", "--timeout=30",
                                    "--max-memory=512", "--error", "--strict", "jarvis"), timeout=600),
        Step("taint-controls", "taint", ("semgrep", "--test", "--config", "scripts/security/taint.yml",
                                          "tests/security/taint_fixtures.py")),
        tests("http-boundaries", "dast", "tests.test_api_hardening", "tests.test_security_boundaries"),
        tests("paired-client-boundaries", "dast", "tests.test_api_clients"),
        Step("handler-observation", "iast", (sys.executable, "scripts/security/checks.py", "iast")),
        Step("python-debug-allocator", "sanitizers", (sys.executable, "-X", "dev", "scripts/security/checks.py",
                                                     "tests", "tests.test_fuzz_findings", "tests.test_api_token")),
        Step("native-sanitizers", "sanitizers", gap="Rust ASan/TSan and Windows sensor instrumented builds require an isolated native build lab; see native-sanitizers.sh"),
        tests("bounded-models", "model", "tests.test_verify_mc", "tests.test_verify_models", "tests.test_verify_ladder_model"),
        Step("authority-spec", "formal", (sys.executable, "scripts/security/checks.py", "formal")),
        Step("implementation-refinement", "formal", (sys.executable, 'scripts/security/refinement.py')),
        Step("human-review", "manual", gap="Independent reviewer must sign exact source scope and findings"),
        tests("artifact-gate-regressions", "binary", "tests.test_release_gate", "tests.test_release_gate_archives"),
        Step("built-artifact-review", "binary", gap="Actual ELF/PE hardening, disassembly and bundled-library review require a named sealed artifact"),
        Step("python-runtime-audit", "sca", ("pip-audit", "--no-deps", "--disable-pip", "-r", "release/requirements-runtime.txt")),
        Step("rust-lock-audit", "sca", ("cargo-audit", "audit", "--file", "desktop/Cargo.lock")),
        Step("history-secrets", "secrets", ("gitleaks", "git", "--redact=100", "--no-banner", ".")),
        Step("ases", "configuration", (sys.executable, "scripts/dev/standard_check.py")),
        tests("service-definitions", "configuration", "tests.test_argus_server", "tests.test_argus_server_net"),
        tests("synthetic-exploits", "pentest", "tests.test_fuzz_findings", "tests.test_security_boundaries"),
        Step("deployed-attack-chains", "pentest", gap="Disposable deployed VM attack chains, broker and Windows paths remain untested"),
        Step("architecture-review", "threat", gap="Threat model recorded in ARGUS-SECURITY-TESTING.md; independent human coverage review pending"),
    ]
    if options is not None:
        replacements = {}
        if options.artifact:
            replacements['built-artifact-review'] = Step('built-artifact-review', 'binary',
                    (sys.executable, 'scripts/security/binary_review.py', str(options.artifact.absolute())))
        if options.rustup_home:
            replacements['native-sanitizers'] = Step('native-sanitizers', 'sanitizers',
                    (sys.executable, 'scripts/security/native_checks.py', '--rustup-home', str(options.rustup_home.absolute())), timeout=900)
        if options.release:
            replacements['deployed-attack-chains'] = Step('deployed-attack-chains', 'pentest',
                    (sys.executable, 'scripts/security/vm_pentest.py', '--release', str(options.release.absolute()),
                     '--lab-root', str(options.lab_root.absolute())), timeout=1500)
        if options.review_receipt and options.review_signature:
            argv = (sys.executable, 'scripts/security/review_record.py', '--receipt', str(options.review_receipt.absolute()),
                    '--signature', str(options.review_signature.absolute()))
            for name, method in [('human-review', 'manual'), ('architecture-review', 'threat')]:
                replacements[name] = Step(name, method, argv)
        steps = [replacements.get(step.name, step) for step in steps]
    # Discover every Bun package, not just the desktop frontend.
    for manifest in sorted([ROOT / "desktop/ui/package.json", *ROOT.glob("hosted/*/package.json")]):
        rel = manifest.parent.relative_to(ROOT).as_posix()
        steps.append(Step("bun-audit-" + rel.replace("/", "-"), "sca", ("bun", "audit"), rel))
    return steps


def isolated_env(home):
    # Executable search is retained for provisioned tools, never shell evaluation.
    env = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C.UTF-8",
           "HOME": str(home), "USERPROFILE": str(home), "TMPDIR": str(home),
           "XDG_CONFIG_HOME": str(home / ".config"), "XDG_DATA_HOME": str(home / ".local/share"),
           "XDG_CACHE_HOME": str(home / ".cache"), "PYTHONPATH": str(ROOT),
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONMALLOC": "debug",
           "PIP_NO_INPUT": "1", "GIT_TERMINAL_PROMPT": "0", "SEMGREP_SEND_METRICS": "off"}
    for sub in (".cache", ".config", ".local/share"):
        (home / sub).mkdir(parents=True, exist_ok=True)
    return env


def kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def execute(step, home, timeout=None, output_limit=MAX_OUTPUT, environment=None, output_consumer=None):
    """Never retain arbitrary scanner output; kill descendants even after parent exit."""
    result = {"name": step.name, "method": step.method, "scope": step.cwd}
    timeout = step.timeout if timeout is None else timeout
    if step.gap:
        return {**result, "status": "pending", "reason": step.gap}
    env = isolated_env(home)
    if environment:
        allowed = {'RUSTUP_HOME', 'RUSTUP_AUTO_INSTALL', 'CARGO_HOME', 'CARGO_BUILD_JOBS',
                   'CARGO_TARGET_DIR', 'RUSTFLAGS', 'RUSTDOCFLAGS', 'RUSTC', 'ASAN_OPTIONS', 'TSAN_OPTIONS'}
        if set(environment) - allowed:
            raise ValueError('unsupported tool environment override')
        env.update(environment)
    if not shutil.which(step.argv[0], path=env["PATH"]):
        return {**result, "status": "unavailable", "reason": "tool not installed"}
    start = time.monotonic()
    digest, size, status, returncode = hashlib.sha256(), 0, "error", None
    proc = None
    try:
        proc = subprocess.Popen(step.argv, cwd=ROOT / step.cwd, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                start_new_session=True)
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = timeout - (time.monotonic() - start)
                if remaining <= 0:
                    status = "timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    data = os.read(key.fd, min(65536, output_limit - size + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    size += len(data)
                    digest.update(data)
                    if size > output_limit:
                        status = "output_limit"
                        break
                    if output_consumer is not None:
                        output_consumer(data)
                if status == "output_limit":
                    break
            else:
                # A child can close stdout and continue running.
                try:
                    returncode = proc.wait(timeout=max(0.001, timeout - (time.monotonic() - start)))
                    status = "passed" if returncode == 0 else "incomplete" if returncode == 2 else "failed"
                except subprocess.TimeoutExpired:
                    status = "timeout"
    except OSError:
        status = "error"  # Exception text can contain secrets/paths; do not copy it.
    finally:
        if proc is not None:
            kill_group(proc)
            proc.wait()
            proc.stdout.close()
    return {**result, "status": status, "returncode": returncode,
            "seconds": round(time.monotonic() - start, 3), "output_bytes": size,
            "output_sha256": digest.hexdigest()}


def exit_code(results):
    if any(r["status"] in {"failed", "error", "timeout", "output_limit"} for r in results):
        return 1
    return 2 if not results or any(r["status"] != "passed" for r in results) else 0


def save_report(path, report):
    # Directory is freshly created mode 0700, never a caller-specified path.
    temp = path.with_suffix(".tmp")
    with temp.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    temp.chmod(0o600)
    temp.replace(path)


def source_snapshot():
    """Hash tracked and untracked checkout files, without reporting their contents.

    Symlinks are hashed as links, never followed into protected user data. A
    finite byte budget makes large/unreadable trees explicitly incomplete.
    """
    digest, size = hashlib.sha256(), 0
    try:
        listing = subprocess.run(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'],
                                 cwd=ROOT, capture_output=True, timeout=10, check=True).stdout
        if len(listing) > MAX_OUTPUT:
            return {'status': 'incomplete'}
        for raw in sorted(set(listing.split(b'\0')) - {b''}):
            path = ROOT / os.fsdecode(raw)
            digest.update(raw + b'\0')
            try:
                mode = path.lstat().st_mode
                digest.update(str(stat.S_IMODE(mode)).encode() + b'\0')
                if stat.S_ISLNK(mode):
                    link = os.fsencode(os.readlink(path))
                    digest.update(b'link:' + hashlib.sha256(link).digest())
                    continue
                if not stat.S_ISREG(mode):
                    return {'status': 'incomplete'}
                # Do not follow a link substituted after lstat, or block on a FIFO.
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                file_digest = hashlib.sha256()
                with os.fdopen(fd, 'rb') as source:
                    if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                        return {'status': 'incomplete'}
                    while chunk := source.read(65536):
                        size += len(chunk)
                        if size > 256 * 1024 * 1024:
                            return {'status': 'incomplete'}
                        file_digest.update(chunk)
                digest.update(b'file:' + file_digest.digest())
            except FileNotFoundError:
                digest.update(b'deleted\0')
        return {'status': 'measured', 'sha256': digest.hexdigest(), 'bytes': size}
    except (OSError, subprocess.SubprocessError):
        return {'status': 'incomplete'}


def activate_toolchain(directory):
    """Use only a private installation whose receipt matches pinned manifests."""
    directory = directory.absolute()
    if directory.is_symlink() or directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
        raise ValueError('toolchain must be private and owned by this user')
    with (directory / 'receipt.json').open('rb') as file:
        raw = file.read(MAX_OUTPUT + 1)
    if len(raw) > MAX_OUTPUT:
        raise ValueError('tool receipt bound')
    receipt = json.loads(raw)
    for field, name in [('requirements_sha256', 'requirements.txt'), ('manifest_sha256', 'toolchain.json')]:
        if receipt.get(field) != hashlib.sha256((ROOT / 'scripts/security' / name).read_bytes()).hexdigest():
            raise ValueError('stale tool receipt')
    wanted = {'bandit', 'semgrep', 'pip-audit', 'z3', 'gitleaks', 'cargo-audit'}
    if receipt.get('schema') != 1 or set(receipt.get('tools', {})) != wanted:
        raise ValueError('incomplete tool receipt')
    paths = set()
    for name, entry in receipt['tools'].items():
        path = directory / entry['path']
        if not path.resolve().is_relative_to(directory.resolve()) or not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
            raise ValueError('tool escapes installation or exceeds bound')
        with path.open('rb') as file:
            digest = hashlib.file_digest(file, 'sha256').hexdigest()
        if digest != entry['sha256'] or path.name != name:
            raise ValueError('tool digest mismatch')
        paths.add(str(path.parent))
    os.environ['PATH'] = os.pathsep.join(sorted(paths)) + os.pathsep + os.environ.get('PATH', os.defpath)
    return hashlib.sha256(raw).hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--method", action="append", choices=METHODS)
    ap.add_argument("--list", action="store_true")
    ap.add_argument('--toolchain', type=Path)
    ap.add_argument('--artifact', type=Path)
    ap.add_argument('--rustup-home', type=Path)
    ap.add_argument('--release', type=Path)
    ap.add_argument('--lab-root', type=Path, default=Path.home() / '.cache/jarvis-vmlab')
    ap.add_argument('--review-receipt', type=Path)
    ap.add_argument('--review-signature', type=Path)
    args = ap.parse_args(argv)
    try:
        toolchain_digest = activate_toolchain(args.toolchain) if args.toolchain else None
    except (OSError, ValueError, KeyError, TypeError):
        ap.error('toolchain receipt is missing, stale or invalid')
    selected = set(args.method or METHODS)
    steps = [step for step in plan(args) if step.method in selected]
    if args.list:
        for step in steps:
            print(f"{step.method:14} {step.name}: {step.gap or ' '.join(step.argv)}")
        return 0
    directory = Path(tempfile.mkdtemp(prefix="argus-security-"))
    report = {"schema": 1, "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "selected_methods": sorted(selected), "scope": "checkout and synthetic tests only",
              "complete": False, "interrupted": False, "results": []}
    report['source_start'] = source_snapshot()
    report['toolchain_receipt_sha256'] = toolchain_digest
    path = directory / "report.json"
    save_report(path, report)
    print(f"report: {path}", flush=True)
    try:
        for step in steps:
            report['active_step'] = step.name
            save_report(path, report)
            with tempfile.TemporaryDirectory(prefix="home-", dir=directory) as scratch:
                result = execute(step, Path(scratch))
            report["results"].append(result)
            save_report(path, report)
            print(f"{step.method}/{step.name}: {result['status']}", flush=True)
    except KeyboardInterrupt:
        report["interrupted"] = True
        save_report(path, report)
        return 130
    report.pop('active_step', None)
    report['source_end'] = source_snapshot()
    stable = (report['source_start'].get('status') == 'measured'
              and report['source_start'] == report['source_end'])
    report['source_stable'] = stable
    report["complete"] = stable and len(selected) == len(METHODS) and exit_code(report["results"]) == 0
    report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save_report(path, report)
    code = exit_code(report['results'])
    return code if code else 0 if stable else 2


if __name__ == "__main__":
    sys.exit(main())
