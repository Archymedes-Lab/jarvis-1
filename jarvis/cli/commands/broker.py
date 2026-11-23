"""`jarvis broker` — the elevated collector broker.

    jarvis broker status     installed, current, last run, per-job result
    jarvis broker install    stage scripts and register the task (one UAC prompt)
    jarvis broker install --firewall-logging
                             also log allowed and blocked firewall connections
    jarvis broker remove     unregister and delete (one UAC prompt)
    jarvis broker sysmon-baseline
                             apply windows-sysmon/jarvis-windows-baseline.xml
                             with an exact registry backup in the vault,
                             verification and automatic rollback (one UAC prompt)
"""

import base64
import hashlib
import re
import subprocess
import time
from pathlib import Path

from jarvis.core.paths import REPO_ROOT, WIN_SCRIPTS_DIR
from jarvis.platform import broker, host
from jarvis.platform import windows as win


def _winpath(path):
    return host.windows_name(path)


def _ps_args(script):
    """PowerShell argv immune to WSL/Windows command-line quote rewriting.

    Progress is silenced: over a pipe PowerShell serialises it as CLIXML
    ("Preparing modules for first use") into stderr, which reached the user."""
    script = "$ProgressPreference='SilentlyContinue';" + script
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return [win._PS, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]


STAGE_TRIES = 3
STAGE_TIMEOUT_S = 60


def _clean(text):
    """PowerShell output without CLIXML serialisation noise."""
    return "\n".join(line for line in (text or "").splitlines()
                     if not line.startswith(("#< CLIXML", "<Objs "))).strip()


def _make_stage(prefix):
    """A fresh folder under the Windows user's TEMP: (path, "") or ("", why).

    Retried: right after a daemon restart or a task registration the interop
    bridge can refuse one call (2026-10-27: "could not create a staging
    folder", fine seconds later), and the real error used to be discarded."""
    script = (f"$d=Join-Path $env:TEMP ('{prefix}-'+[guid]::NewGuid());"
              "New-Item -ItemType Directory $d | Out-Null; $d")
    why = ""
    for attempt in range(STAGE_TRIES):
        if attempt:
            time.sleep(3 * attempt)
        try:
            r = subprocess.run(_ps_args(script), capture_output=True, text=True,
                               errors="replace", cwd="/", timeout=STAGE_TIMEOUT_S)
        except (OSError, subprocess.SubprocessError) as exc:
            why = f"{type(exc).__name__}: {exc}"
            continue
        stage = r.stdout.strip().splitlines()[-1].strip() if r.stdout.strip() else ""
        if r.returncode == 0 and stage:
            return stage, ""
        why = _clean(r.stderr)[-400:] or f"PowerShell exited {r.returncode} with no output"
    return "", f"could not create a staging folder on Windows after {STAGE_TRIES} tries: {why}"


_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# PowerShell closes a single-quoted string at any of these characters.
_PS_QUOTES = ("'", "\u2018", "\u2019", "\u201a", "\u201b")
_POWERSHELL = "(Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\\v1.0\\powershell.exe')"

# Runs elevated. It never executes anything from the user's TEMP stage: it
# creates a fresh folder under %SystemRoot%\Temp whose ACL (SYSTEM and
# Administrators only, nothing inherited) is set in the same call that creates
# it, copies the staged files there, checks each copy against the SHA-256 JARVIS
# computed from its checkout, and runs only those copies. Data reaches it as
# quoted literals built by _ps_literal, never as code.
_BOOTSTRAP = r"""$ErrorActionPreference = 'Stop'
$sys = [Environment]::SystemDirectory
$env:PSModulePath = Join-Path $sys 'WindowsPowerShell\v1.0\Modules'
$src = __SRC__
$want = [ordered]@{ __WANT__ }
$entry = __ENTRY__
$argv = @(__ARGS__)
$id = { param($v) New-Object Security.Principal.SecurityIdentifier($v) }
$sec = New-Object Security.AccessControl.DirectorySecurity
$sec.SetOwner((& $id 'S-1-5-32-544'))
$sec.SetAccessRuleProtection($true, $false)
foreach ($s in 'S-1-5-18', 'S-1-5-32-544') {
    $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((& $id $s), 'FullControl',
        'ContainerInherit, ObjectInherit', 'None', 'Allow')))
}
$dst = Join-Path (Join-Path (Split-Path -Parent $sys) 'Temp') ('jarvis-elevated-' + [guid]::NewGuid().ToString('N'))
$code = 1
try {
    if (Test-Path -LiteralPath $dst) { throw "refusing: $dst already exists" }
    [void][IO.Directory]::CreateDirectory($dst, $sec)
    foreach ($name in $want.Keys) {
        $to = Join-Path $dst $name
        Copy-Item -LiteralPath (Join-Path $src $name) -Destination $to
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $to).Hash.ToLowerInvariant()
        if ($got -ne $want[$name]) { throw "refusing: $name changed after JARVIS checked it" }
    }
    $argv = @($argv | ForEach-Object { $_.Replace('{stage}', $dst) })
    & (Join-Path $sys 'WindowsPowerShell\v1.0\powershell.exe') -NoProfile -NonInteractive `
        -ExecutionPolicy Bypass -File (Join-Path $dst $entry) @argv
    $code = $LASTEXITCODE
} catch {
    Write-Output $_.Exception.Message
    $code = 1
} finally {
    Remove-Item -LiteralPath $dst -Recurse -Force -ErrorAction SilentlyContinue
}
exit $code
"""


def _ps_literal(text):
    """`text` as a PowerShell single-quoted literal (data, never code)."""
    text = str(text)
    if any(ch in text for ch in "\r\n\0"):
        raise ValueError("control character in a PowerShell literal")
    for quote in _PS_QUOTES:
        text = text.replace(quote, quote + quote)
    return "'" + text + "'"


def _bootstrap(stage, digests, entry, args):
    """The elevated bootstrap for `digests` ({name: sha256}) staged in `stage`."""
    for name in list(digests) + [entry]:
        if not _SAFE_NAME.match(name):
            raise ValueError(f"unsafe staged file name: {name!r}")
    if entry not in digests:
        raise ValueError("the entry script must be one of the verified files")
    for digest in digests.values():
        if not _HEX64.match(digest):
            raise ValueError("not a SHA-256 hex digest")
    want = "; ".join(f"{_ps_literal(n)} = {_ps_literal(d)}" for n, d in digests.items())
    return (_BOOTSTRAP.replace("__SRC__", _ps_literal(stage))
            .replace("__WANT__", want)
            .replace("__ENTRY__", _ps_literal(entry))
            .replace("__ARGS__", ", ".join(_ps_literal(a) for a in args)))


def _elevated_verified(files, entry, args, prefix, timeout=240):
    """Run `entry` elevated, through one UAC prompt, from verified copies.

    `files` maps a staged name to its checkout path. The files are staged in
    the user's TEMP (writable by anything running as the user), so the
    elevated side copies them into an administrator-only folder, refuses any
    copy whose SHA-256 differs from what was read here, and runs only those
    copies. The \\\\wsl share and the TEMP stage are never executed elevated.
    `{stage}` in `args` becomes that protected folder. Returns (exit code, output).
    """
    if not win.available():
        return 1, "the Windows interop bridge is not available"
    digests = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
               for name, path in files.items()}
    stage, why = _make_stage(prefix)
    if not stage:
        return 1, why
    try:
        inner = _bootstrap(stage, digests, entry, args)
        copy = ";".join(
            f"Copy-Item -LiteralPath {_ps_literal(_winpath(path))} "
            f"-Destination (Join-Path {_ps_literal(stage)} {_ps_literal(name)})"
            for name, path in files.items())
    except ValueError as exc:
        return 1, f"refused: {exc}"
    # The bootstrap travels as a here-string and is encoded on the Windows
    # side: encoding it twice here nearly filled the 32767-character limit.
    # Its data literals cannot contain a newline, so no line can end it early.
    script = (f"{copy}; $b = @'\n{inner}\n'@\n"
              "$e = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($b)); "
              f"$p = Start-Process -FilePath {_POWERSHELL} -Verb RunAs -Wait -PassThru "
              "-ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',"
              "'-EncodedCommand',$e; "
              f"Remove-Item -LiteralPath {_ps_literal(stage)} -Recurse -Force; exit $p.ExitCode")
    try:
        r = subprocess.run(_ps_args(script),
                           capture_output=True, text=True, errors="replace", timeout=timeout, cwd="/")
    except subprocess.TimeoutExpired:
        return 1, "timed out waiting for the UAC prompt"
    return r.returncode, _clean(r.stdout + "\n" + r.stderr)


def _elevated_files(files, entry, args, timeout=240):
    """Copy `files` ({name: path}) and run `entry` elevated through one UAC prompt."""
    return _elevated_verified(files, entry, args, "jarvis-elevated", timeout)


def _sysmon_baseline():
    from jarvis.collectors.telemetry import sysmon_policy
    policy = REPO_ROOT / sysmon_policy.BASELINE
    installer = REPO_ROOT / "scripts" / "repair" / "apply-jarvis-sysmon-policy.ps1"
    digest = hashlib.sha256(policy.read_bytes()).hexdigest()
    print(f"baseline SHA-256 {digest}")
    print("approve the UAC prompt on the Windows desktop…")
    code, out = _elevated_files(
        {"apply.ps1": installer, "baseline.xml": policy}, "apply.ps1",
        ["-PolicyPath", "{stage}\\baseline.xml", "-ExpectedSha256", digest])
    if out:
        print(out)
    # Success is what the elevated broker next reads back, not the exit code.
    print("applied; the evidence job confirms the running hash on its next run"
          if code == 0 else "did not complete — nothing is changed unless the script reported it")
    return 0 if code == 0 else 1


def _elevated(args, timeout=240):
    """Run jarvis-elevated-broker.ps1 with `args` through a UAC prompt, from a
    verified administrator-only copy (see _elevated_verified)."""
    files = {n: (REPO_ROOT if n == broker.BROKER_SCRIPT else WIN_SCRIPTS_DIR) / n
             for n in [broker.BROKER_SCRIPT] + list(broker.SCRIPTS.values())}
    return _elevated_verified(files, broker.BROKER_SCRIPT, list(args) + ["-Source", "{stage}"],
                              "jarvis-broker", timeout)


def cmd_broker(args, store=None):
    if args.action == "status":
        if not broker.installed():
            print("not installed — run `jarvis broker install`")
            return 1
        drift = broker.drifted()
        print("scripts:", "match this checkout" if not drift else "DIFFER: " + ", ".join(drift))
        st = broker.status() or {}
        if not st:
            print("no run recorded yet")
            return 1
        print(f"admin token: {st.get('admin')}; last run finished "
              f"{int((time.time() - (st.get('finished') or 0)) / 60)}m ago")
        for name, job in (st.get("jobs") or {}).items():
            print(f"  {name:9} {'ok' if job.get('ok') else 'FAILED'} {job.get('secs')}s {job.get('error') or ''}")
        return 0
    if args.action == "sysmon-baseline":
        return _sysmon_baseline()
    if args.action == "install":
        extra = ["-Install"] + (["-EnableFirewallLogging"] if args.firewall_logging else [])
        print("approve the UAC prompt on the Windows desktop…")
        code, out = _elevated(extra)
    else:
        print("approve the UAC prompt on the Windows desktop…")
        code, out = _elevated(["-Remove"])
    if out:
        print(out)
    if args.action == "install":
        # An older installation does not make a failed restage successful.
        # The elevated command must complete and every staged script must
        # match this checkout before we say "done".
        ok = code == 0 and broker.installed() and not broker.drifted()
    else:
        ok = code == 0 and not broker.installed()
    print("done" if ok else "did not complete — the prompt may have been declined")
    return 0 if ok else 1


def add_parser(sub):
    p = sub.add_parser("broker", help="elevated read-only collectors (posture, memscan, firewall log)")
    p.add_argument("action", nargs="?", default="status", choices=["status", "install", "remove",
                                                               "sysmon-baseline"])
    p.add_argument("--firewall-logging", action="store_true",
                   help="on install, also log allowed and blocked firewall connections")
    p.set_defaults(fn=cmd_broker)
    return p
