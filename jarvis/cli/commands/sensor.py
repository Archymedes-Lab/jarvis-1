"""`jarvis sensor` — install and inspect the native Windows sensor service.

Installation needs administrator: it registers a service, sets ACLs on
protected folders and adds the service account to Event Log Readers. The files
are copied to a Windows temp folder, never run off the \\\\wsl share, and the
elevated shell runs neither from there: it copies them into Program Files and
checks their SHA-256, fixed from the checkout before the UAC prompt (_inner).
An elevated shell must not execute a file the unprivileged user can edit.

Status and health need no privilege: they read the spool the service writes.
"""

import hashlib
import subprocess

from jarvis.core.paths import repo_file
from jarvis.platform import elevation, host
from jarvis.platform import windows as win
from jarvis.platform.native import ingest

SENSOR_FILES = ["JarvisSensor.cs", "install.ps1"]


def _winpath(path):
    return host.windows_name(path)


# The elevated shell's transcript: written under Program Files (administrators
# write, users read), never into the user-writable stage, where a planted link
# would turn an elevated write into one aimed wherever the link points.
LOG = r"Jarvis\Logs\sensor-install.log"


def _inner(stage, hashes, args):
    """The command the elevated PowerShell runs (platform/elevation.py): the
    staged files are copied into Program Files and matched against `hashes`,
    fixed from the checkout before the UAC prompt, and install.ps1 runs from
    that checked copy with the source hash it must compile."""
    return elevation.inline_command(stage, hashes, "install.ps1",
                                    [*args, "-SourceSha256", hashes["JarvisSensor.cs"]])


def _elevated(args, timeout=300):
    """Run windows-sensor/install.ps1 elevated from a checked copy. -> (code, output)."""
    if not win.available():
        return 1, "the Windows interop bridge is not available"
    stage = subprocess.run(
        [win._PS, "-NoProfile", "-Command",
         "$d=Join-Path $env:TEMP ('jarvis-sensor-'+[guid]::NewGuid());"
         "New-Item -ItemType Directory $d | Out-Null; $d"],
        capture_output=True, text=True, errors="replace", cwd="/").stdout.strip()
    if not stage:
        return 1, "could not create a staging folder on Windows"
    src = repo_file("windows-sensor")
    copy = ";".join(
        f"Copy-Item -LiteralPath '{_winpath(src / n)}' -Destination '{stage}\\{n}'"
        for n in SENSOR_FILES)
    # -Verb RunAs cannot redirect the child's streams (parameter-set conflict),
    # and the elevated window is separate, so the child records its own
    # transcript (LOG) and we read it back.
    hashes = {n: hashlib.sha256((src / n).read_bytes()).hexdigest() for n in SENSOR_FILES}
    log = f"(Join-Path $env:ProgramFiles {elevation.literal(LOG)})"
    inner = (f"New-Item -ItemType Directory -Force -Path (Split-Path -Parent {log}) | Out-Null;"
             f"Start-Transcript -LiteralPath {log} -Force | Out-Null; "
             f"try {{ {_inner(stage, hashes, args)} }} finally {{ Stop-Transcript | Out-Null }}")
    script = (f"{copy}; " + elevation.launcher(inner, after=(
        f"Get-Content -LiteralPath {log} -EA SilentlyContinue; "
        f"Remove-Item -LiteralPath {elevation.literal(stage)} -Recurse -Force;")))
    try:
        r = subprocess.run([win._PS, "-NoProfile", "-Command", script],
                           capture_output=True, text=True, errors="replace",
                           timeout=timeout, cwd="/")
    except subprocess.TimeoutExpired:
        return 1, "timed out waiting for the UAC prompt"
    return r.returncode, (r.stdout + r.stderr).strip()


def _service_state():
    if not win.available():
        return None
    r = subprocess.run(
        [win._PS, "-NoProfile", "-Command",
         "$s=Get-Service JarvisNativeSensor -EA SilentlyContinue;"
         "if($s){$s.Status.ToString()}else{'absent'}"],
        capture_output=True, text=True, errors="replace", cwd="/")
    return (r.stdout or "").strip() or "absent"


def cmd_sensor(args, store=None):
    if args.action == "status":
        state = _service_state()
        print(f"service JarvisNativeSensor: {state or 'Windows bridge unavailable'}")
        health = ingest.read_health(args.spool or ingest.SPOOL)
        if health is None:
            print(f"spool: none at {args.spool or ingest.SPOOL} — run `jarvis sensor install`")
            return 1
        age = health.get("age")
        print(f"health: {int(age)}s old" if age is not None else "health: timestamp unreadable",
              f"· boot {health.get('boot_id')} · device {str(health.get('device_id'))[:8]}")
        used, cap = health.get("spool_bytes"), health.get("spool_capacity")
        if used and cap:
            print(f"spool: {used // 1048576} of {cap // 1048576} MiB")
        for channel, st in (health.get("channels") or {}).items():
            s = st.get("status") if isinstance(st, dict) else st
            extra = f" — {st.get('reason')}" if isinstance(st, dict) and st.get("reason") else ""
            print(f"  {channel.replace('Microsoft-Windows-', '').replace('/Operational', '')}: {s}{extra}")
        return 0

    if args.action == "remove":
        print("approve the UAC prompt on the Windows desktop…")
        code, out = _elevated(["-Remove"] + (["-PurgeSpool"] if args.purge_spool else []))
        if out:
            print(out)
        return code

    # install
    extra = []
    if args.enable_task_log:
        extra.append("-EnableTaskLog")
    if args.sysmon_log_mb:
        extra += ["-SysmonLogMB", str(int(args.sysmon_log_mb))]
    print("approve the UAC prompt on the Windows desktop…")
    code, out = _elevated(["-Install"] + extra)
    if out:
        print(out)
    if _service_state() == "Running":
        print("done — the native ingestion job will drain the spool within a minute")
        return 0
    print("did not complete — the prompt may have been declined")
    return code or 1


def add_parser(sub):
    p = sub.add_parser("sensor", help="the native Windows event sensor (install needs admin)")
    p.add_argument("action", nargs="?", default="status", choices=["status", "install", "remove"])
    p.add_argument("--enable-task-log", action="store_true",
                   help="install: turn on the Task Scheduler channel (off by default in Windows)")
    p.add_argument("--sysmon-log-mb", type=int, metavar="MB",
                   help="install: enlarge the Sysmon log so fewer records are overwritten unread")
    p.add_argument("--purge-spool", action="store_true",
                   help="remove: also delete the recorded spool (kept as evidence otherwise)")
    p.add_argument("--spool", help="spool directory (default: ProgramData)")
    p.set_defaults(fn=cmd_sensor)
    return p
