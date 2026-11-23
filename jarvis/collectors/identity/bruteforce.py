"""Password guessing, seen from the artefacts it leaves in the auth logs.

Brute force (T1110) is one of the most-cited techniques in the intel corpus and
one of the few runtime behaviours that *does* leave a durable host artefact: a
pile of failed-authentication records. Every OS keeps them.

  Linux   sshd and PAM write "Failed password", "authentication failure" and
          "Invalid user" lines to the journal or /var/log/auth.log. btmp
          (read by `lastb`) records failed logins too, when it is readable.

  Windows the Security log records event 4625 for every failed logon and 4740
          for an account lockout — but only if logon auditing is enabled, so
          "no events" is reported as "cannot tell", not "clean".

This is a counting exercise, not interception: a spike of failures from one
source, a spread of failures across many usernames (spraying), or any lockout
is the signal. It cannot see a slow, low-volume guess that stays under the
threshold, and it says so.
"""

import json
import re
import subprocess

from jarvis.core.finding import finding as _finding
from jarvis.core.paths import load_win_script
from jarvis.platform import windows as collect_windows
from jarvis.platform.windows import ps_json

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

WINDOW_H = 24
SPIKE_ONE_SOURCE = 20      # failures from a single source in the window
SPRAY_USERS = 10           # distinct usernames targeted from one source
TOTAL_ELEVATED = 40        # total failures in the window worth a medium

# 4625 status codes that are a policy refusing a logon, not a wrong guess.
# Measured 2026-09-24: all 20 failures were msedge.exe / msedgewebview2.exe
# Windows single sign-on attempts refused with 0xc000006e (account
# restriction), which read as a 20-failure guessing attack. Wrong-password
# (0xc000006a), unknown-user (0xc0000064) and every unlisted status still count
# as guessing, so an unfamiliar status can never quietly lower the verdict.
POLICY_REFUSALS = {
    "0xc000006e": "account restriction",
    "0xc000006f": "outside allowed logon hours",
    "0xc0000070": "workstation not permitted",
    "0xc0000071": "password expired",
    "0xc0000072": "account disabled",
    "0xc0000193": "account expired",
    "0xc0000133": "clock out of sync with the domain",
    "0xc000015b": "logon type not granted",
    "0xc0000224": "password must change at next logon",
}


def _refusal(status, sub):
    """The policy reason for a failure, or "" when it counts as a guess."""
    status, sub = (status or "").lower(), (sub or "").lower()
    if status == "0xc000006d" and sub in POLICY_REFUSALS:
        return POLICY_REFUSALS[sub]
    return POLICY_REFUSALS.get(status, "")

# The username is chosen by the remote client and may contain " from <ip>": the
# source is the address in sshd's own trailing " from IP port N", so the user
# part is greedy and the line is anchored at its end. pam_unix writes rhost=
# before user=, so its first rhost= is pam's own.
_SSHD_TAIL = r" from (?P<{ip}>\S+) port \d+(?: ssh2)?(?: \[preauth\])?\]?\s*$"
_LINUX_FAIL = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>.*?)" + _SSHD_TAIL.format(ip="ip")
    + r"|authentication failure;.*?rhost=(?P<ip2>\S+)(?:.*?\buser=(?P<user2>\S+))?"
    r"|Invalid user (?P<user3>.*?)" + _SSHD_TAIL.format(ip="ip3"))


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))


# ── Linux ───────────────────────────────────────────────────────────────────

class _Lines(list):
    """Auth lines, with the number of failure lines left out because an
    unprivileged process wrote them (kept visible, never counted)."""
    untrusted = 0


def _journal_messages(stdout):
    """MESSAGE of each `journalctl -o json` entry written by a root process.

    Any local user can put authpriv lines in the journal (`logger -p
    authpriv.notice "Failed password for x from <ip> port 1 ssh2"`) and invent
    a brute force from an innocent address; _UID is set by journald itself and
    cannot be forged. sshd, sshd-session, sudo and pam all log as root."""
    out = _Lines()
    for raw in stdout.splitlines():
        try:
            entry = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        msg = entry.get("MESSAGE")
        if entry.get("_UID") != "0":
            if isinstance(msg, str) and _LINUX_FAIL.search(msg):
                out.untrusted += 1
            continue
        if isinstance(msg, list):                  # non-UTF-8 messages come as byte arrays
            try:
                msg = bytes(b for b in msg if isinstance(b, int) and 0 <= b < 256).decode("utf-8", "replace")
            except ValueError:
                continue
        if isinstance(msg, str):
            out.append(msg)
    return out


def _linux_lines():
    """Recent auth lines, from the journal if present, else the flat logs."""
    since = f"{WINDOW_H} hours ago"
    try:
        r = subprocess.run(
            ["journalctl", "--since", since, "--no-pager", "-q",
             "SYSLOG_FACILITY=10", "-o", "json", "--output-fields=MESSAGE,_UID"],
            capture_output=True, text=True,
            errors="replace", timeout=30)
        if r.returncode == 0 and r.stdout.strip():
            return _journal_messages(r.stdout)
    except (OSError, subprocess.SubprocessError):
        pass
    lines = []
    for p in ("/var/log/auth.log", "/var/log/auth.log.1",
              "/var/log/secure", "/var/log/secure.1"):
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                lines += fh.read().splitlines()[-20000:]
        except OSError:
            continue
    return lines


def _linux(lines=None):
    """`lines` are auth-log lines already read (the coverage map's probes)."""
    out = []
    lines = _linux_lines() if lines is None else lines
    if not lines and not isinstance(lines, _Lines):     # an empty journal read is still a read
        out.append(_finding(
            "bruteforce", "low", "no readable auth log on the Linux side",
            "neither the journal nor /var/log/auth.log could be read, so "
            "failed-login volume here is unknown — run as root to see it",
            "journalctl / auth.log"))
        return out

    by_ip = {}          # ip -> [count, {users}]
    sudo_fail = 0
    for ln in lines:
        if "pam_unix(sudo:auth): authentication failure" in ln:
            sudo_fail += 1
        m = _LINUX_FAIL.search(ln)
        if not m:
            continue
        ip = m.group("ip") or m.group("ip2") or m.group("ip3") or "?"
        user = m.group("user") or m.group("user2") or m.group("user3") or "?"
        rec = by_ip.setdefault(ip, [0, set()])
        rec[0] += 1
        rec[1].add(user)

    total = sum(v[0] for v in by_ip.values())
    for ip, (n, users) in sorted(by_ip.items(), key=lambda x: -x[1][0])[:8]:
        if n >= SPIKE_ONE_SOURCE or len(users) >= SPRAY_USERS:
            spray = (f", spread across {len(users)} usernames"
                     if len(users) >= SPRAY_USERS else "")
            out.append(_finding(
                "bruteforce", "high",
                f"{n} failed SSH/PAM logins from {ip} in {WINDOW_H}h{spray}",
                f"sample users: {', '.join(sorted(users)[:6])}. A sustained "
                f"guess against this host — confirm the source is yours or "
                f"block it", "auth log"))

    if not out and total >= TOTAL_ELEVATED:
        out.append(_finding(
            "bruteforce", "medium",
            f"{total} failed logins on the Linux side in {WINDOW_H}h",
            "below the single-source spike threshold but above background — "
            "worth knowing which host and account", "auth log"))

    if sudo_fail >= 5:
        out.append(_finding(
            "bruteforce", "medium",
            f"{sudo_fail} failed sudo authentications in {WINDOW_H}h",
            "repeated wrong passwords at sudo — a local user, or something "
            "trying to escalate", "auth log"))

    if not out:
        out.append(_finding(
            "bruteforce", "ok", "no failed-login spike on the Linux side",
            f"{total} failed attempts in {WINDOW_H}h, none concentrated on one "
            f"source", "auth log"))
    untrusted = getattr(lines, "untrusted", 0)
    if untrusted:
        # Not counted (anyone can write them), but never silently dropped: an
        # sshd that does not run as root would also land here.
        out.append(_finding(
            "bruteforce", "low",
            f"{untrusted} failed-login line(s) in the journal written by a non-root process",
            "not counted toward brute-force detection, because any local user can "
            "write such lines; if this host's sshd runs unprivileged, they may be real",
            "journal (authpriv)"))
    return out


# ── Windows ─────────────────────────────────────────────────────────────────

_WIN_PS = load_win_script("bruteforce.ps1")


def _windows():
    if not collect_windows.available():
        return []
    d = ps_json(_WIN_PS, timeout=120)
    if not d:
        return [_finding(
            "bruteforce", "low", "could not read the Windows Security log",
            "the 4625 query returned nothing — the log may be inaccessible "
            "from here", "Security log", host="win")]
    return windows_findings(d)


def windows_findings(d):
    """Findings from the 4625/4740 summary bruteforce.ps1 returns. Pure, so the
    verification catalogue can drive it (V15: a guessed user name never
    chooses the source a containment action reads)."""
    out = []
    auditing = int(d.get("auditing") or 0)
    if auditing == -1:
        out.append(_finding(
            "bruteforce", "low", "cannot read the Windows Security log",
            "the 4625 query was denied — reading it needs Administrator or "
            "'Event Log Readers' membership, so failed-logon volume on the "
            "Windows side is unknown from here", "Security log", host="win"))
        return out
    if auditing == 0:
        out.append(_finding(
            "bruteforce", "medium", "failed-logon auditing looks disabled",
            "the 4625 query returned no events and no error, which usually "
            "means 'Audit logon events' is off — a brute force against this "
            "machine would leave no trace. Enable it in the local security "
            "policy", "auditpol", host="win"))
        return out

    total = int(d.get("total") or 0)
    top = d.get("top") or []
    if isinstance(top, dict):
        top = [top]
    guesses, refused = {}, {}
    for row in top:
        n = int(row.get("n") or 0)
        # Split from the right: the user name is the guesser's own text and may
        # hold "|"; the address, status codes and process name are Windows'.
        user, ip, status, sub, proc = ((row.get("key") or "").rsplit("|", 4) + [""] * 5)[:5]
        why = _refusal(status, sub)
        if why:
            r = refused.setdefault(why, [0, set()])
            r[0] += n
            r[1].add(proc or "an unnamed process")
        else:
            guesses[(user, ip)] = guesses.get((user, ip), 0) + n
    refused_total = sum(n for n, _ in refused.values())
    for (user, ip), n in sorted(guesses.items(), key=lambda kv: -kv[1]):
        if n >= SPIKE_ONE_SOURCE:
            out.append(_finding(
                "bruteforce", "high",
                f"{n} failed Windows logons for {user or '(blank)'} "
                f"from {ip if ip not in ('', '-') else 'local'} in 24h",
                "a concentrated logon-guessing attempt — confirm the source",
                "Security log 4625", host="win"))
    for why, (n, procs) in sorted(refused.items(), key=lambda kv: -kv[1][0]):
        out.append(_finding(
            "bruteforce", "low",
            f"{n} Windows sign-in attempt{'s' if n != 1 else ''} refused by policy ({why})",
            f"by {', '.join(sorted(procs)[:4])} — a rule refused these logons; they are "
            "not wrong-password guesses. Worth a look only if the process is unfamiliar.",
            "Security log 4625", host="win"))
    total -= refused_total

    if int(d.get("lockouts") or 0):
        out.append(_finding(
            "bruteforce", "high",
            f"{d['lockouts']} account lockout(s) in the last 7 days",
            "an account hit the lockout threshold — either a real attack or a "
            "stale credential hammering the domain", "Security log 4740",
            host="win"))

    if not any(f["severity"] in ("high", "critical") for f in out) and total >= TOTAL_ELEVATED:
        out.append(_finding(
            "bruteforce", "medium",
            f"{total} failed Windows logons in 24h",
            "elevated but not concentrated on one source", "Security log 4625",
            host="win"))
    if not any(f["severity"] != "low" for f in out):
        out.append(_finding(
            "bruteforce", "ok", "no failed-logon spike on the Windows side",
            f"{total} wrong-password or unknown-user failures in 24h, none "
            "concentrated", "Security log",
            host="win"))
    return out


def audit(hosts=("wsl", "win")):
    out = []
    if "wsl" in hosts:
        out += _linux()
    if "win" in hosts:
        out += _windows()
    return sort_findings(out)
