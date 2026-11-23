"""Successful SSH logins: who got in, how, and from where (ARGUS-SERVER.md W3).

The brute-force audit counts failures; this reads the other half, sshd's
"Accepted ..." records in the journal, behind a stored journal cursor, and
keeps a learned set per account of source networks (/24, /48) and key
fingerprints, with first-seen times.

Reported (each kept for a day, so it does not vanish on the next run):

    critical  a login from an address that failed to authenticate at least
              GUESS_FAILURES times in the hour before: a guess that succeeded
    high      root logged in over SSH
    high      a password login on a server where accounts otherwise use keys
    high      a key fingerprint not seen before for that account
    medium    a known account from a network not seen before for it

The first run learns: it pages only for root, guessed and password logins.
A journal that cannot be read, or a cursor the journal no longer has, is
reported as not observed, never as "no logins" (I1, I7).

Trusted origin (FZ-04): `-t sshd` matches SYSLOG_IDENTIFIER, which the
client chooses (`logger -t sshd "Accepted publickey for ..."` from any
account). Only records whose _UID, written by journald itself, is root are
evidence; sshd and sshd-session log as root (the privsep child's messages go
through the root monitor). This is bruteforce._journal_messages' rule. A
record from any other account is never evidence and never trains the
baseline, but it is counted and reported, not silently dropped: something is
writing as sshd, or this host's sshd runs unprivileged.
"""

import ipaddress
import json
import re
import subprocess
import time

from jarvis.core.finding import win_finding as _finding

STATE_META = "logins_state_v1"     # {"cursor", "learned_at", "accounts": {...}}
EVENTS_META = "logins_events_v1"   # [{"ts", "kind", ...}] last day of reportable events
FAILS_META = "logins_failures_v1"  # {ip: [ts, ...]} last hour
MAX_LINES = 20000
MAX_EVENTS = 500
MAX_FAIL_IPS = 5000
KEEP_S = 24 * 3600
GUESS_WINDOW_S = 3600
GUESS_FAILURES = 5
MAX_PER_ACCOUNT = 256
IDENTIFIERS = ("sshd", "sshd-session")     # OpenSSH 9.8+ logs sessions as sshd-session

ACCEPTED = re.compile(
    r"Accepted (?P<method>[\w/-]+) for (?P<user>\S+) from (?P<ip>\S+) port \d+"
    r"(?: ssh2)?(?:: (?P<ktype>\S+) (?P<fp>SHA256:\S+|[0-9a-f:]{47}))?")
# The user name is chosen by the remote client and may hold spaces and " from <ip>"
# (sshd logs it as sent, at most 100 characters): the source is the address in sshd's
# own trailing " from IP port N", so the line is anchored at its end (FZ-03; the same
# rule bruteforce._LINUX_FAIL applies). Failed publickey lines end in ": TYPE FP".
FAILED = re.compile(
    r"(?:Failed \S+ for (?:invalid user )?.*?|Invalid user .*?) from (?P<ip>\S+) port \d+"
    r"(?: ssh2)?(?:: \S+ \S+)?(?: \[preauth\])?\]?\s*$")


def network_of(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(ipaddress.ip_network(f"{addr}/{24 if addr.version == 4 else 48}", strict=False))


class Records(list):
    """(ts, message) records from root; `untrusted` counts sshd-tagged records
    from any other account and `untrusted_ts` is the newest one's time."""
    untrusted = 0
    untrusted_ts = 0.0


def read_journal(cursor, run=subprocess.Popen, max_lines=MAX_LINES):
    """(records, new cursor, problem). records are (ts, message) from root only
    (a Records list carrying the count of rejected non-root ones)."""
    argv = ["journalctl", "-o", "json", "--no-pager", "-q"]
    for ident in IDENTIFIERS:
        argv += ["-t", ident]
    argv += ["--after-cursor", cursor] if cursor else ["--since", "-24h"]
    try:
        proc = run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    except OSError as exc:
        return [], cursor, f"journalctl could not run: {exc.strerror or exc}"
    records, last, truncated = Records(), cursor, False
    try:
        for n, line in enumerate(proc.stdout):
            if n >= max_lines:
                truncated = True
                break
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if not isinstance(rec, dict):      # one odd line lost the whole read (FZ-15)
                continue
            msg = rec.get("MESSAGE")
            if isinstance(msg, list):           # journald encodes non-UTF-8 as bytes
                msg = bytes(b for b in msg if isinstance(b, int) and 0 <= b < 256).decode("utf-8", "replace")
            try:
                ts = int(rec.get("__REALTIME_TIMESTAMP", 0)) / 1e6
            except (TypeError, ValueError, OverflowError):
                ts = 0.0
            if rec.get("_UID") != "0":
                # Forgeable: counted and reported, never evidence (FZ-04).
                records.untrusted += 1
                records.untrusted_ts = max(records.untrusted_ts, ts)
            elif isinstance(msg, str):
                records.append((ts, msg))
            last = rec.get("__CURSOR") or last
    finally:
        if truncated:
            proc.kill()
        try:
            _out, err = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            err = ""
    problem = ""
    if proc.returncode not in (0, None, -9) and not records:
        problem = "journalctl failed: " + ((err or "").strip().splitlines() or [""])[-1][:200]
        if cursor and "cursor" in (err or "").lower():
            # Start again from the last day rather than retrying a cursor the
            # journal no longer has, forever.
            problem = ("the stored journal cursor is gone (journal rotated or vacuumed): "
                       "logins in between were not read")
            last = None
    elif truncated:
        problem = f"more than {max_lines} sshd records since the last run; the rest is read next run"
    return records, last, problem


def _fresh_account():
    return {"nets": {}, "keys": {}, "methods": {}}


def evaluate(records, state, failures, now):
    """(events, state, failures): apply records in order. Pure."""
    learning = not state.get("learned_at")
    accounts = state.setdefault("accounts", {})
    events = []
    uses_keys = any(a.get("methods", {}).get("publickey") for a in accounts.values())
    for ts, msg in records:
        f = FAILED.search(msg)
        if f:
            lst = failures.setdefault(f["ip"], [])
            lst.append(ts)
            continue
        m = ACCEPTED.search(msg)
        if not m:
            continue
        user, ip, method, fp = m["user"], m["ip"], m["method"], m["fp"] or ""
        net = network_of(ip)
        acct = accounts.setdefault(user, _fresh_account())
        known_user = bool(acct["nets"] or acct["keys"])
        recent_fails = [t for t in failures.get(ip, []) if ts - GUESS_WINDOW_S <= t <= ts]
        base = {"ts": ts, "user": user, "ip": ip, "net": net, "method": method}
        if len(recent_fails) >= GUESS_FAILURES:
            events.append({**base, "kind": "guessed", "fails": len(recent_fails)})
        if user == "root":
            events.append({**base, "kind": "root"})
        if method == "password" and (uses_keys or acct["methods"].get("publickey")):
            events.append({**base, "kind": "password"})
        if not learning and fp and fp not in acct["keys"] and known_user:
            events.append({**base, "kind": "new_key", "fp": fp})
        if not learning and net not in acct["nets"] and known_user:
            events.append({**base, "kind": "new_net"})
        if len(acct["nets"]) < MAX_PER_ACCOUNT:
            acct["nets"].setdefault(net, ts)
        if fp and len(acct["keys"]) < MAX_PER_ACCOUNT:
            acct["keys"].setdefault(fp, ts)
        acct["methods"][method] = acct["methods"].get(method, 0) + 1
        uses_keys = uses_keys or method == "publickey"
    cutoff = now - GUESS_WINDOW_S
    failures = {ip: [t for t in ts_list if t >= cutoff][-50:] for ip, ts_list in failures.items()}
    failures = {ip: v for ip, v in failures.items() if v}
    if len(failures) > MAX_FAIL_IPS:
        failures = dict(sorted(failures.items(), key=lambda kv: -len(kv[1]))[:MAX_FAIL_IPS])
    if learning:
        state["learned_at"] = now
    return events, state, failures


TITLES = {
    "guessed": ("critical", "a password guesser logged in as {user}",
                "{user} logged in from {ip} by {method} after {fails} failed attempts from that address "
                "in the hour before"),
    "root": ("high", "root logged in over SSH", "from {ip} by {method}"),
    "password": ("high", "password login for {user}",
                 "from {ip}; accounts on this server otherwise log in with keys"),
    "new_key": ("high", "new SSH key used for {user}", "{fp} from {ip}: not seen for {user} before"),
    "new_net": ("medium", "{user} logged in from a new network", "{ip} ({net}) by {method}"),
    "untrusted": ("medium", "sshd journal records written by a non-root process",
                  "{count} record(s) tagged sshd came from an account other than root: not used as "
                  "login evidence or to learn the baseline, because any local account can write them "
                  "(logger -t sshd). Find the writer; if this host's sshd runs unprivileged they may be real"),
}


def findings(events, now):
    out = {}
    for e in events:
        if now - e["ts"] > KEEP_S:
            continue
        sev, title, detail = TITLES[e["kind"]]
        title = title.format(**e)
        where = e["net"] if e["kind"] != "new_key" else e.get("fp", "")
        key = (title, where)
        stamp = time.strftime("%Y-%m-%d %H:%M", time.gmtime(e["ts"]))
        out[key] = _finding("login", sev, title, detail.format(**e) + f" (last {stamp} UTC)", where, host="wsl")
    return list(out.values())


def _load(store, key, default):
    try:
        v = json.loads(store.get_meta(key, "") or "null")
    except (ValueError, TypeError):
        v = None
    return default if v is None else v


def audit(store, hosts=None, now=None, reader=read_journal):
    now = time.time() if now is None else now
    state = _load(store, STATE_META, {})
    failures = _load(store, FAILS_META, {})
    records, cursor, problem = reader(state.get("cursor"))
    events, state, failures = evaluate(records, state, failures, now)
    untrusted = getattr(records, "untrusted", 0)
    if untrusted:
        events.append({"ts": getattr(records, "untrusted_ts", 0.0) or now, "kind": "untrusted",
                       "count": untrusted, "net": "journal (SYSLOG_IDENTIFIER=sshd, _UID!=0)"})
    state["cursor"] = cursor
    kept = [e for e in _load(store, EVENTS_META, []) if isinstance(e, dict) and now - e.get("ts", 0) <= KEEP_S]
    kept = (kept + events)[-MAX_EVENTS:]
    store.set_meta(STATE_META, json.dumps(state))
    store.set_meta(FAILS_META, json.dumps(failures))
    store.set_meta(EVENTS_META, json.dumps(kept))
    out = findings(kept, now)
    if problem:
        out.append(_finding("visibility", "medium", "SSH logins not fully observed", problem,
                            "journalctl -t sshd", host="wsl"))
    return out
