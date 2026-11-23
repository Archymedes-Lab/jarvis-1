"""Operational health of a Linux server: the "boring" daily checks operators
most want automated (Exa research 2026-10-28, ~/.cache/argus-research), the
ones behind most small-company outages: expired certificates, failed units,
memory exhaustion, crashes.

    units     systemd units in the failed state, by name, with their result
    certs     TLS certificates the web servers and certbot use: expired is
              critical, under 7 days high, under 21 days medium (certbot
              renews at 30, so 21 means renewal is failing)
    oom       processes the kernel killed for memory, read from the kernel
              journal behind a stored cursor
    reboots   a previous boot that ended without a clean shutdown (power loss,
              kernel panic, hard reset), once per boot, medium until soaked

Disk and inode headroom stay with `storage`; the daemon's own OOM kills with
`resources`.

Invariants (tests/test_opshealth.py holds each):
    I1  a source that cannot be read is reported as not observed, never as
        healthy; a host without systemd or a web server is not applicable
    I2  bounded: certificate files, journal lines, kept events and reported
        names all have ceilings
    I3  read-only: only public certificates are opened (never key files), and
        only their expiry and subject are kept
"""

import glob
import json
import os
import re
import ssl
import subprocess
import time

from jarvis.core.finding import finding as _finding

STATE_META = "opshealth_state_v1"   # {"cursor", "boots": {boot_id: "clean"|"unclean"}, "events": [...]}
MAX_CERTS = 200
MAX_CERT_BYTES = 256 * 1024
MAX_CONFIG_FILES = 400
MAX_LINES = 20000
MAX_EVENTS = 200
MAX_LISTED = 8
KEEP_S = 24 * 3600
CERT_CRITICAL_D, CERT_HIGH_D, CERT_MEDIUM_D = 0, 7, 21

WEB_CONFIGS = ("/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*",
               "/etc/apache2/sites-enabled/*", "/etc/apache2/apache2.conf", "/etc/httpd/conf.d/*.conf",
               "/etc/haproxy/haproxy.cfg", "/etc/caddy/Caddyfile")
CERT_DIRECTIVE = re.compile(r"^\s*(?:ssl_certificate|SSLCertificateFile|tls)\s+['\"]?(/[^\s;'\"]+)", re.M | re.I)
HAPROXY_CRT = re.compile(r"\bcrt\s+(/\S+)")
# "Out of memory: Killed process" (system-wide) and "Memory cgroup out of
# memory: Killed process" (a unit over its MemoryMax): both stop a service.
OOM_RE = re.compile(r"out of memory: Killed process (\d+) \(([^)]{1,64})\)", re.I)
CLEAN_END = ("Journal stopped", "System is powering down", "System is rebooting", "Reached target System Power Off",
             "Reached target System Reboot", "Reached target Shutdown")


def _run(argv, timeout=30):
    """(returncode, stdout) or (None, reason)."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout, check=False)
    except FileNotFoundError:
        return None, "missing"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"{argv[0]} failed: {type(exc).__name__}"
    # journalctl exits 0 and prints only a hint when it may not open the system
    # journal: that is "not observed", never "nothing happened" (I1).
    if argv[0] == "journalctl" and "insufficient permissions" in (r.stderr or ""):
        return None, ("the system journal is not readable by this account (needs CAP_DAC_READ_SEARCH, "
                      "or membership of systemd-journal or adm)")
    return r.returncode, r.stdout


# ── failed units ─────────────────────────────────────────────────────────

def failed_units(run=_run):
    """(findings, problem)."""
    code, out = run(["systemctl", "list-units", "--state=failed", "--no-legend", "--plain", "--no-pager",
                     "--all", "--full"])
    if code is None:
        return [], ("" if out == "missing" else out)
    if code not in (0, 1):
        return [], f"systemctl list-units exited {code}"
    units = [line.split()[0] for line in out.splitlines() if line.strip() and not line.startswith("●")]
    units += [line.split()[1] for line in out.splitlines() if line.startswith("●") and len(line.split()) > 1]
    if not units:
        return [], ""
    out_f = []
    for u in sorted(set(units))[:MAX_LISTED]:
        _c, show = run(["systemctl", "show", u, "-p", "Result", "-p", "ExecMainStatus", "--no-pager"], timeout=10)
        props = dict(line.split("=", 1) for line in (show or "").splitlines() if "=" in line)
        why = ", ".join(f"{k} {v}" for k, v in props.items() if v) or "failed"
        out_f.append(_finding("operations", "medium", f"service {u} has failed",
                              f"{why}; see `journalctl -u {u} -n 50`", u))
    if len(set(units)) > MAX_LISTED:
        out_f.append(_finding("operations", "medium", f"{len(set(units))} systemd units have failed",
                              "showing the first " + str(MAX_LISTED) + "; `systemctl --failed` lists all", "systemd"))
    return out_f, ""


# ── certificates ─────────────────────────────────────────────────────────

def cert_paths(root="/"):
    """Certificate files named by web server configs and certbot, bounded."""
    def r(p):
        return os.path.join(root, p.lstrip("/")) if root != "/" else p
    found, configs = [], []
    for pattern in WEB_CONFIGS:
        configs += sorted(glob.glob(r(pattern)))
    for cfg in configs[:MAX_CONFIG_FILES]:
        try:
            with open(cfg, errors="replace") as fh:
                text = fh.read(MAX_CERT_BYTES)
        except OSError:
            continue
        for m in list(CERT_DIRECTIVE.finditer(text)) + list(HAPROXY_CRT.finditer(text)):
            found.append(r(m.group(1)))
    found += sorted(glob.glob(r("/etc/letsencrypt/live/*/cert.pem")))
    seen, out = set(), []
    for p in found:
        if "privkey" in p or p.endswith(".key"):      # I3: never a key file
            continue
        real = os.path.realpath(p)
        if real not in seen:
            seen.add(real)
            out.append(p)
    return out[:MAX_CERTS], max(0, len(seen) - MAX_CERTS)


def cert_expiry(path):
    """(not_after epoch, subject CN) of the first certificate in a PEM file."""
    with open(path, "rb") as fh:
        data = fh.read(MAX_CERT_BYTES)
    m = re.search(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", data, re.S)
    if not m:
        raise ValueError("no PEM certificate")
    import tempfile
    # The decoder takes a path; a PEM with a private key in it is never passed on.
    with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=True) as tmp:
        tmp.write(m.group(0) + b"\n")
        tmp.flush()
        info = ssl._ssl._test_decode_cert(tmp.name)  # type: ignore[attr-defined]
    cn = ""
    for rdn in info.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                cn = v
    return ssl.cert_time_to_seconds(info["notAfter"]), cn


def cert_findings(now, root="/", reader=cert_expiry):
    paths, extra = cert_paths(root)
    out, problems = [], []
    for p in paths:
        try:
            not_after, cn = reader(p)
        except FileNotFoundError:
            out.append(_finding("operations", "high", "web server names a certificate that is missing",
                                f"{p} does not exist; the server will fail to start or reload", p))
            continue
        except (OSError, ValueError, ssl.SSLError) as exc:
            problems.append(f"{p}: {type(exc).__name__}")
            continue
        days = (not_after - now) / 86400
        label = cn or os.path.basename(os.path.dirname(p)) or p
        when = time.strftime("%Y-%m-%d", time.gmtime(not_after))
        if days <= CERT_CRITICAL_D:
            out.append(_finding("operations", "critical", f"TLS certificate for {label} has expired",
                                f"expired {when}; browsers and clients refuse it", p))
        elif days < CERT_HIGH_D:
            out.append(_finding("operations", "high", f"TLS certificate for {label} expires in {int(days)} days",
                                f"expires {when}", p))
        elif days < CERT_MEDIUM_D:
            out.append(_finding("operations", "medium", f"TLS certificate for {label} expires in {int(days)} days",
                                f"expires {when}; automatic renewal normally acts at 30 days, so it may be failing",
                                p))
    if extra:
        problems.append(f"{extra} more certificates not checked (limit {MAX_CERTS})")
    return out, problems


# ── kernel journal: OOM kills and how the previous boots ended ───────────

def read_kernel(cursor, run=_run):
    """(records, cursor, problem): (ts, message) of kernel messages since cursor."""
    argv = ["journalctl", "-k", "-o", "json", "--no-pager", "-q", "-n", str(MAX_LINES)]
    argv += ["--after-cursor", cursor] if cursor else ["--since", "-24h"]
    code, out = run(argv, timeout=60)
    if code is None:
        return [], cursor, ("" if out == "missing" else out)
    records, last = [], cursor
    for line in out.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        msg = rec.get("MESSAGE")
        if isinstance(msg, list):
            msg = bytes(msg).decode("utf-8", "replace")
        if isinstance(msg, str):
            try:
                ts = int(rec.get("__REALTIME_TIMESTAMP", 0)) / 1e6
            except (TypeError, ValueError):
                ts = 0.0
            records.append((ts, msg))
        last = rec.get("__CURSOR") or last
    problem = ""
    if code != 0 and not records:
        problem = f"journalctl -k exited {code}"
        if cursor:
            last = None
    return records, last, problem


def boot_endings(run=_run):
    """{boot_id: "clean"|"unclean"} for previous boots, and a problem."""
    code, out = run(["journalctl", "--list-boots", "-o", "json", "--no-pager"], timeout=30)
    if code is None or code != 0:
        return {}, ("" if out == "missing" else f"journalctl --list-boots: {out or code}")
    try:
        boots = json.loads(out or "[]")
    except ValueError:
        return {}, "journalctl --list-boots gave no JSON"
    if not isinstance(boots, list):
        return {}, ""
    result = {}
    for b in boots[:-1][-5:]:                      # previous boots only, the last five
        bid = b.get("boot_id") or ""
        if not bid:
            continue
        # Root's records only (_UID is written by journald): the clean-shutdown
        # markers come from systemd and journald, and `logger "Journal stopped"`
        # from any account must not turn a crashed boot into a clean one (FZ-04's rule).
        _c, tail = run(["journalctl", "-b", bid, "-n", "60", "-o", "cat", "--no-pager", "_UID=0"], timeout=30)
        result[bid] = "clean" if any(s in (tail or "") for s in CLEAN_END) else "unclean"
    if len(boots) <= 1 and not os.path.isdir("/var/log/journal"):
        return result, "only the current boot is in the journal (it is not persistent): earlier crashes are not visible"
    return result, ""


def audit(store, hosts=None, now=None, root="/", run=_run, cert_reader=cert_expiry):
    now = time.time() if now is None else now
    out, problems = [], []
    try:
        state = json.loads(store.get_meta(STATE_META, "") or "{}")
        if not isinstance(state, dict):
            raise ValueError
    except (ValueError, TypeError):
        state = {}
        problems.append("stored state could not be read; starting again")

    f, p = failed_units(run)
    out += f
    if p:
        problems.append(p)
    f, p = cert_findings(now, root, cert_reader)
    out += f
    problems += p

    records, cursor, p = read_kernel(state.get("cursor"), run)
    if p:
        problems.append(p)
    events = [e for e in state.get("events", []) if isinstance(e, dict) and now - e.get("ts", 0) <= KEEP_S]
    for ts, msg in records:
        m = OOM_RE.search(msg)
        if m:
            events.append({"ts": ts, "kind": "oom", "pid": int(m.group(1)), "comm": m.group(2)})

    endings, p = boot_endings(run)
    if p:
        problems.append(p)
    known = state.get("boots") or {}
    for bid, how in endings.items():
        if bid not in known and how == "unclean" and state.get("boots") is not None:
            events.append({"ts": now, "kind": "unclean", "boot": bid})
    known.update(endings)
    state = {"cursor": cursor, "boots": dict(list(known.items())[-50:]), "events": events[-MAX_EVENTS:]}
    store.set_meta(STATE_META, json.dumps(state))

    ooms = [e for e in state["events"] if e["kind"] == "oom"]
    if ooms:
        names = sorted({e["comm"] for e in ooms})
        out.append(_finding("operations", "high", f"the kernel killed {len(ooms)} process(es) for memory",
                            "in the last day: " + ", ".join(names[:MAX_LISTED])
                            + (" …" if len(names) > MAX_LISTED else "")
                            + "; the server ran out of memory", "kernel OOM killer"))
    for e in state["events"]:
        if e["kind"] == "unclean":
            # medium until validated on real servers: the ending is inferred from the
            # last journal lines (Jev 2026-10-29: 0.76 that this can misfire).
            out.append(_finding("operations", "medium", "the server went down without shutting down",
                                f"boot {e['boot'][:12]} ended with no clean shutdown: power loss, kernel panic, "
                                "a hard reset or a hypervisor stop",
                                # One identity per boot (category+title+where): with a shared
                                # "journal", three crashes merged into one alert and one ack.
                                f"journal boot {e['boot'][:12]}"))
    if problems:
        out.append(_finding("visibility", "medium", "server operations not fully observed",
                            "; ".join(problems)[:1500], "opshealth"))
    return out
