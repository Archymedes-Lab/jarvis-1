"""Outbound alerts by email, through Resend.

Everything else in jarvis stays on the machine. This is the one component that
reaches the network on its own, and only when you have put a Resend API key and
a recipient in ~/.jarvis/config.json — with neither, it is inert. It exists so
that "jarvis stopped recording" reaches you when you are not looking at the
dashboard.

Config, all under ~/.jarvis/config.json (kept 0600), or the noted env var:

    resend_api_key      "re_..."            (or $JARVIS_RESEND_KEY)
    alert_to            "you@example.com"   or ["a@x.com", "b@y.com"]
    alert_from          "JARVIS <jarvis@yourdomain.com>"  a verified sender
    alert_min_severity  "high"              critical | high | medium
    alert_digest_interval 3600             group ordinary changes for an hour
    alert_on_clear      true                include recoveries in the digest
    alert_hourly_cap    12                  transport ceiling; unsent work stays queued
    report_hour         9                   daily advisory, host local time
    alert_send_attempts 5                   transport retries per email

Other channels (ARGUS-SERVER.md W4), each optional and independent:

    webhook_url         "https://..."        JSON POST; Slack/Discord-compatible text
    webhook_secret      "..."                HMAC-SHA256 signature in X-Argus-Signature
    ntfy_url            "https://ntfy.sh/your-topic"   push to a phone
    ntfy_token          "tk_..."             for a protected topic
    syslog              true                 one line per alert to /dev/log; counts as
                                             a channel only while a log forwarder runs
    notify_url          "https://argus.archymedes.xyz"  sealed phone notifications
                                             (ARGUS-NOTIFY.md); a channel once a phone is
                                             paired with `notify pair`
    notify_label        "web-1"              the name phones show for this server

Off-box liveness (ARGUS-SERVER.md W10, service/heartbeat.py), not an alert channel:

    heartbeat_url       "https://hc-ping.com/<uuid>"   one GET a minute to a dead-man
                                             service; it alerts when the pings stop

Critical findings and monitoring outages send immediately. Other findings
must survive a second observation and are grouped into an hourly change digest.
Unchanged findings escalate once per age threshold, never via periodic STILL
mail. Notification state and pending delivery survive process restarts.
"""

import hashlib
import hmac
import json
import os
import random
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from jarvis.core import brand
from jarvis.response import categories

CONFIG_PATH = os.path.expanduser("~/.jarvis/config.json")
API_URL = "https://api.resend.com/emails"

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

# Transport retries. One outage mail is worth several attempts: the network
# path this alert travels is frequently the same one that just broke.
SEND_ATTEMPTS = 5
SEND_BACKOFF_BASE = 2.0
SEND_BACKOFF_CAP = 30.0

# Outages re-page far more often than ordinary findings. "The monitor is not
# watching" is not information you want delivered once and then filed; every
# hour it stays down is another hour of nothing being recorded.
OUTAGE_RESEND = 900          # 15 minutes, overridable per config

# An hour of an unfixed outage should escalate, not fade. Repeat intervals grow
# only up to this, so a long outage keeps pinging rather than going quiet.
OUTAGE_RESEND_CAP = 3600

# The hourly ceiling that applies to outage mail. Deliberately far above the
# ordinary cap: the ordinary cap protects an inbox from a flapping collector,
# but nothing may be allowed to suppress "the monitor is not watching". This
# only exists so a genuine runaway cannot burn a Resend quota to zero.
OUTAGE_HOURLY_CAP = 60


def parse_int(v, default):
    """int() with a default for None / "" / junk — but 0 is kept as 0."""
    if v is None or v == "":
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

# Substrings that mark a finding as "jarvis itself is not watching something".
# These page regardless of alert_min_severity, because a monitoring gap is the
# one class of finding whose whole point is that nothing else will tell you.
_OUTAGE_MARKERS = (
    "not running", "not recording", "is down", "was down", "stopped reporting",
    "has stopped", "cannot be restarted", "could not restart", "keeps dying",
    "has restarted", "is stale", "has never produced", "is failing",
    "heartbeat is overdue", "hook has stopped", "interop bridge",
    "outside the desktop session", "saw no keyboard", "cannot be started",
)
_OUTAGE_CATEGORIES = ("input", "collectors", "daemon")

STATE_META = "alert_state"       # json: {key: {first, last_sent, count, sev}}
SENT_LOG_META = "alert_sent_log"  # json: [ts, ...] emails actually sent, last hour


# ── config ──────────────────────────────────────────────────────────────────

def load_conf():
    conf = {}
    try:
        with open(CONFIG_PATH, errors="replace") as fh:
            conf = json.load(fh) or {}
    except (OSError, ValueError):
        conf = {}
    env = os.environ.get("JARVIS_RESEND_KEY", "").strip()
    if env:
        conf["resend_api_key"] = env
    return conf


def recipients(conf):
    to = conf.get("alert_to") or []
    if isinstance(to, str):
        to = [x.strip() for x in to.replace(";", ",").split(",")]
    return [x for x in to if x]


def email_enabled(conf):
    return bool((conf.get("resend_api_key") or "").strip()
                and (conf.get("alert_from") or "").strip()
                and recipients(conf))


# Programs that ship the local log somewhere a person reads it. A syslog line
# with none of them running reaches no one, so it is not a channel.
LOG_FORWARDERS = ("rsyslogd", "syslog-ng", "vector", "fluent-bit", "td-agent-bit", "fluentd",
                  "promtail", "alloy", "filebeat", "elastic-agent", "otelcol", "otelcol-contrib",
                  "nxlog", "splunkd", "wazuh-agentd", "datadog-agent", "journal-upload",
                  "systemd-journal-upload", "systemd-journal-remote")


def log_forwarder(proc="/proc"):
    """The name of a running log forwarder, or ""."""
    try:
        pids = [d for d in os.listdir(proc) if d.isdigit()]
    except OSError:
        return ""
    for pid in pids:
        try:
            with open(f"{proc}/{pid}/comm", errors="replace") as fh:
                comm = fh.read().strip()
        except OSError:
            continue
        if comm in LOG_FORWARDERS or comm.startswith("otelcol"):
            return comm
    return ""


def _https(url):
    try:
        u = urllib.parse.urlsplit((url or "").strip())
    except ValueError:
        return False
    return u.scheme == "https" and bool(u.hostname)


def channels(conf, forwarder=None):
    """Names of the channels that can reach the owner, in delivery order."""
    out = []
    if email_enabled(conf):
        out.append("email")
    if _https(conf.get("webhook_url")):
        out.append("webhook")
    if _https(conf.get("ntfy_url")):
        out.append("ntfy")
    if conf.get("syslog") is True:
        if (log_forwarder() if forwarder is None else forwarder):
            out.append("syslog")
    from jarvis.response.notify import channel as notify_channel
    if notify_channel.ready(conf):
        out.append("notify")
    return out


def enabled(conf):
    """True when at least one channel can reach the owner."""
    return bool(channels(conf))


def channel_findings(conf=None):
    """A finding that stays critical while no outbound channel can page you.

    Detection without delivery is a log. The desktop toast still fires for
    criticals, but it lives in the user's own session and can be muted there,
    so an unconfigured or paused mail path is reported at critical and is not
    acknowledgeable (category `daemon`)."""
    conf = load_conf() if conf is None else conf
    if enabled(conf):
        return []
    missing = [name for name, ok in (("key", bool((conf.get("resend_api_key") or "").strip())),
                                     ("sender", bool((conf.get("alert_from") or "").strip())),
                                     ("recipient", bool(recipients(conf)))) if not ok]
    syslog_note = (" syslog is on, but no log forwarder is running, so a log line would "
                   "reach no one." if conf.get("syslog") is True else "")
    return [{"category": "daemon", "severity": "critical", "host": "wsl",
             "title": "no alert channel can reach you",
             "detail": "email alerting is not configured (missing: " + ", ".join(missing)
                       + "), and no webhook_url or ntfy_url (https) is set." + syslog_note
                       + " Critical findings reach only the dashboard and a desktop toast "
                         "that your own session can mute. Configure a channel in "
                         "~/.jarvis/config.json (`jarvis alert --help`).",
             "where": "~/.jarvis/config.json"}]


def branded_sender(conf):
    """Keep the configured verified address while presenting the JARVIS name."""
    sender = (conf.get("alert_from") or "").strip()
    match = re.search(r"<([^<>]+)>", sender)
    address = match.group(1).strip() if match else sender
    return f"JARVIS <{address}>"


def status(store):
    """A dict for `jarvis alert` to print — never includes the key itself."""
    conf = load_conf()
    try:
        state = json.loads(store.get_meta(STATE_META, "{}") or "{}")
    except ValueError:
        state = {}
    return {
        "enabled": enabled(conf),
        "channels": channels(conf),
        "have_key": bool((conf.get("resend_api_key") or "").strip()),
        "from": conf.get("alert_from", ""),
        "to": recipients(conf),
        "min_severity": conf.get("alert_min_severity", "high"),
        "digest_interval": max(60, parse_int(conf.get("alert_digest_interval"), 3600)),
        "resend_after": 0,
        "outage_resend_after": max(60, parse_int(
            conf.get("alert_outage_resend_after"), OUTAGE_RESEND)),
        "on_clear": conf.get("alert_on_clear", True) is not False,
        "hourly_cap": max(0, parse_int(conf.get("alert_hourly_cap"), 12)),
        "outage_hourly_cap": OUTAGE_HOURLY_CAP,
        "send_attempts": max(1, parse_int(conf.get("alert_send_attempts"),
                                     SEND_ATTEMPTS)),
        "active": sorted(state.keys()),
        "outages": sorted(k for k, v in state.items() if v.get("outage")),
        "sent_last_hour": len(recent_sends(store)),
        "last_ok": int(store.get_meta("alert_last_ok", 0) or 0),
        "report_last_ok": int(store.get_meta(REPORT_OK_META, 0) or 0),
        "report_last_error": store.get_meta(REPORT_ERROR_META, "") or "",
        "advisory_model": conf.get("advisory_model", "") or "",
        "advisory_ai": bool((os.environ.get("JARVIS_OPENAI_KEY", "").strip() or
                             (conf.get("openai_api_key") or "").strip()) and
                            (conf.get("advisory_model") or "").strip()),
        "last_error": store.get_meta("alert_last_error", "") or "",
        "capped_at": int(store.get_meta("alert_capped_at", 0) or 0),
    }


# ── transport ───────────────────────────────────────────────────────────────

def send_email(conf, subject, text, html=None, category=None):
    """POST one email to Resend. Returns "" on success, else an error string.

    The API key goes only in the Authorization header of this one request to
    api.resend.com, over TLS with verification on. It is never logged.
    """
    key = (conf.get("resend_api_key") or "").strip()
    message = {
        "from": branded_sender(conf),
        "to": recipients(conf),
        "subject": _filed(subject, category)[:200],
        "text": text,
    }
    if category:
        # A header mail filters can sort on without parsing the subject.
        message["headers"] = {"X-Argus-Category": category}
    if html:
        message["html"] = html
    payload = json.dumps(message).encode()
    ctx = ssl.create_default_context()
    attempts = max(1, parse_int(conf.get("alert_send_attempts"), SEND_ATTEMPTS))
    last = "no attempt was made"

    for i in range(attempts):
        if i:
            # Full jitter on an exponential backoff. JARVIS's outage mail and a
            # transient DNS or TLS failure must not become a tight retry loop
            # against api.resend.com — that is how a key gets rate-limited
            # exactly when it is needed.
            time.sleep(min(SEND_BACKOFF_CAP,
                           SEND_BACKOFF_BASE * (2 ** (i - 1)))
                       * (0.5 + random.random() / 2))
        req = urllib.request.Request(API_URL, data=payload, method="POST")
        req.add_header("Authorization", f"Bearer {key}")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        # api.resend.com sits behind Cloudflare, which blocks the default
        # "Python-urllib/x.y" agent with a 403 (error 1010). Any real UA is fine.
        req.add_header("User-Agent", "jarvis-monitor/1.0 (+https://github.com)")
        try:
            with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
                if resp.status in (200, 201):
                    return ""
                last = f"Resend returned HTTP {resp.status}"
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = json.loads(exc.read().decode()).get("message", "")
            except Exception:
                pass
            last = f"Resend HTTP {exc.code}: {detail or exc.reason}"
            # 4xx other than 408/429 is a permanent problem with the request
            # itself — a bad key, an unverified sender. Retrying cannot fix it
            # and only burns the rate limit.
            if 400 <= exc.code < 500 and exc.code not in (408, 429):
                return last
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last = f"could not reach Resend: {exc}"

    return f"{last} (after {attempts} attempts)"


def _post(url, body, headers, attempts=3, timeout=15, label="channel"):
    """POST with retries; "" on 2xx, else an error that never contains the URL
    (webhook URLs often embed their secret)."""
    ctx = ssl.create_default_context()
    last = "no attempt was made"
    for i in range(attempts):
        if i:
            time.sleep(min(SEND_BACKOFF_CAP, SEND_BACKOFF_BASE * (2 ** (i - 1))) * (0.5 + random.random() / 2))
        req = urllib.request.Request(url, data=body, method="POST")
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if 200 <= resp.status < 300:
                    return ""
                last = f"{label} returned HTTP {resp.status}"
        except urllib.error.HTTPError as exc:
            last = f"{label} HTTP {exc.code}"
            if 400 <= exc.code < 500 and exc.code not in (408, 429):
                return last
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last = f"could not reach the {label}: {type(exc).__name__}"
    return f"{last} (after {attempts} attempts)"


def _priority(subject):
    low = (subject or "").lower()
    return "critical" if "critical" in low or "down" in low or "not watching" in low else "high"


def send_webhook(conf, subject, text, now=None, category=None, severity=None):
    ts = int(time.time() if now is None else now)
    payload = {"source": "argus", "host": socket.gethostname(), "ts": ts, "subject": subject[:200],
               "category": category or "system", "category_label": categories.label(category or "system"),
               "priority": severity or _priority(subject), "text": f"*{subject[:200]}*\n{text[:3500]}",
               "content": f"**{subject[:200]}**\n{text[:1800]}", "body": text[:60000]}
    body = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "argus-monitor/1.0",
               "X-Argus-Timestamp": str(ts)}
    secret = (conf.get("webhook_secret") or "").strip()
    if secret:
        sig = hmac.new(secret.encode(), str(ts).encode() + b"." + body, hashlib.sha256).hexdigest()
        headers["X-Argus-Signature"] = "sha256=" + sig
    return _post(conf["webhook_url"].strip(), body, headers, label="webhook")


def _ascii(text, limit):
    return (text or "").encode("ascii", "replace").decode()[:limit]


def send_ntfy(conf, subject, text, category=None, severity=None):
    prio = severity or _priority(subject)
    headers = {"Title": _ascii(_filed(subject, category), 200),
               "Priority": "5" if prio == "critical" else "4" if prio == "high" else "3",
               "Tags": ("rotating_light" if prio == "critical" else "warning") + f",{category or 'system'}",
               "User-Agent": "argus-monitor/1.0", "Content-Type": "text/plain; charset=utf-8"}
    token = (conf.get("ntfy_token") or "").strip()
    if token:
        headers["Authorization"] = "Bearer " + token
    # ntfy caps a message at 4 KiB; longer bodies become attachments it may refuse.
    return _post(conf["ntfy_url"].strip(), text.encode()[:3900], headers, label="ntfy server")


SYSLOG_SOCKET = "/dev/log"


def send_syslog(subject, text, path=SYSLOG_SOCKET, category=None, severity=None):
    """One RFC 3164-style line to the local syslog socket (journald reads it)."""
    prio = severity or _priority(subject)
    pri = 3 * 8 + (2 if prio == "critical" else 3)          # daemon.crit / daemon.err
    line = " ".join((f"[{category or 'system'}] " + subject + " | " + text).split())[:1800]
    msg = f"<{pri}>argus[{os.getpid()}]: {line}".encode("utf-8", "replace")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(path)
            s.send(msg)
        return ""
    except OSError as exc:
        return f"syslog socket: {exc.strerror or type(exc).__name__}"


def deliver(conf, subject, text, html=None, only=None, senders=None, category=None,
            severity=None, counts=None):
    """Send one alert on every configured channel, each independently (I8).

    `category` (response/categories.py) files the message on every channel:
    email subject and header, webhook field, ntfy tag, syslog prefix, phone
    payload. A caller that names none is the monitor talking about itself.
    Returns "" when at least one channel delivered, else every channel's error.
    A failing channel never stops another. `senders` exists for tests."""
    names = [c for c in channels(conf) if only is None or c in only]
    if not names:
        return "no alert channel is configured"
    category = category if category in categories.LABELS else "system"
    # Everything that leaves the machine says ARGUS-INSTINCT (core/brand.py); the
    # findings behind it keep their identity.
    subject, text = brand.brand(subject), brand.brand(text)
    html = brand.brand(html) if html else html
    senders = senders or {
        "email": lambda: send_email(conf, subject, text, html=html, category=category),
        "webhook": lambda: send_webhook(conf, subject, text, category=category, severity=severity),
        "ntfy": lambda: send_ntfy(conf, subject, text, category=category, severity=severity),
        "syslog": lambda: send_syslog(subject, text, category=category, severity=severity),
        "notify": lambda: _send_notify(conf, subject, text, category=category, severity=severity,
                                       counts=counts),
    }
    errors, delivered = [], 0
    for name in names:
        try:
            err = senders[name]()
        except Exception as exc:  # noqa: BLE001 - one channel's bug must not silence the others
            err = f"{type(exc).__name__}"
        if err:
            errors.append(f"{name}: {err}")
        else:
            delivered += 1
    LAST_DELIVERY.clear()
    LAST_DELIVERY.update({"channels": names, "delivered": delivered, "errors": errors})
    return "" if delivered else "; ".join(errors)


LAST_DELIVERY: dict = {}


def _send_notify(conf, subject, text, category=None, severity=None, counts=None):
    from jarvis.response.notify import channel as notify_channel
    return notify_channel.send(conf, subject, text, severity=severity or _priority(subject),
                               category=category, counts=counts)


def _filed(subject, category):
    """The subject with its category in front, once."""
    if not category:
        return subject
    tag = f"[{categories.label(category)}]"
    return subject if subject.startswith(tag) else f"{tag} {subject}"


TEST_SUBJECT = "[ARGUS-INSTINCT] Test message: warnings can reach you"
TEST_TEXT = ("This is a test message you asked for (jarvis alert --test). Nothing to do.\n"
             "If it reached you, warnings about this computer, including when ARGUS-INSTINCT "
             "stops watching it, will reach you here too.\n")


def test(store):
    conf = load_conf()
    if not enabled(conf):
        return "alerts are not configured — set an email (resend_api_key, alert_from, " \
               "alert_to), webhook_url or ntfy_url in " + CONFIG_PATH
    err = deliver(conf, TEST_SUBJECT, TEST_TEXT, category="test", severity="low")
    if not err:
        record_send(store)
    return err


# ── periodic whole-system advisory (store keys; the report itself is
#    response/reporting/advisory.py) ─────────────────────────────────────────

REPORT_OK_META = "advisory_report_last_ok"
REPORT_ERROR_META = "advisory_report_last_error"


# ── dispatch ────────────────────────────────────────────────────────────────

# Categories whose findings are inherently per-PID / per-connection churn. They
# belong on the dashboard, not in an inbox — a genuinely dangerous process
# still pages through sysmon / hunt / intrusion with a stable title.
# "ledger" is here for a structural reason, not a preference one. Its findings
# are *about* alerts that were already emailed. If they paged, an unresolved
# HIGH would generate a ledger HIGH, which would be mailed, which would be
# recorded in the ledger as another unresolved alert, which would page. The
# backlog belongs in the advisory report and on the dashboard, where it is read
# deliberately rather than pushed.
NOPAGE_CATEGORIES = {"process", "peer", "coverage gap", "not observable",
                      "ledger"}

# Findings about Argus's own detection coverage against current intel (the
# `gaps` job): "nothing here checks T1001" is a statement about the tool, not
# an observation about the machine. They belong in the coverage view
# (/api/coverage "intel_gaps"), never in the machine's findings list, its
# severity totals, the pulse's urgent list or autopilot investigations
# (QC-ARGUS-1-2026-10-27 blocker 3; docs/security/ALERT-QUALITY-2026-11-08.md).
# They are moved, not dropped: every one stays listed there with its priority.
COVERAGE_CATEGORIES = frozenset({"coverage gap", "not observable", "not applicable"})


def is_coverage_gap(f):
    """True for a finding about Argus's detection coverage, not about the machine."""
    return isinstance(f, dict) and f.get("category") in COVERAGE_CATEGORIES

# Volatile tokens that must not be part of a dedupe key, or every occurrence is
# a "new" alert: pids, the NEW marker, repeat counts, long hex/base64 blobs,
# and the timestamped names in Claude Code's shell snapshots.
_VOLATILE = re.compile(
    r"\[pid \d+\]|\bpid[= ]\d+|—\s*NEW\b|\(×\d+\)|\bsnapshot-\w+-\d+[-\w]*|"
    r"\b[0-9a-f]{16,}\b|\b\d{10,}\b")


# Detail text also carries clock times and sighting counters that change on
# every observation; an identity built from detail must ignore them.
_VOLATILE_DETAIL = re.compile(
    r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?(\.\d+)?|\[(?:last )?seen[^\]]*\]|"
    r"\bseen \d+×|\b\d+ (?:times|events|sampled)\b")


def stable_text(text):
    """Text with pids, counters, long hex, clock times and sighting counts removed."""
    return _VOLATILE.sub("", _VOLATILE_DETAIL.sub("", text or "")).strip(" -—|")


def finding_key(f):
    title = _VOLATILE.sub("", f.get("title", "")).strip(" -—|")
    return f"{f.get('category', '')}|{title}|{f.get('where', '')}"


# The full input audit and its watchdog cover the same ground; either may clear
# an alert the other raised. Every other job clears only its own.
#
# "bridge" and "coverage" both emit the identical Windows-bridge finding, so
# they share a dedupe key and never double-mail — but they are deliberately NOT
# given a shared domain: coverage raises other alerts of its own, and the
# bridge job (which reports nothing but the bridge) would then clear them all.
_DOMAIN = {"input": "input", "input_hook": "input"}


def same_domain(a, b):
    return _DOMAIN.get(a, a) == _DOMAIN.get(b, b)


def is_outage(f):
    if f.get("category") not in _OUTAGE_CATEGORIES:
        return False
    if SEV_RANK.get(f.get("severity"), 9) > SEV_RANK["medium"]:
        return False
    blob = (f.get("title", "") + " " + f.get("detail", "")).lower()
    return any(m in blob for m in _OUTAGE_MARKERS)


def recent_sends(store):
    try:
        log = [int(x) for x in json.loads(store.get_meta(SENT_LOG_META, "[]") or "[]")]
    except (ValueError, TypeError):
        log = []
    cutoff = int(time.time()) - 3600
    return [t for t in log if t >= cutoff]


def record_send(store):
    log = recent_sends(store)
    log.append(int(time.time()))
    store.set_meta(SENT_LOG_META, json.dumps(log[-100:]))
