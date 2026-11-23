"""Findings you have confirmed as expected: "that was me".

A detection JARVIS cannot judge (a sandbox account a tool created, an updater
that injects a thread) stays in "Needs you — confirm" until someone decides.
Acknowledging records that decision and suppresses repeated email attention.
The security score charges an accepted finding as low (owner decision
2026-09-25); everything below is what keeps that from hiding a change.

What an acknowledgement is not:

  * permanent — it expires (90 days by default) and must be renewed;
  * unconditional — it is bound to the finding's identity (the same key
    alerting uses) and to the severity it had when acknowledged; if the same
    finding comes back worse, the acknowledgement no longer applies;
  * silent — every acknowledgement carries a reason, the dashboard still lists
    the finding, and `jarvis ack list` shows every one with its expiry.

Monitoring outages cannot be acknowledged: JARVIS being blind is never
"expected".

A critical finding needs a confirmation the local API cannot give. The API is
reachable by any program that can read the token, so a "yes" arriving there
must not be able to silence the worst findings (PRODUCTION-READINESS-2026-11-02
blocker 1). `acknowledge` refuses a critical finding unless the caller names
how the person confirmed it (`confirmed_by`), and an acknowledgement of a
critical finding that carries no such record does not apply. The only caller
that supplies one today is the command line after an interactive, typed
confirmation.

Limit, stated: on an install where the daemon runs as the person's own
account, a program running as that account can write the store directly and
forge the record. The gate is a wall only where the store belongs to a
separate service account.
"""

import hashlib
import json
import time

from jarvis.response import alert

META = "acknowledged_v1"
DEFAULT_DAYS = 90
# Findings about the guard itself, its evidence, or its own blindness can never
# be waved away by the account an intruder would hold (PROTECTION-REVIEW C1).
UNACKNOWLEDGEABLE = ("daemon", "collectors", "tamper", "tampering", "visibility")
# Severities whose acknowledgement needs a confirmation made outside the local API.
CONFIRM_SEVERITIES = ("critical",)
TERMINAL = "terminal"
CONFIRMERS = (TERMINAL,)


class ConfirmationRequired(ValueError):
    """A critical finding was offered for acknowledgement without a confirmation."""


def needs_confirmation(finding):
    return (finding or {}).get("severity") in CONFIRM_SEVERITIES


def finding_id(finding, job):
    """Short stable id for a finding, as printed in emails and the CLI.

    Built from the alert identity plus the detail (volatile parts removed):
    two findings that share a title and location but describe different
    things — two autostart entries under the same key — get different ids, so
    confirming one never silently confirms the other.
    """
    f = finding or {}
    key = f"{job}|{alert.finding_key(f)}|{alert.stable_text(f.get('detail'))}"
    return hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:8]


def load(store):
    try:
        value = json.loads(store.get_meta(META, "{}") or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def _save(store, acks):
    store.set_meta(META, json.dumps(acks, sort_keys=True))


def can_acknowledge(finding):
    f = finding or {}
    return (f.get("category") not in UNACKNOWLEDGEABLE and not alert.is_outage(f)
            and f.get("severity") not in (None, "ok"))


def is_acknowledged(acks, finding, job, now=None):
    """True while a live acknowledgement covers this finding at this severity."""
    entry = acks.get(finding_id(finding, job))
    if not entry or not can_acknowledge(finding):
        return False
    now = int(time.time() if now is None else now)
    if now >= int(entry.get("expires", 0)):
        return False
    if needs_confirmation(finding) and entry.get("confirmed_by") not in CONFIRMERS:
        return False
    worse = (alert.SEV_RANK.get(finding.get("severity"), 9)
             < alert.SEV_RANK.get(entry.get("severity"), 9))
    return not worse


def awaiting_confirmation(entry):
    """True for a stored acknowledgement of a critical finding that no longer applies
    because nobody confirmed it outside the API (for example one made before the gate)."""
    e = entry or {}
    return e.get("severity") in CONFIRM_SEVERITIES and e.get("confirmed_by") not in CONFIRMERS


def acknowledge(store, finding, job, reason, days=DEFAULT_DAYS, now=None, confirmed_by=None):
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("a reason is required")
    if not can_acknowledge(finding):
        raise ValueError("monitoring outages and clean checks cannot be acknowledged")
    if not 1 <= int(days) <= 365:
        raise ValueError("days must be between 1 and 365")
    if confirmed_by is not None and confirmed_by not in CONFIRMERS:
        raise ValueError("unknown confirmation")
    if needs_confirmation(finding) and confirmed_by is None:
        raise ConfirmationRequired("a critical finding must be confirmed at this computer, in a terminal")
    now = int(time.time() if now is None else now)
    acks = load(store)
    fid = finding_id(finding, job)
    acks[fid] = {"job": job, "key": alert.finding_key(finding), "title": finding.get("title", ""),
                 "severity": finding.get("severity"), "reason": reason[:300],
                 "at": now, "expires": now + int(days) * 86400}
    if confirmed_by is not None:
        acks[fid]["confirmed_by"] = confirmed_by
    _save(store, acks)
    return fid, acks[fid]


def revoke(store, fid):
    acks = load(store)
    entry = acks.pop(fid, None)
    _save(store, acks)
    return entry


def prune(store, now=None):
    """Drop expired acknowledgements; returns how many were removed."""
    now = int(time.time() if now is None else now)
    acks = load(store)
    live = {k: v for k, v in acks.items() if int(v.get("expires", 0)) > now}
    if len(live) != len(acks):
        _save(store, live)
    return len(acks) - len(live)


def resolve(snapshots, fid):
    """(finding, job) in the latest snapshots whose id is `fid`, else None."""
    for job, snap in (snapshots or {}).items():
        for f in (snap or {}).get("findings") or ():
            if isinstance(f, dict) and f.get("severity") != "ok" and finding_id(f, job) == fid:
                return f, job
    return None
