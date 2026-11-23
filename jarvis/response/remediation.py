"""Bounded repair before notification. Findings never become shell commands.

Only fixed operations are executable. A successful exit is not resolution:
the owning collector must complete a fresh observation without the finding.
"""
import json
import subprocess
import time

from jarvis.core import collection
from jarvis.core.paths import win_script
from jarvis.platform.windows import ps_json

from .alert import finding_key

META = 'automatic_repairs_v1'
COOLDOWN = 3600
WINDOW = 86400
MAX_ATTEMPTS = 3


def audit(store, now=None):
    """Return a redacted summary of the durable bounded-repair ledger."""
    now = int(time.time() if now is None else now)
    try:
        records = json.loads(store.get_meta(META, '{}') or '{}')
        if not isinstance(records, dict):
            raise ValueError('invalid repair state')
    except (ValueError, TypeError, AttributeError):
        return {"status": "unavailable", "reason": "repair history unreadable",
                "actions": [], "verified": 0, "failed": 0, "blocked": 0}
    actions = []
    def _timestamp(value):
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0
    for action, record in sorted(records.items()):
        if not isinstance(record, dict):
            continue
        status = record.get('status')
        if status not in ('attempting', 'verified', 'failed', 'blocked'):
            status = 'unknown'
        actions.append({"action": str(action)[:80], "status": status,
                        "job": str(record.get('job', ''))[:80],
                        "at": _timestamp(record.get('at')),
                        "verified_at": _timestamp(record.get('verified_at')),
                        "attempts_24h": sum(
                            now - _timestamp(ts) < WINDOW
                            for ts in record.get('attempts', [])
                            if isinstance(ts, (int, float)))})
    return {"status": "active", "actions": actions,
            "verified": sum(row["status"] == "verified" for row in actions),
            "failed": sum(row["status"] == "failed" for row in actions),
            "blocked": sum(row["status"] == "blocked" for row in actions)}


def action_for(job, finding):
    identity = (job, finding.get('category'), finding.get('title'))
    if identity == ('sysmon_linux', 'sysmon-linux',
                    'Sysmon for Linux is installed but stopped'):
        return 'telemetry'
    if (job in ('bridge', 'coverage') and finding.get('category') == 'collectors'
            and finding.get('title') == 'the Windows side is blind — interop bridge is down'):
        return 'mount'
    if (identity == ('firewall', 'rules', 'permissive inbound rule')
            and finding.get('host') == 'win'
            and 'orphaned rule' in finding.get('detail', '')):
        return 'orphan_firewall'
    return ''


def execute(action):
    if action == 'orphan_firewall':
        script = win_script('repair_orphan_firewall.ps1').read_text()
        result = ps_json(script, timeout=30)
        return bool(isinstance(result, dict) and result.get('ok') is True)
    if action not in ('telemetry', 'mount'):
        return False
    try:
        result = subprocess.run(
            ['/usr/bin/sudo', '-n', '/usr/local/sbin/jarvis-repair', action],
            capture_output=True, timeout=45, cwd='/')
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def process(store, conf, job, findings, error, collect):
    """Return findings/error for persistence and alerts; retain failed evidence."""
    if conf.get('auto_remediate', True) is False or error:
        return findings, error
    candidates = [f for f in findings if action_for(job, f)]
    if not candidates:
        return findings, error
    action = action_for(job, candidates[0])  # one bounded operation per pass
    targets = [f for f in candidates if action_for(job, f) == action]
    keys = {finding_key(f) for f in targets}
    now = int(time.time())
    try:
        records = json.loads(store.get_meta(META, '{}'))
        if not isinstance(records, dict):
            raise ValueError('invalid repair state')
        record = records.get(action, {})
        attempts = [int(t) for t in record.get('attempts', []) if now - int(t) < WINDOW]
    except (ValueError, TypeError, AttributeError):
        return _annotate(findings, keys, 'blocked', 'Repair history is unreadable; needs review.'), error
    if attempts and (now - max(attempts) < COOLDOWN or len(attempts) >= MAX_ATTEMPTS):
        return _annotate(findings, keys, 'blocked',
                         'Automatic repair retry limit reached; finding still needs attention.'), error
    record = {'attempts': attempts + [now], 'status': 'attempting', 'job': job,
              'at': now, 'finding_keys': sorted(keys)}
    records[action] = record
    store.set_meta(META, json.dumps(records))  # crash counts as an attempt
    reason = 'Automatic repair failed or lacks permission; manual attention required.'
    status = 'failed'
    try:
        if execute(action):
            with collection.observe() as observation:
                fresh = list(collect())
            # Coverage loss must never be mistaken for a successful repair.
            unavailable = any(f.get('category') in ('collectors', 'visibility')
                              and f.get('severity') != 'ok' for f in fresh)
            remaining = keys & {finding_key(f) for f in fresh}
            positive = (action == 'orphan_firewall' or
                        any(f.get('severity') == 'ok' and (
                            (action == 'telemetry' and f.get('category') == 'telemetry') or
                            (action == 'mount' and f.get('title') == 'Windows bridge is up'))
                            for f in fresh))
            if not observation.error and not unavailable and not remaining and positive:
                status = 'verified'
                reason = 'Repair completed and the owning collector verified the finding is absent.'
                findings = fresh
            else:
                reason = 'Repair attempted, but a complete fresh scan did not verify resolution.'
                # Retain original evidence and any newly discovered threats.
                merged = {finding_key(f): f for f in findings}
                merged.update({finding_key(f): f for f in fresh})
                findings = list(merged.values())
                error = observation.error or ('repair verification incomplete' if unavailable else '')
        record.update(status=status, reason=reason, verified_at=now if status == 'verified' else 0)
    except Exception as exc:
        reason = 'Automatic repair or verification failed (' + type(exc).__name__ + '); needs attention.'
        record.update(status='failed', reason=reason)
    store.set_meta(META, json.dumps(records))
    return _annotate(findings, keys, status, reason), error


def _annotate(findings, keys, status, reason):
    return [{**f, 'remediation': {'status': status, 'reason': reason}}
            if finding_key(f) in keys else f for f in findings]
