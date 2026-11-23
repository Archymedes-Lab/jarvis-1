"""The observed server review: one report from a window of stored observation.

The paid offer chosen in PMF-2026-11.md is a one-week observed server review for
small agencies. This module turns what the daemon already recorded (each job's
latest snapshot and its run receipts in `defender_runs`) into one report the
client can read. It runs nothing and adds no collector.

Invariants (tests/test_review.py):
- Read-only and offline: the store is opened with SQLite `mode=ro`, never created
  or migrated; no network. A missing or unreadable store is refused, never
  rendered as an empty (clean-looking) report.
- Evidence continuity: every job behind the server edition's capabilities gets a
  section with an explicit state (observed, partial, stale, not observed). A job
  with no receipt in the window, a failed latest run, or a snapshot older than
  the window is never dropped and never shown as this window's evidence.
- Claims bounded by the register: coverage comes from `audience.first_run`; the
  report says it is not an audit or certification and that scores are not
  verdicts; hand-written text is checked against the overclaim and promise guards.
- Privacy: titles pass `privacy.redact` and a length cap; a detail that the
  redactor would change, or of a finding about secrets, is withheld entirely. The file is created owner-only,
  exclusively, without following a symlink.
- Bounded: window 1-31 days, at most MAX_FINDINGS per section, MAX_LINES lines.
"""

import json
import os
import socket
import sqlite3
import time

from jarvis.core import assurance, audience
from jarvis.response.privacy import redact

MIN_DAYS, MAX_DAYS, DEFAULT_DAYS = 1, 31, 7
MAX_FINDINGS = 40
MAX_TITLE = 160
MAX_DETAIL = 300
MAX_LINES = 900
SEVERITIES = ('critical', 'high', 'medium', 'low')
# A finding is about a secret *value* (and its detail may quote it) when its kind or
# category is a secrets one, or its title names a secret together with where it was
# found. A setting that merely mentions one ("PasswordAuthentication is enabled") is
# configuration, not a secret: its detail is shown, still subject to the redactor check.
SECRET_WORDS = ('secret', 'credential', 'password', 'private key', 'token', 'api key')
SECRET_KINDS = ('secret', 'secrets', 'credential', 'credentials', 'leak', 'leaks')
VALUE_WORDS = ('found', 'in repository', 'in repo', 'in file', 'in history', 'exposed', 'leaked',
               'committed', 'hard-coded', 'hardcoded', 'plain text', 'plaintext', 'readable by',
               'world-readable', 'in environment', 'in logs', 'in log', 'in config', 'stored in')

WITHHELD = ('detail withheld from this report: it may contain a secret; see it on the server '
            'itself')
NOT_AN_AUDIT = ('This is an observed review of what ARGUS-1 recorded on this server. It is not '
                'a security audit, a penetration test or a certification, and it does not say '
                'that this server is or is not compromised.')
STATE_WORDS = {
    'observed': 'observed in this window',
    'partial': 'ran in this window, but no run was complete',
    'stale': 'no run in this window; last findings are older and shown for reference only',
    'not_observed': 'not observed in this window',
}


class ReviewError(Exception):
    """The report cannot be produced honestly (no store, bad window)."""


def server_jobs(profile='server'):
    """[(capability, label, job)] for every job behind the edition's capabilities."""
    rows = []
    for cap, label in audience.PROFILES[profile]['capabilities']:
        for job in assurance.OBSERVATION_REQUIREMENTS.get(cap, ()):
            rows.append((cap, label, job))
    return rows


def open_readonly(db_path):
    """A read-only connection, or ReviewError. Never creates the file."""
    path = os.path.abspath(os.path.expanduser(db_path))
    if not os.path.isfile(path):
        raise ReviewError(f'no ARGUS-1 store at {path}; is the daemon installed and has it run?')
    try:
        conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute('SELECT 1 FROM snapshots LIMIT 1')
        conn.execute('SELECT 1 FROM defender_runs LIMIT 1')
    except sqlite3.Error as exc:
        raise ReviewError(f'the ARGUS-1 store cannot be read ({type(exc).__name__})') from exc
    return conn


def _is_secret(finding):
    kinds = {str(finding.get(k) or '').strip().lower() for k in ('kind', 'category')}
    if kinds & set(SECRET_KINDS):
        return True
    title = str(finding.get('title') or '').lower()
    return any(w in title for w in SECRET_WORDS) and any(v in title for v in VALUE_WORDS)


def _clip(text, limit):
    text = ' '.join(redact(str(text or '')).split())
    return text if len(text) <= limit else text[:limit - 1].rstrip() + '…'


def _finding(f):
    sev = f.get('severity') if f.get('severity') in SEVERITIES else 'low'
    row = {'severity': sev, 'title': _clip(f.get('title') or 'untitled finding', MAX_TITLE)}
    detail = ' '.join(str(f.get('detail') or '').split())
    if _is_secret(f):
        row['detail'] = WITHHELD
    elif detail and redact(detail) != detail:
        # Partly redacted text still hints at the value and its place (Jev review
        # 2026-11-02, redaction alone enough: 0.16): withhold the whole detail.
        row['detail'] = WITHHELD
    elif detail:
        row['detail'] = _clip(detail, MAX_DETAIL)
    return row


def _section(conn, cap, label, job, since, statement_status):
    runs = conn.execute(
        "SELECT coverage, COUNT(*) n, MAX(observed_at) last FROM defender_runs "
        "WHERE job=? AND observed_at>=? GROUP BY coverage", (job, since)).fetchall()
    counts = {r['coverage']: int(r['n']) for r in runs}
    last_run = max((r['last'] for r in runs), default=None)
    snap = conn.execute('SELECT ts, error, payload FROM snapshots WHERE kind=?', (job,)).fetchone()
    findings, snap_ts, snap_error = [], None, ''
    if snap is not None:
        snap_ts, snap_error = snap['ts'], (snap['error'] or '')
        try:
            payload = json.loads(snap['payload'])
        except ValueError:
            payload = None
        if not isinstance(payload, list):
            snap_error = snap_error or 'stored findings unreadable'
            payload = []
        findings = [_finding(f) for f in payload if isinstance(f, dict)]
    if counts.get('complete'):
        state = 'observed'
    elif counts:
        state = 'partial'
    elif snap is not None:
        state = 'stale'
    else:
        state = 'not_observed'
    if state in ('observed', 'partial') and snap_ts is not None and snap_ts < since:
        state = 'stale'            # receipts exist, but the stored findings predate the window
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f['severity']], f['title']))
    total = len(findings)
    return {
        'capability': cap, 'label': label, 'job': job, 'register': statement_status,
        'state': state, 'state_text': STATE_WORDS[state],
        'runs': {k: counts.get(k, 0) for k in ('complete', 'partial', 'unavailable')},
        'last_run': last_run, 'findings_at': snap_ts,
        'error': _clip(snap_error, 120) if snap_error else '',
        'finding_count': total, 'findings': findings[:MAX_FINDINGS],
        'truncated': max(0, total - MAX_FINDINGS),
    }


def build(db_path, days=DEFAULT_DAYS, now=None, host=None):
    """The review as a dict. Raises ReviewError."""
    if isinstance(days, bool) or not isinstance(days, int) or not MIN_DAYS <= days <= MAX_DAYS:
        raise ReviewError(f'the window must be {MIN_DAYS} to {MAX_DAYS} days')
    now = time.time() if now is None else float(now)
    since = now - days * 86400
    statement = audience.first_run('server')
    status = {r['capability']: r['status'] for r in statement['looks_at'] + statement['not_provided']}
    conn = open_readonly(db_path)
    try:
        sections = [_section(conn, cap, label, job, since, status.get(cap, audience.UNKNOWN_WORD))
                    for cap, label, job in server_jobs()]
    finally:
        conn.close()
    with_jobs = {cap for cap, _l, _j in server_jobs()}
    counts = {s: 0 for s in SEVERITIES}
    for sec in sections:
        if sec['state'] in ('observed', 'partial'):
            for f in sec['findings']:
                counts[f['severity']] += 1
    return {
        'kind': 'argus.server_review/v1',
        'host': (host if host is not None else socket.gethostname())[:64],
        'generated_at': now, 'window_days': days, 'window_start': since,
        'not_an_audit': NOT_AN_AUDIT,
        'register_line': statement['register_line'],
        'coverage': statement['looks_at'],
        'not_provided': statement['not_provided'],
        'without_collector': [r for r in statement['looks_at'] if r['capability'] not in with_jobs],
        'sections': sections,
        'severity_counts_in_window': counts,
        'states': {k: sum(s['state'] == k for s in sections) for k in STATE_WORDS},
        'scores_note': statement['scores_note'],
        'facts': statement['facts'],
        'removal': statement['removal'],
    }


def _when(ts):
    return 'never' if ts is None else time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(ts))


def _last_run(sec):
    """'never' only when nothing was ever stored; a stale area says when its result is from."""
    if sec['last_run'] is not None:
        return _when(sec['last_run'])
    if sec['findings_at'] is not None:
        return f'no run in this window (stored result from {_when(sec["findings_at"])})'
    return 'none recorded'


def common_status(review):
    """The capability status most areas share: stated once at the top of the report."""
    seen = [s['register'] for s in review['sections']]
    return max(sorted(set(seen)), key=seen.count) if seen else ''


def render(review):
    """Plain text. Bounded; refuses hand-written text that overclaims."""
    handwritten = [NOT_AN_AUDIT] + list(STATE_WORDS.values())
    bad = [p for t in handwritten for p in audience._overclaims(t) + audience._promises(t)]
    if bad:
        raise ValueError(f'review text would overclaim: {sorted(set(bad))}')
    c = review['severity_counts_in_window']
    st = review['states']
    common = common_status(review)
    lines = [f'ARGUS-1 observed server review: {review["host"]}'
             + (' (preview)' if review.get('preview') else ''),
             f'Window: {_when(review["window_start"])} to {_when(review["generated_at"])} '
             f'({review["window_days"]} days)', '', review['not_an_audit'], '',
             review['register_line'], '',
             f'Capability status: {common} for every area below unless noted.',
             f'Areas: {st["observed"]} observed, {st["partial"]} partial, {st["stale"]} stale, '
             f'{st["not_observed"]} not observed.',
             f'Findings from areas observed in this window: {c["critical"]} critical, '
             f'{c["high"]} high, {c["medium"]} medium, {c["low"]} low.',
             'Findings are operational observations to review with the server owner, not '
             'verdicts.', '']
    for sec in review['sections']:
        lines.append(f'## {sec["label"]} [{sec["job"]}]')
        lines.append(f'   State: {sec["state_text"]}. Runs in window: {sec["runs"]["complete"]} '
                     f'complete, {sec["runs"]["partial"]} partial, {sec["runs"]["unavailable"]} '
                     f'unavailable. Last run: {_last_run(sec)}.')
        if sec['register'] != common:
            lines.append(f'   Capability status: {sec["register"]}.')
        if sec['error']:
            lines.append(f'   Last error: {sec["error"]}')
        if sec['state'] == 'not_observed':
            lines.append('   Nothing can be said about this area for this window.')
        elif sec['findings_at'] is None:
            lines.append('   No stored result for this area: its findings cannot be shown.')
        elif sec.get('preview_note') and sec['finding_count']:
            lines.append(f'   {sec["finding_count"]} findings in the stored result of '
                         f'{_when(sec["findings_at"])}: listed in the full report.')
        elif not sec['findings']:
            lines.append(f'   No findings in the stored result of {_when(sec["findings_at"])}.')
        else:
            if sec['state'] == 'stale':
                lines.append(f'   Findings below are from {_when(sec["findings_at"])}, before this window.')
            for f in sec['findings']:
                lines.append(f'   - {f["severity"]:<8} {f["title"]}')
                if f.get('detail'):
                    lines.append(f'              {f["detail"]}')
            if sec['truncated'] and not sec.get('preview_note'):
                lines.append(f'   ... {sec["truncated"]} more not shown (see `argus '
                             f'{sec["job"]}` on the server).')
        lines.append('')
    lines.append('What this review could not see (blind spots):')
    for row in review['coverage']:
        lines.append(f'  - {row["label"]}: {row["status"]}. Limit: {row["limit"]}.')
    for row in review['not_provided']:
        lines.append(f'  - {row["label"]}: not provided ({row["limit"]}).')
    for row in review['without_collector']:
        lines.append(f'  - {row["label"]}: no collector run is recorded for it in this report.')
    lines += ['', review['scores_note'], '', 'Good to know:']
    lines += [f'  - {f}' for f in review['facts']]
    lines += ['', f'To remove ARGUS-1: {review["removal"]}']
    if review.get('preview'):
        lines += ['', 'This is a preview. The full report lists every finding with its detail. '
                  'It needs an Argus licence on this server:',
                  '  enter a licence key: argus licence activate ARGUS-SRV-XXXXX-...',
                  f'  buy Argus Server ($50 per server per year): {review.get("buy_url")}',
                  '  or buy from here and activate automatically: argus licence buy']
    if len(lines) > MAX_LINES:
        lines = lines[:MAX_LINES - 1] + ['(truncated: use --json for the full bounded report)']
    return '\n'.join(lines) + '\n'


def preview(review, buy_url):
    """The unlicensed form of the report: every area's state, the counts and the blind spots,
    without the individual findings. Premium content only: nothing here gates protection,
    and `argus <job>` on the server still shows every finding."""
    out = dict(review)
    out['preview'] = True
    out['buy_url'] = buy_url
    out['sections'] = [{**sec, 'findings': [], 'truncated': sec['finding_count'],
                        'preview_note': True} for sec in review['sections']]
    return out


def write_private(path, text):
    """Create `path` owner-only; refuse to overwrite or follow a symlink."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        fh.write(text)
