"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'stop JARVIS being reported unavailable when it is running, and stop the causes',
    'measured_baseline': {
        'last_toast': 'Windows health monitor toast while the daemon answered /api/health in '
                      'under 3.4 s; native partial on most passes, sysmon draining a 213k backlog',
        'sensor_read': 'resume by XPath EventRecordID>N on a 208,860-record 256 MB log: 770 ms '
                       'to first record idle; read timeout 2 s x 3 attempts fails under load; '
                       '463 timeout recurrences since 2026-09-21',
        'seek_read': 'Seek(Begin, after+1-oldest): 26 ms to first record, landed 43 records '
                     'short of target; 2000 reads in 195 ms',
        'restart_storms': '8 episodes of 3 reviver restarts in 15 min during 90-400 s cold '
                          'starts, each restart resetting catch-up',
        'clock': 'WSL wall clock steps back 2.47 s every 32 s (timesyncd vs Hyper-V sync); '
                 'journald rotates each step, history about 50 min',
    },
    'alternatives': {
        'sensor': [
            'positional seek by index with bounded record-id correction, XPath fallback',
            'keep XPath and raise the read timeout and retries',
            'keep an in-memory EventBookmark between passes, XPath only after restart',
        ],
        'supervisor': [
            'reviver start grace of 300 s after unit start plus per-source kick backoff; '
            'health monitor names degraded coverage separately from unavailable',
            'leave supervisors unchanged and rely on fixing sensors only',
        ],
    },
    'selected': {'sensor': 'positional seek with bounded correction',
                 'supervisor': 'start grace, kick backoff, distinct degraded message'},
    'invariants': [
        'no event skipped: first emitted record is the lowest id above the cursor, or the oldest '
        'with an explicit gap',
        'timeout or failed correction leaves the cursor unchanged',
        'fixed bound on seeks and skips per pass',
        'restarts only past grace and within the existing 3-per-15-min budget; systemd watchdog '
        'and selfcheck remain backstops',
        'degraded coverage stays alerted with the same timing, only labelled accurately; /api/health '
        'and its 503 unchanged',
    ],
    'thresholds': {'start_grace_s': 300, 'kick_backoff_s': [30, 600], 'max_corrections': 8,
                   'max_skip_records': 50000},
}
QUESTIONS = {
    'sensor_design': {'type': 'choice', 'instructions':
        'Which sensor alternative in `alternatives.sensor` best meets the goal under the '
        'invariants, given the measured read costs?',
        'criteria': {'seek': 'Positional seek with bounded correction and fallback',
                     'timeout': 'Raise timeout and retries',
                     'bookmark': 'In-memory bookmark, XPath after restart',
                     'uncertain': 'Insufficient information'}},
    'timeout_only_fails': {'type': 'noul', 'instructions':
        'Would only raising the read timeout leave each pass cost growing with log size, so '
        'timeouts return under heavier load?',
        'criteria': {'true': 'Yes, it treats the symptom', 'false': 'No, it is a sufficient fix'}},
    'grace_safe': {'type': 'noul', 'instructions':
        'With a systemd watchdog at 900 s and an independent selfcheck every 2 min still able '
        'to restart a dead daemon, is a 300 s reviver grace after unit start a safe bound '
        'that avoids restarting a daemon in cold start?',
        'criteria': {'true': 'Safe bound', 'false': 'Unsafe bound'}},
    'label_not_weaken': {'type': 'noul', 'instructions':
        'If degraded coverage still produces a toast and mail with the same timing but is titled '
        '"coverage degraded" instead of "monitoring unavailable", does that keep visibility '
        'without weakening the alert?',
        'criteria': {'true': 'Visibility kept, more accurate', 'false': 'It weakens the alert'}},
    'validation_gap': {'type': 'noul', 'instructions':
        'Is a live Windows measurement of the new read path on the real Sysmon channel still '
        'required beyond unit tests with a fake log before calling the sensor fix verified?',
        'criteria': {'true': 'Yes, live measurement required', 'false': 'Unit tests suffice'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    if STATE['phase'] == 'implementation':
        STATE['validation'] = json.loads(sys.stdin.read() or '{}')
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
