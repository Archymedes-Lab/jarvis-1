"""Fixed engineering metadata only; advisory, never deployment authorization.

Argus server 2026-10-25: off-box heartbeat (W10) and patch/CVE awareness (W11)."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'a self-hosted Linux server security monitor must alert when the host or itself goes '
            'silent, and report security fixes that are available but not installed',
    'heartbeat_design': 'a job in the daemon fast lane does one HTTPS GET per minute to an external '
                        'dead-man service the owner configures; silence there is the alarm; the URL is '
                        'treated as a secret; no data about the machine is sent',
    'heartbeat_alternatives': ['on-host timer that restarts the daemon', 'peers watching each other',
                               'daily still-alive email'],
    'cve_design': 'download the distribution own security data (Ubuntu USN OVAL, Debian OVAL) daily, '
                  'parse as a bounded stream, compare installed versions locally with Debian version '
                  'ordering, report only CVEs whose fix exists and is not installed, rank by CISA KEV',
    'cve_alternatives': ['send the package inventory to a public vulnerability API',
                         'Debian tracker JSON of 86 MB parsed in memory', 'shell out to optional distro tools'],
    'severity_plan': 'known-exploited with fix not installed is high per package; other fixable CVEs one '
                     'aggregated medium; reboot pending over a day medium; stale package lists medium',
}
QUESTIONS = {
    'heartbeat_choice': {'type': 'choice', 'instructions':
        'Which design best ensures the owner learns that the host or the monitor went silent?',
        'criteria': {'external_deadman': 'Outbound ping to an external dead-man service',
                     'onhost_timer': 'On-host timer that restarts the daemon',
                     'peers': 'Peers watching each other', 'email': 'Daily still-alive email',
                     'uncertain': 'Insufficient information'}},
    'heartbeat_semantics': {'type': 'noul', 'instructions':
        'Is it a problem that the ping proves only that the daemon scheduler runs, not that every '
        'collector is healthy, given collector failures already alert through the normal channels?',
        'criteria': {'true': 'Yes, a meaningful problem', 'false': 'No, acceptable'}},
    'cve_choice': {'type': 'choice', 'instructions':
        'Which CVE design best fits privacy, bounded memory on a 1 GB-capped daemon, and actionable output?',
        'criteria': {'local_oval': 'Distribution OVAL parsed as a bounded stream, matched locally',
                     'public_api': 'Send inventory to a public vulnerability API',
                     'tracker_json': 'Parse the 86 MB tracker JSON in memory',
                     'distro_tools': 'Shell out to optional distro tools',
                     'uncertain': 'Insufficient information'}},
    'fixable_only': {'type': 'noul', 'instructions':
        'Is reporting only CVEs whose fix is available but not installed (and not unfixed CVEs) the '
        'right default to keep alerts actionable for small teams?',
        'criteria': {'true': 'Yes, right default', 'false': 'No, unfixed CVEs should also alert'}},
    'kev_high': {'type': 'noul', 'instructions':
        'Is high severity per package proportionate for a known-exploited CVE whose fix is available '
        'but not installed on a server?',
        'criteria': {'true': 'Proportionate', 'false': 'Not proportionate'}},
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
