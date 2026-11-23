"""Fixed engineering metadata only; advisory, never deployment authorization.

Argus server 2026-10-28: vulnerabilities in the applications a server runs
(dependency CVEs, risky code, secrets and permissions in code trees)."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'a self-hosted Linux server security monitor must report vulnerabilities in the '
            'application code the server runs: vulnerable or malicious dependencies, risky code '
            'patterns, credentials committed to code, writable code trees, and .env or .git '
            'exposed under a web root; without sending anything about the server off the box',
    'deps_design': 'walk bounded app roots for lockfiles and venvs; a daily job downloads the '
                   'public OSV per-ecosystem zip dumps only for ecosystems present (npm 219 MB, '
                   'PyPI 37 MB, others under 13 MB measured), streams them to disk under a byte '
                   'cap, keeps only advisories for package names in the local inventory, deletes '
                   'the dump; matching is local',
    'deps_alternatives': ['query the OSV API with the package inventory',
                          'require operators to install osv-scanner or trivy',
                          'hold whole dumps in memory under the 1 GB service cap'],
    'sast_design': 'bundled dependency-free line rules per language (Python, PHP, JS/TS, Ruby, Go, '
                   'Java): injection sinks, eval or deserialisation, TLS verification off, debug '
                   'mode; a rule on the same line as request input is medium, otherwise low; one '
                   'aggregated finding per project and rule with file:line only, no code text',
    'sast_alternatives': ['AST parsing per language', 'semgrep required', 'no code scanning'],
    'tools_design': 'run bandit when already installed; run semgrep only with an operator-supplied '
                    'local rules path and metrics off; never install either',
    'severity_plan': 'known malicious package critical; dependency with a CISA KEV CVE high; other '
                     'dependency advisories one medium finding per project when any is high or '
                     'critical, else low; code-pattern findings at most medium; secret in code '
                     'capped at high; world-writable code tree medium; .env or .git under a web '
                     'root high',
    'cadence': 'one daily bulk-lane deferrable walk feeds inventory, rules, secrets and '
               'permissions; a separate daily download job; both unscored until soaked',
}
QUESTIONS = {
    'deps_choice': {'type': 'choice', 'instructions':
        'Which dependency-vulnerability design best fits privacy (nothing about the server leaves '
        'it), bounded memory under a 1 GB cap, and no extra software for the operator?',
        'criteria': {'local_osv_dumps': 'Stream public OSV dumps to disk, filter to inventory, match locally',
                     'osv_api': 'Query the OSV API with the package inventory',
                     'external_scanner': 'Require osv-scanner or trivy',
                     'in_memory': 'Hold whole dumps in memory',
                     'uncertain': 'Insufficient information'}},
    'sast_choice': {'type': 'choice', 'instructions':
        'For a monitor that must not flood small teams with alerts, which code-scanning design is '
        'the best default?',
        'criteria': {'line_rules': 'Bundled line rules with request-input confidence, aggregated per project',
                     'ast': 'AST parsing per language',
                     'semgrep_required': 'Require semgrep',
                     'none': 'No code scanning',
                     'uncertain': 'Insufficient information'}},
    'sast_cap_medium': {'type': 'noul', 'instructions':
        'Is capping pattern-based code findings at medium severity proportionate, given they are '
        'heuristic and unconfirmed?',
        'criteria': {'true': 'Proportionate', 'false': 'Not proportionate'}},
    'malicious_critical': {'type': 'noul', 'instructions':
        'Is critical severity proportionate for a dependency that OSV lists as a known malicious '
        'package and that appears in a lockfile on the server?',
        'criteria': {'true': 'Proportionate', 'false': 'Not proportionate'}},
    'semgrep_local_only': {'type': 'noul', 'instructions':
        'Is running semgrep only with an operator-supplied local rules path and metrics off the '
        'right privacy default, rather than its registry rules which require network access?',
        'criteria': {'true': 'Right default', 'false': 'Registry rules should be the default'}},
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
