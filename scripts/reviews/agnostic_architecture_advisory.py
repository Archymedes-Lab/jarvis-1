"""Fixed metadata only; advisory on deploying ARGUS-1 safely on many kinds of computer.

Compares the credible architectures for an OS-agnostic agent (docs/architecture/
AGNOSTIC-DEPLOYMENT.md). No code, paths, findings or host data are sent. The answers
cannot select an unsafe design, approve a release or replace the invariant tests."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'one security monitor that installs and runs safely on many computers: Ubuntu, Debian, '
            'RHEL-family, Alpine, containers, virtual machines, WSL, Windows and later macOS, run by '
            'individuals and small teams, local-first with optional central management later',
    'today': {
        'agent': 'about 90 thousand lines of Python, 72 collectors declared in one registry, shipped as '
                 'one compiled binary per OS with signed checksums',
        'host_model': 'three host kinds only (Windows, WSL, Linux); macOS is misread as Linux; no notion '
                      'of distribution family, init system, container or package manager',
        'gaps': 'owner-machine paths in shipped files, only 3 of 72 collectors run in a killable child, '
                'no central enrolment or update channel, one release signing key',
    },
    'options': {
        'facts_first': 'keep the agent; add a measured host facts probe and per-collector requirements so the '
                       'same binary decides what applies on each host, reports the rest as not applicable '
                       'with the missing fact, then add enrolment and a signed staged update channel',
        'osquery_substrate': 'adopt osquery as the cross-platform sensor layer and keep this project as '
                             'the analysis and evidence layer on top',
        'rewrite_static': 'rewrite the agent as a single static Go or Rust binary first',
        'fleet_server_first': 'build a central server with enrolment, policy and updates before changing the agent',
    },
}
QUESTIONS = {
    'first_step': {'type': 'choice', 'instructions':
        'Which architecture should come first to let this monitor run safely on many kinds of computer?',
        'criteria': {'facts_first': 'Host facts probe and per-collector requirements in the existing agent',
                     'osquery_substrate': 'osquery as the cross-platform sensor layer',
                     'rewrite_static': 'A static Go or Rust rewrite first',
                     'fleet_server_first': 'A central fleet server first'}},
    'gating_hides_gaps': {'type': 'noul', 'instructions':
        'If a collector is skipped whenever a required host fact is missing, is there a serious risk of hiding a '
        'real visibility gap, such as an absent audit sensor, unless requirements only name the thing being '
        'observed and never the sensor?',
        'criteria': {'true': 'Yes, a serious risk without that rule', 'false': 'No, low risk'}},
    'updates_like_code': {'type': 'noul', 'instructions':
        'Should detection content and configuration for such an agent go through the same staged rings, '
        'health gates and automatic halt as program updates?',
        'criteria': {'true': 'Yes', 'false': 'No, content can ship faster'}},
    'central_optional': {'type': 'noul', 'instructions':
        'Should protection keep working fully when the central server is unreachable, with the server only '
        'adding enrolment, policy and fleet views?',
        'criteria': {'true': 'Yes, local-first', 'false': 'No, central control first'}},
}
# Review of the phase 1 implementation (2026-11-02). Metadata only.
REVIEW_STATE = {
    'goal': 'phase 1 of running one monitor safely on many kinds of computer',
    'built': {
        'facts': 'file reads only with a 64 KB cap: OS, distribution family, init system, container runtime, '
                 'libc, package databases, container engines, kernel BTF; unknown stays unknown',
        'requirements': 'seven collectors declare requirements naming the observed thing (package database, '
                        'systemd, own kernel, container engine, distribution security data); unmet means listed '
                        'not applicable with the missing fact; sensor-gap collectors declare none (tested)',
        'unsupported_os': 'macOS used to be misread as Linux; it is now unsupported and the daemon refuses to start',
        'release_gate': 'new rule refuses a Windows home folder seen through a WSL mount; it found exactly one '
                        'file in the shipped server release, which is now left out',
        'cursor_fix': 'Linux Sysmon cursor used to move before the read; now only after a good read, a failed '
                      'pass is reported and the window is read again; syslog fallback capped to its last 8 MB',
        'tests': 'fixture hosts for Debian, Ubuntu on WSL, Rocky, Alpine container, Kubernetes, macOS; '
                 'mutation checks caught every deliberate break; development host schedule unchanged',
    },
}
REVIEW_QUESTIONS = {
    'top_gap': {'type': 'choice', 'instructions':
        'Which remaining gap in this phase 1 most limits safe deployment on many computers?',
        'criteria': {'fixtures_only': 'Requirements are tested on fixture hosts only, never on real other distributions',
                     'few_requirements': 'Only seven collectors declare requirements',
                     'probe_once': 'Facts are probed once per process, so later changes are missed until restart',
                     'no_isolation': 'Most collectors still run in shared threads and can stall a lane'}},
    'safe_to_merge': {'type': 'noul', 'instructions':
        'Given the development host schedule is unchanged and every change is test-guarded, is this phase '
        'safe to merge before any real other-distribution run?',
        'criteria': {'true': 'Yes', 'false': 'No, run on real hosts first'}},
}
FOOTPRINT_STATE = {
    'goal': 'a light security monitor for small servers and laptops',
    'measured': {
        'fixed': 'two collectors whose cost grew with stored history now stay flat: one walked the whole '
                 'database every five minutes (6.8 s CPU, 367 MB peak, now 0.2 s and 34 MB); one loaded every '
                 'process fingerprint ever seen each minute (1.8 s, 180 MB, now 0.5 s and 38 MB)',
        'baseline': 'fresh install: 42 jobs cost 5.4 percent of one core at steady state',
        'open': 'event log re-parses an 8 MB hash chain on each open, four opens a minute, growing linearly; '
                'SQLite allows 64 MB cache plus 256 MB memory map per connection; the optional Linux Sysmon '
                'daemon took 29 percent of a core with the current configuration',
    },
}
FOOTPRINT_QUESTIONS = {
    'next': {'type': 'choice', 'instructions': 'Which open cost should be addressed next for a light product?',
             'criteria': {'chain_cache': 'Event log hash-chain parsing on every open',
                          'sqlite_budget': 'Per-connection SQLite cache and memory map',
                          'sysmon_config': 'The Linux Sysmon configuration that the product recommends',
                          'none': 'None; the remaining costs are acceptable'}},
    'evidence_risk': {'type': 'noul', 'instructions':
        'Is caching the parsed hash chain keyed on file size and modification time a risk to tamper evidence '
        'unless the integrity walk still reads the file itself?',
        'criteria': {'true': 'Yes, a risk without that rule', 'false': 'No'}},
}
if __name__ == '__main__':
    if sys.argv[1:] == ['footprint']:
        STATE, QUESTIONS = FOOTPRINT_STATE, FOOTPRINT_QUESTIONS
    if sys.argv[1:] == ['review']:
        STATE, QUESTIONS = REVIEW_STATE, REVIEW_QUESTIONS
    try:
        result = jev._call(STATE, QUESTIONS, timeout=20)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
        sys.exit(0)
