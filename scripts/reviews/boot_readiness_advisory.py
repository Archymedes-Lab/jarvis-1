"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'JARVIS monitors continuously and is fully operational right after every '
            'Windows boot, measured, not assumed',
    'measured_2026_10_27': {
        'window': '14 days; Windows awake 106.6 h; 37 unexpected hard resets',
        'blind_while_awake': 'best single sensor blind 6.5 h (93.9% coverage); outages '
                             'of 15-85 min with every sensor silent',
        'boot_to_first_scan': 'median about 1-2 min; outliers 25-118 min',
        'pre_logon': 'JARVIS starts at user logon; one boot waited 87 min for logon; the '
                     'Windows native sensor and Sysmon run from boot and spool events',
        'stale_after_boot': '20 min after boot, memscan/posture/spy still carried '
                            'pre-reboot results that the reliability plane counted fresh',
        'sysmon_boot': 'the boot overflowed the 50000-entry driver queue in 36 s: 102 '
                       'process starts and 73388 registry events dropped, under the '
                       'revised baseline applied 3 days earlier',
        'watchdog': 'the Windows wake watchdog read WSL\'s own timeout text as a unit '
                    'state and attempted ~30 restarts of a running daemon',
    },
    'design': {
        'boot_currency': '16 registry-declared boot-scoped collectors (startup entries, '
                         'services, drivers, boot chain, live processes, firewall); a '
                         'result older than the guest boot time counts as at least one '
                         'cadence late (due now) instead of the 99 used for never-ran jobs',
        'readiness': 'health reports pending, failed and boot-to-verified seconds from '
                     'persisted snapshots; it is not folded into the ready flag because '
                     'a 503 there raises the user-facing "unavailable" alert',
        'watchdog_fix': 'unit state accepted only if it is one of the 8 states systemctl '
                        'can print; anything else is unknown and the unit is left alone',
        'sysmon': 'Services registry subtree recorded only at 25 persistence/tamper value '
                  'names, service key deletion, and whole firewall, port-proxy and sensor '
                  'subtrees',
        'start_at_boot': 'add a boot trigger to the existing S4U keepalive task; S4U WSL '
                         'is measured working after logon, unmeasured before any logon',
    },
    'validation': {
        'tests': '22 boot readiness tests incl. sweep ordering with and without the '
                 'floor, restart stability, unreadable boot time; real Windows PowerShell '
                 'parser checks on both supervisors; Sysmon policy evaluator proves every '
                 'registry detector sample is recorded',
        'replay': '7-day replay of 46582 retained registry events keeps 30%; dropped '
                  'kinds are brightness, DHCP lease, binding and enumeration churn',
        'found': 'the replay test found one detector whose key no baseline ever recorded',
        'not_yet': 'nothing deployed; no reboot measured with any change',
    },
}
QUESTIONS = {
    'floor_choice': {'type': 'choice', 'instructions':
        'For a boot-scoped collector whose last result predates the current boot, which '
        'scheduling treatment best balances fast post-boot verification against keeping '
        'tier-0 event ingestion first on a single serial lane?',
        'criteria': {
            'due_now': 'count it as one cadence late (due now), competing on criticality',
            'never_ran': 'count it as never ran (top priority above everything)',
            'age_only': 'leave it judged by age alone, as before'}},
    'readiness_separate': {'type': 'noul', 'instructions':
        'Is reporting boot readiness as its own health field, rather than making the '
        'service read not-ready until every boot audit has a post-boot result, the honest '
        'and safer choice given design.readiness?',
        'criteria': {'true': 'Yes, separate field', 'false': 'No, it should gate ready'}},
    'sysmon_anchor_safe': {'type': 'noul', 'instructions':
        'Given design.sysmon and the replay and detector-sample evidence, does anchoring '
        'the Services subtree to persistence and tamper values keep service-based '
        'persistence and defence tampering visible while cutting boot volume?',
        'criteria': {'true': 'Yes, signal kept', 'false': 'No, a meaningful signal is lost'}},
    'biggest_risk': {'type': 'choice', 'instructions':
        'Which remaining uncertainty most threatens the goal of being fully operational '
        'at boot after these changes?',
        'criteria': {
            'pre_logon_wsl': 'WSL under S4U may not start before any interactive logon',
            'sysmon_overflow': 'the narrower Sysmon policy may still overflow at boot',
            'hard_resets': 'the frequent Windows hard resets themselves',
            'governed_delay': 'governed boot audits deferring under boot-time load'}},
    'reboot_required': {'type': 'noul', 'instructions':
        'Is a measured real reboot (boot-to-verified seconds, Sysmon drop counts, '
        'pre-logon service start) still required before calling boot readiness fixed?',
        'criteria': {'true': 'Yes, required', 'false': 'Tests and replay suffice'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
