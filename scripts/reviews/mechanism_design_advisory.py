"""Mechanism design system and live process view: compare designs, advisory only.

Fixed engineering metadata; nothing about the protected machine, its processes
or its findings. Jev ranks alternatives; tests and measurement decide, and the
owner keeps authority over anything that changes what is scored or deployed.

    python3 scripts/reviews/mechanism_design_advisory.py
"""
import json

from jarvis.response import jev

STATE = {
    'system': 'a personal host-security monitor: about 55 scheduled collectors on three serial '
              'worker lanes, a loopback web dashboard, sealed root-owned releases',
    'problem': 'each collector\'s contract (interval, label, lane, platform domain, scoring area, '
               'deferrability under load, tier, criticality, run timeout, dependency root) is '
               'spread over eight separate tables in six modules; one collector was found in '
               'none of the scoring tables',
    'registry_alternatives': {
        'A': 'one declarative table of frozen per-collector records in the lowest layer; the old '
             'tables become views derived from it; a golden test proves the views equal the '
             'tables they replace; conformance checks run in the build gate',
        'B': 'decorators on each collector function register its contract next to its code',
        'C': 'keep the eight tables and add a test that they agree with each other',
    },
    'process_view_goal': 'a three-dimensional live view of every process on both the Windows '
                         'host and the Linux guest, lightweight and closely in step with reality',
    'measured': {
        'windows_list_processes_from_a_persistent_script': '26 ms CPU per pass, mostly '
                                                            'interpreter overhead',
        'windows_management_query_per_pass': '310 to 440 ms wall, 195 ms CPU',
        'security_event_log_process_start': 'every start recorded, about 2 s to reach the '
                                            'monitor; process exits are filtered, so most are '
                                            'never recorded',
        'linux_proc_scan': 'local file reads, a few milliseconds',
    },
    'feed_alternatives': {
        'A': 'a compiled snapshot differ that runs once a second only while a viewer is '
             'connected, sends start, exit and resource deltas, and back-fills sub-second '
             'processes from the event-log process starts',
        'B': 'the monitor daemon itself lists processes every second at all times',
        'C': 'event-log process starts and exits only, no periodic listing',
        'D': 'kernel tracing session, which requires an administrator-installed component',
    },
    'rules': [
        'the view is read-only and can never start, stop or change a process',
        'the view must never slow the security collectors',
        'an absent or stale feed must look stale, never calm',
        'command lines and file contents are private',
    ],
}

QUESTIONS = {
    'registry_choice': {
        'type': 'choice',
        'instructions': 'Which registry alternative in `registry_alternatives` best removes the '
                        'drift described in `problem` while keeping live behaviour provably '
                        'unchanged?',
        'criteria': {'A': 'Declarative table with derived views and a golden test',
                     'B': 'Decorators next to each collector',
                     'C': 'Keep the tables, add an agreement test'}},
    'feed_choice': {
        'type': 'choice',
        'instructions': 'Given `measured` and `rules`, which alternative in `feed_alternatives` '
                        'best serves `process_view_goal`?',
        'criteria': {'A': 'Demand-driven compiled differ with event-log back-fill',
                     'B': 'Always-on listing inside the monitor daemon',
                     'C': 'Event log only',
                     'D': 'Administrator-installed kernel tracing'}},
    'demand_driven_sync_ok': {
        'type': 'noul',
        'instructions': 'Alternative A of `feed_alternatives` starts listing processes only when '
                        'a viewer connects. Is a fresh full snapshot on connect followed by '
                        'one-second deltas enough to stay closely in step with reality for a '
                        'person watching?',
        'criteria': {'true': 'Yes, close enough to reality for a watching person',
                     'false': 'No, the view would lag or diverge noticeably'}},
    'cmdline_in_view': {
        'type': 'noul',
        'instructions': 'Should the live process view send full process command lines to the '
                        'page by default, given the privacy rule in `rules`?',
        'criteria': {'true': 'Yes, send command lines by default',
                     'false': 'No, send names and metadata only by default'}},
    'golden_test_sufficient': {
        'type': 'noul',
        'instructions': 'For registry alternative A, beyond the golden equality test, is a run '
                        'of the real daemon with fresh collector results still needed before '
                        'calling the refactor behaviour-preserving?',
        'criteria': {'true': 'Yes, a live readback is still needed',
                     'false': 'No, the golden test is enough'}},
}

# Implementation review (--implementation): what was built and measured.
IMPLEMENTED = {
    'registry': 'built as alternative A; a golden test proves every derived view equals the old '
                'table for the 57 collectors that existed; conformance runs in the unit suite, '
                'the verification ladder and the Argus build gate',
    'feed': 'built as alternative A: a compiled helper reads the whole process table in one '
            'system call every 500 ms (26 ms CPU per second, 2.6% of one core, while watched), '
            'subscribes to event-log process starts, and stops 15 s after the last viewer leaves; '
            'the Linux side reads /proc on the same tick (3 ms per pass)',
    'verified': 'helper fields matched an independent system query for 299 of 299 processes; '
                'tests cover helper exit, start failure, restart cap, stale sources, lagging '
                'viewers, linger shutdown and metadata filtering; two mutants were caught',
    'not_verified': 'frame rate in a real browser with a real GPU; a 30-minute soak through the '
                    'helper lifetime; daemon memory with the view open for hours; a machine '
                    'where the event log cannot be read without administrator rights',
    'feed_runs_in': 'threads inside the monitoring daemon process, separate from collector '
                    'lanes, sharing the interpreter',
}
IMPL_QUESTIONS = {
    'next_gate': {
        'type': 'choice',
        'instructions': 'Given `implemented.not_verified`, which single measurement should come '
                        'first before the process view is called ready?',
        'criteria': {'gpu': 'Frame rate in a real browser with a real GPU',
                     'soak': 'A 30-minute soak through the helper lifetime and restart',
                     'memory': 'Daemon memory with the view open for hours',
                     'standard_user': 'A machine where the event log needs administrator rights'}},
    'shared_interpreter_risk': {
        'type': 'noul',
        'instructions': 'Per `implemented.feed_runs_in` and the measured costs, is running the feed '
                        'threads inside the monitoring daemon likely to delay security collectors '
                        'noticeably while one person watches the view?',
        'criteria': {'true': 'Yes, a noticeable delay is likely',
                     'false': 'No, the delay should be negligible'}},
    'explicit_budgets_drift': {
        'type': 'noul',
        'instructions': 'The registry now states each collector\'s tier, criticality and timeout '
                        'explicitly instead of deriving them from rules. Is it likely that new '
                        'collectors will get inconsistent budgets because no rule derives them, '
                        'even with the conformance checks in `implemented.registry`?',
        'criteria': {'true': 'Yes, inconsistency is likely without a deriving rule',
                     'false': 'No, the checks are enough'}},
}

if __name__ == '__main__':
    import sys
    if '--implementation' in sys.argv:
        STATE['implemented'] = IMPLEMENTED
        QUESTIONS = IMPL_QUESTIONS
    try:
        result = jev._call(STATE, QUESTIONS, timeout=40)
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
    else:
        for key, ans in result['answers'].items():
            print(json.dumps({key: {k: ans[k] for k in ('choice', 'noul', 'confidence',
                                                          'probabilities') if k in ans}}))
