"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'record every display brightness change on the Windows host as a timeline '
            'event, alongside the existing volume change events, so a change the user did '
            'not make is visible with its context',
    'existing': {
        'coarse': 'controls collector samples WmiMonitorBrightness every 5 minutes and '
                  'reports a change as low severity, unattributed',
        'volume_rule': 'resident input hook samples the master volume every second and '
                       'reports a change with no control key in the prior 1.5 s as medium '
                       '("changed with no key press behind it")',
    },
    'design': {
        'sampler': 'the resident input hook polls WmiMonitorBrightness every 2 s on its '
                   'own PowerShell runspace (measured read cost 10-16 ms after a 121 ms '
                   'first call), never on the thread that services the low-level hook',
        'record': 'control-state event: from, to, panel id (24 safe chars), seconds since '
                  'any keyboard or mouse input (GetLastInputInfo), ms since last control '
                  'key, foreground process name; no content',
        'severity': 'low "display brightness changed" with counts, active-vs-idle split, '
                    'and an explicit list of legitimate causes; it is excluded from the '
                    'medium unkeyed-volume rule',
        'failure': 'after 30 consecutive WMI failures the sampler stops; the 5-minute '
                   'collector already reports the provider as unobservable',
    },
    'rationale': 'the laptop brightness hotkey is ACPI/WMI and produces no virtual key, '
                 'and Windows moves brightness itself (adaptive, battery, idle dimming), '
                 'so keyed-vs-unkeyed is not a tell for brightness the way it is for volume',
    'validation': {'tests': '7 new unit tests (ingest shape, low severity, volume rule not '
                            'diluted, forensic timeline, hook script contract) and the 63 '
                            'related tests pass; live mechanics probed on the host',
                   'not_yet': 'the running hook is the sealed release; the new sampler is '
                              'not live until an owner release and hook restart'},
}
QUESTIONS = {
    'severity_honest': {'type': 'noul', 'instructions':
        'Given rationale and design.severity, is reporting every brightness change as '
        'low severity with its idle context, rather than reusing the medium unkeyed-volume '
        'rule, the honest severity for this signal?',
        'criteria': {'true': 'Low is honest', 'false': 'It should alert at medium or higher'}},
    'hook_safety': {'type': 'noul', 'instructions':
        'Does running the 10-16 ms WMI read on a separate runspace, with the 2 s period and '
        'the stop-after-30-failures rule, keep this sampler from degrading the low-level '
        'keyboard hook or wasting resources when no provider exists?',
        'criteria': {'true': 'Yes, bounded and off the hook thread', 'false': 'No, a risk remains'}},
    'privacy': {'type': 'noul', 'instructions':
        'Is the record (brightness levels, trimmed panel id, idle seconds, foreground '
        'process name, timing) free of user content, matching what the volume events '
        'already record?',
        'criteria': {'true': 'No content, consistent', 'false': 'It leaks something new'}},
    'biggest_gap': {'type': 'choice', 'instructions':
        'Which remaining gap most limits the value of this brightness monitoring?',
        'criteria': {
            'attribution': 'no way to name which process or mechanism changed brightness',
            'external_displays': 'external monitors without a WMI provider are unseen',
            'not_live': 'the sampler is not yet in the running release',
            'idle_dimming_noise': 'legitimate idle or adaptive dimming will dominate the log'}},
    'validation_gap': {'type': 'noul', 'instructions':
        'Beyond unit tests and the mechanics probe, is a live run of the new hook with a '
        'deliberate brightness change observed in control_events still required before '
        'calling this feature working?',
        'criteria': {'true': 'Yes, still required', 'false': 'Unit tests and the probe suffice'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
