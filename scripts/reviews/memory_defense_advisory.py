"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'report the OS-wide memory-corruption and credential-memory mitigations that are off or at default, with exact remediation, without double-counting the per-process memory scan',
    'alternatives': [
        'a new posture section reading Get-ProcessMitigation -System, kernel shadow stacks, WDigest and the LSA lock',
        'extend the memory scan (broker, elevated) to read the same values',
        'a separate scheduled collector',
    ],
    'selected': 'posture section; the memory scan keeps per-process state',
    'measured_live': {
        'dep_sehop_cfg': 'NOTSET (Windows default)', 'aslr': 'bottom-up, high-entropy and force-relocate ON',
        'user_shadow_stack': 'OFF', 'kernel_shadow_stack': 'not enabled', 'lsa': 'RunAsPPL 1, boot flag 1, Credential Guard running',
        'wdigest': 'unset', 'asr': '7 key rules block, 3 further rules audit-only, 8 not configured',
        'memscan_script': 'live release and broker match each other and lack the reflective PE-image check present in the checkout',
    },
    'severities': {
        'DEP OFF': 'high', 'SEHOP/ASLR/CFG OFF': 'medium', 'defaults (NOTSET)': 'low pin advice',
        'shadow stacks off': 'low (memscan already reports CET per process as medium)',
        'WDigest 1': 'high', 'ASR audit-only': 'low; a key rule not blocking stays medium',
    },
    'invariants': ['unreadable values are visibility, never off', 'a reported ON is a configuration fact, not enforcement proof',
                   'no change is applied; every finding carries its own command'],
}
QUESTIONS = {
    'design': {'type': 'choice', 'instructions': 'Which alternative best fits the goal with the least duplication and no new elevation?',
               'criteria': {'posture': 'Posture section', 'memscan': 'Extend the memory scan', 'collector': 'Separate collector', 'uncertain': 'Insufficient information'}},
    'default_low': {'type': 'noul', 'instructions': 'Is low the right severity for DEP, SEHOP and CFG reading NOTSET (the Windows default, which is on for 64-bit code) rather than OFF?',
                    'criteria': {'true': 'Low is right', 'false': 'It should be medium'}},
    'shadow_low': {'type': 'noul', 'instructions': 'Given the memory scan already reports missing CET per process as medium, is low right for the system-wide shadow-stack default in the posture section?',
                   'criteria': {'true': 'Low avoids double counting', 'false': 'Both should be medium'}},
    'release_risk': {'type': 'noul', 'instructions': 'If the broker script for the memory scan is reinstalled from the checkout before the matching Python release is deployed, would the live daemon lose the memory scan entirely because it refuses results from a script that differs from its own copy?',
                     'criteria': {'true': 'Yes, order matters: release first, then broker install', 'false': 'No'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
