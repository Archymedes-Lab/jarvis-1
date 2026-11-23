"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'close the microphone/camera consent surface on an owner command, and see any reopening',
    'alternatives': [
        'separate read-only 5-minute collector plus an owner-only CLI writer with recorded rollback',
        'fold the posture read into the existing controls collector',
        'disable the capture devices (PnP) through the elevated broker',
        'daemon applies and lifts a time-bounded seal on its own',
    ],
    'selected': 'separate read-only collector plus owner-only CLI writer',
    'measured': {
        'live_read': '2.5 s, no errors, 14 capture endpoints, 1 camera, 2 Stereo Mix loopback endpoints active',
        'host_posture': 'microphone and camera global and desktop-app values Allow in the user hive; no AppPrivacy policy',
        'tests': '19 new unit tests: seal drift, use-after-seal, policy override, flip between samples, invalid snapshot, readback mismatch fails closed, CLI refuses off-tty, audio capture session severity under seal',
    },
    'decisions': {
        'open_posture_severity': 'low (informational, zero score weight) when no seal is declared',
        'broken_seal': 'high, unattributed; Sysmon records no ConsentStore writes on this host',
        'capture_session_under_seal': 'high in the audio collector; medium when unsealed',
        'write_path': 'stdin JSON validated against an allowlist on both sides; readback must equal the request or the seal is not recorded',
    },
    'invariants': [
        'the daemon never writes; only the owner CLI writes after confirmation',
        'unreadable sources are visibility loss, never clean; previous evidence kept',
        'sealing is reversible with one command and explained before it happens',
        'no claim of complete coverage: user-mode gate, kernel streaming and drivers bypass it',
    ],
    'limits': [
        'the seal has never been applied on the live host; its effect on a real capture attempt is unmeasured',
        'a reopen-and-reclose inside one five-minute interval is unseen',
        'WSL has no consent store',
    ],
}
QUESTIONS = {
    'design': {'type': 'choice', 'instructions':
        'Which alternative best meets the goal under the invariants with the least new authority given to the daemon?',
        'criteria': {'collector_cli': 'Separate collector plus owner-only CLI writer',
                     'controls': 'Fold into the controls collector',
                     'pnp': 'Disable the devices through the elevated broker',
                     'auto': 'Daemon-applied time-bounded seal', 'uncertain': 'Insufficient information'}},
    'open_low': {'type': 'noul', 'instructions':
        'Is low (informational) the right severity for microphone and camera access being open when the owner has not declared a seal?',
        'criteria': {'true': 'Low is right', 'false': 'It should be medium or higher'}},
    'use_after_seal_high': {'type': 'noul', 'instructions':
        'Given the ledger only shows an app passed the gate, is high the right severity for a ledger entry that started after the seal while values still read Deny?',
        'criteria': {'true': 'High is right', 'false': 'It should be lower'}},
    'validation_gap': {'type': 'noul', 'instructions':
        'Should the capability stay at unverified until the seal is applied on the live host and a real capture attempt is observed to fail?',
        'criteria': {'true': 'Stay unverified', 'false': 'Partial is already justified'}},
    'hidden_risk': {'type': 'choice', 'instructions':
        'Which remaining risk most deserves a further deterministic test before release?',
        'criteria': {'rollback': 'Unseal restoring the wrong previous values',
                     'noise': 'Repeated findings every five minutes while sealed and in use',
                     'readback': 'A writer that succeeds partially',
                     'none': 'None stands out'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
