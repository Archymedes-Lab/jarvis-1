"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'Windows supervisors (native service, reviver, health monitor) must tell a live but '
            'degraded daemon from a silent one, so they never restart or give up on a working daemon',
    'measured': {
        'failure': 'health body is 72-76 KB; a degraded daemon answers 503; .NET HttpWebRequest cuts '
                   'non-200 bodies at 64 KB, JSON parse fails, probe returns not answered; the native '
                   'service restarted a live daemon 3 times in 4 min then gave up (2026-10-30/31)',
        'fix': 'DefaultMaximumErrorResponseLength set to 4096 KB inside each probe before the request',
        'tests': 'real PowerShell probes from all three scripts against a stub 503 with a 90 KB body; '
                 'failed before the fix, pass after; fixed probe read the live daemon as answering and live',
    },
    'alternatives': {
        'raise_cap': 'chosen: one line per probe, no daemon release needed, bounded at 4 MB',
        'small_endpoint': 'add a compact liveness endpoint; needs a daemon release and the old probes keep failing',
    },
    'limits': [
        'a body over 4 MB would truncate again',
        'reaches the machine only with the next release (reviver, health monitor) and an Argus rebuild (native service)',
    ],
}
QUESTIONS = {
    'fix_sufficient': {'type': 'noul', 'instructions':
        'Given the measurements, does raising the error-body cap fully remove the false "silent" verdict for a live 503?',
        'criteria': {'true': 'Removes it', 'false': 'Another path still misreads a live daemon'}},
    'also_compact': {'type': 'noul', 'instructions':
        'Should probes additionally move to a compact liveness reply so body growth cannot reintroduce this?',
        'criteria': {'true': 'Add the compact reply too', 'false': 'The bounded cap is enough'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
