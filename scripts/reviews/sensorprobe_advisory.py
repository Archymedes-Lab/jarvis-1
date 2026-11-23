"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'prove continuously that the Linux process sensor still sees real events, so a blinded '
            'sensor is reported instead of looking healthy',
    'design': {
        'probe': 'every 15 min one harmless labelled start of a root-owned true program, no shell, '
                 'empty environment, 5 s timeout',
        'sighting': 'ProcessCreate with the resolved probe image and the exact label argument, read '
                    'only from journal records attributed to the root sysmon unit',
        'outcomes': 'seen with latency; not seen in 5 s is re-checked on the next run (late); two '
                    'misses in a row reported high as a possibly blind sensor; a stopped sensor is '
                    'reported as skipped, never ok',
        'origin_fix': 'the existing collector and live process feed matched only the client-set '
                      'identifier; a line from an unprivileged account was accepted; both now use '
                      'trusted journal fields, and the syslog fallback is used only when the '
                      'journal reader cannot run',
    },
    'measured': {
        'live_seen': '10 of 10 probes seen on the real host, median 178 ms, slowest 462 ms, 0.23 s a run',
        'live_negative': 'with the probe not started, the real journal gave low, medium, then high',
        'forgery': 'an unprivileged forged line was in the old query and absent from the trusted one',
        'tests': '24 unit tests incl. false sightings, late, blind and recovery, bounds, origin',
    },
    'limits': [
        'does not exercise the collector cursor and window',
        'Linux process sensor only',
        'a root intruder can forge sensor records or answer the probe',
        'blindness shorter than 15 min is not seen',
    ],
}
QUESTIONS = {
    'design_sound': {'type': 'noul', 'instructions':
        'Given the measurements, does this probe reliably distinguish a working process sensor from '
        'a blinded one without false sightings?',
        'criteria': {'true': 'Yes', 'false': 'There is a hole in that distinction'}},
    'top_gap': {'type': 'choice', 'instructions':
        'Which remaining gap most deserves the next measured test or change?',
        'criteria': {'cursor': 'The collector cursor and window are not exercised',
                     'interval': 'Blindness shorter than the probe interval',
                     'root_forgery': 'A root intruder forging the answer',
                     'other_sensors': 'No probe yet for the Windows sensors and other collectors'}},
    'fallback_change': {'type': 'noul', 'instructions':
        'Is reading syslog only when the journal reader cannot run, instead of whenever the journal '
        'window is empty, the safer behaviour for this sensor?',
        'criteria': {'true': 'Yes', 'false': 'No, it loses real events'}},
    'claim_level': {'type': 'noul', 'instructions':
        'Should this capability stay unverified until a deployed release shows probe receipts from '
        'the running daemon over at least a day?',
        'criteria': {'true': 'Yes, keep it unverified until then', 'false': 'The tests and hand measurement suffice'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
