"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'make the coverage view update within a second and redesign its rendering',
    'feed': {
        'before': 'page polled the full 72 kB summary every 4 s, 15 ms to build',
        'after': 'one full read, then a 2 kB state built in about 2 ms, pushed over a server-sent '
                 'event stream when it changes and rebuilt at most twice a second for all clients',
        'fallback': 'poll the same compact state once a second when the stream is refused or drops',
        'bounds': ['4 open streams', '30 minute stream lifetime', 'read-only database connection',
                   'same-origin check before a slot is taken', 'loopback listener only'],
        'failure': 'unreadable database is sent as an explicit not-ok state; silence for 40 s shows not live',
    },
    'rendering': {
        'meaning_kept': ['pane level', 'collector freshness arc', 'firing only when a stored run timestamp advances',
                         'uptime gauge', 'open serious findings'],
        'new_encodings': ['core colour is the share of collectors current',
                          'inflow motes are events the sensor committed on its last pass',
                          'signal from the core is the scheduler starting a job'],
        'decoration_declared': ['stars', 'dendrite stubs', 'sheen', 'idle drift', 'bloom'],
        'reduced_motion': 'decoration and travel animation off',
    },
    'validation': {
        'unit_tests': '2083 passed',
        'stream': 'a browser held the stream and received 58 state events; slot released on close',
        'rendered': 'both themes and both readings captured on software and hardware GL paths with no shader errors',
        'not_measured': ['frame rate on the owner hardware', 'behaviour over a full 30 minute stream lifetime'],
    },
}
QUESTIONS = {
    'decoration': {'type': 'noul', 'instructions':
        'Could decoration that is declared as such and never driven by data still lead a viewer to '
        'read activity that is not happening?',
        'criteria': {'true': 'A material risk of misreading remains', 'false': 'Declared decoration is not misread'}},
    'liveness': {'type': 'noul', 'instructions':
        'Is showing an explicit not-live state after 40 seconds without an update adequate to stop '
        'the view implying the monitor is running when it is not?',
        'criteria': {'true': 'Adequate', 'false': 'Not adequate'}},
    'feed_risk': {'type': 'choice', 'instructions':
        'Which is the most important remaining risk of the stream design to verify on the live service?',
        'criteria': {'thread_exhaustion': 'Held connections exhausting server threads',
                     'db_contention': 'Frequent reads contending with collectors writing the database',
                     'stale_view': 'The page showing stale state as current',
                     'none': 'No material risk remains'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
