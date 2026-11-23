"""Jev as a guide for the removable-media rules: how each should be counted.

Fixed engineering metadata only, in the same form as `coverage_next_advisory`.
Jev ranks; code applies the same policy; nothing here promotes a technique.
"""
import json
import sys

from jarvis.response import jev
from scripts.reviews import coverage_next_advisory as base

SEEN = ('process-start events name the drive a program ran from; the kind of drive is read from '
        'Windows when a process names a drive that is not an internal disk; no removable drive '
        'has been attached to this machine since the rule was written')
CANDIDATES = {
    'T1091 Replication Through Removable Media': 'a new rule reports any program started from a '
                                                 'removable drive or a USB disk; ' + SEEN,
    'T1025 Data from Removable Media': 'a new rule reports a command-line copy tool reading from a '
                                       'removable drive; files dragged in the file manager start no '
                                       'process and are not seen; ' + SEEN,
    'T1052 Exfiltration Over Physical Medium': 'a new rule reports a command-line copy tool writing to '
                                               'a removable drive; files dragged in the file manager '
                                               'start no process and are not seen; ' + SEEN,
}
DETACHED = {
    'type': 'noul',
    'instructions': 'A program ran from a drive letter that was gone by the time the kind of drive '
                    'could be read, so it may have been a removable drive, a network drive or a '
                    'mounted disk image. Should this be reported to the owner of `machine`, worded '
                    'as a drive that is no longer attached?',
    'criteria': {'true': 'Report it, saying the kind of drive is unknown',
                 'false': 'Stay silent, because the kind of drive is unknown'}}


def questions():
    saved, base.CANDIDATES = base.CANDIDATES, CANDIDATES
    try:
        return dict(base.questions(), detached=DETACHED)
    finally:
        base.CANDIDATES = saved


if __name__ == '__main__':
    try:
        result = jev._call(base.STATE, questions(), timeout=60)
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
        sys.exit(0)
    answers = result['answers']
    for key in CANDIDATES:
        count, noise = answers[f'{key}__count'], answers[f'{key}__noise']['noul']
        print(json.dumps({'candidate': key.split()[0], 'count': count['choice'],
                          'p': {k: round(v, 2) for k, v in count['probabilities'].items()},
                          'noise': round(noise, 2),
                          'build_as': count['choice'] if count['choice'] in base.BUILD else
                          ('held' if count['choice'] == 'claimed' else 'drop'),
                          'measure_noise_first': noise >= base.NOISE_LIMIT}))
    print(json.dumps({'report_detached_drive': round(answers['detached']['noul'], 2)}))
