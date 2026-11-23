"""Jev as a guide for the blind side of the map: which blind techniques can honestly move.

Fixed engineering metadata only, in the same form as `coverage_next_advisory`.
Jev ranks; code applies the same policy; nothing here promotes a technique.
"""
import json
import sys

from jarvis.response import jev
from scripts.reviews import coverage_next_advisory as base

CANDIDATES = {
    'T1571 Non-Standard Port': 'network events: a script host or a system utility that seldom connects '
                               'out by itself reaches a public address on a port outside web, mail, DNS and time',
    'T1205 Traffic Signaling': 'an existing collector reports any process holding a raw packet socket; '
                               'the same finding is already counted for network sniffing',
    'T1039 Data from Network Shared Drive': 'a new rule reports a copy tool run with a network share as its source',
    'T1074 Data Staged': 'a new rule reports an archive or a bulk copy written into a public or temporary '
                         'staging directory',
    'T1119 Automated Collection': 'a new rule reports one command that searches recursively for document '
                                  'types by extension and copies what it finds',
    'T1080 Taint Shared Content': 'a new rule reports a program, script or shortcut being copied onto a network share',
    'T1491 Defacement': 'a new rule reports the desktop wallpaper being changed from a command line',
    'T1678 Delay Execution': 'a new rule reports a loopback ping with a large count, or a long timeout, '
                             'used as a sleep inside a command',
    'T1497 Virtualization/Sandbox Evasion': 'a new rule reports queries for hardware an emulator lacks, '
                                            'such as the thermal zone or the fan',
    'T1011 Exfiltration Over Other Network Medium': 'a new rule reports the Bluetooth file-transfer '
                                                    'program being started to send a file',
    'T1072 Software Deployment Tools': 'a new rule reports a software-deployment agent starting a shell; '
                                       'no such agent is installed on this machine',
    'T1005 Data from Local System': 'a new rule reports a copy tool reading browser profile databases, '
                                    'password-manager files, private keys or wallet files',
    'T1030 Data Transfer Size Limits': 'a new rule reports an archive being split into fixed-size volumes',
    'T1029 Scheduled Transfer': 'a new rule reports a scheduled task or timer whose action is an upload tool',
    'T1132 Data Encoding': 'a new rule reports a shell pipeline that encodes data and hands it to a network tool',
    'T1573 Encrypted Channel': 'a new rule reports a TLS client tool used to carry an interactive shell',
    'T1095 Non-Application Layer Protocol': 'a new rule reports a network utility carrying a shell over '
                                            'UDP, or the name of a tunnel-over-ping tool',
    'T1559 Inter-Process Communication': 'an existing rule reports a document application starting a '
                                         'script host; it is already counted for exploitation and for user execution',
    'T1499 Endpoint Denial of Service': 'a new rule reports a fork-bomb pattern or a stress tool on the command line',
    'T1020 Automated Exfiltration': 'a new rule reports one command that loops over files and uploads each',
}


def questions():
    saved, base.CANDIDATES = base.CANDIDATES, CANDIDATES
    try:
        return base.questions()
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
