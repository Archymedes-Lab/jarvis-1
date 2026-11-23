"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'problem': 'one 477 GB NVMe, one volume; WSL ext4.vhdx 246 GB (223 GB used inside) grows and never '
               'shrinks; automatic page file 12.4 GB; host 16 GB RAM with 326 MB free; the drive hit 0.1 GB '
               'free twice (2026-10-11, 2026-10-23) and each time the WSL VM suffocated and was relaunched',
    'design': {
        'layer1_capacity_owner': 'sparse mode on the image (or scheduled diskpart compaction), fixed 8 GB '
                                 'page file, one-time reclaim of ~42 GB of owner caches by the owner',
        'layer2_headroom_jarvis': 'storage collector every 30 min: host drive free, image size vs in-guest '
                                  'used (overhang > 20 GB = compaction due), page-file policy, ballast '
                                  'presence, bounded sizes of known reclaimables; critical < 2 GB, high < 8 GB; '
                                  'prunes only JARVIS-made superseded release stages beyond the newest three',
        'layer3_ballast': 'a 4 GB pre-created file in the owner profile; when the drive measures below 2 GB '
                          'free and the file exists, JARVIS deletes it, logs the act and pages the owner; it '
                          'never recreates it automatically',
    },
    'invariants': ['JARVIS never deletes owner data', 'the only automatic act is releasing the ballast',
                   'store and sealed history are never pruned by this governor',
                   'every unmeasurable item is a visibility finding'],
    'rejected': ['automatic cache purge (owner data)', 'moving the image (no second disk)',
                 'user.slice memory ceiling (declined by owner 2026-10-23; memory lever, not disk)'],
}
QUESTIONS = {
    'ballast_bounded': {'type': 'noul', 'instructions':
        'Is deleting a file that JARVIS itself reserved in advance for this purpose, when the drive is '
        'below a written critical line, a bounded automatic intervention consistent with the invariants?',
        'criteria': {'true': 'Bounded and consistent', 'false': 'Crosses the line'}},
    'sparse_risk': {'type': 'noul', 'instructions':
        'Given that Microsoft documents a corruption risk for sparse WSL images when the host disk fills '
        'mid-write, is recommending sparse mode plus a 2 GB critical / 8 GB high headroom guard a '
        'reasonable trade on a machine that has already filled its disk twice?',
        'criteria': {'true': 'Reasonable with the guard', 'false': 'Prefer scheduled compaction only'}},
    'headroom_numbers': {'type': 'choice', 'instructions':
        'Which critical/high headroom pair best fits a 474 GB drive whose page file can grow by several GB '
        'in minutes and whose WSL image grows with every guest write?',
        'criteria': {'two_eight': '2 GB critical, 8 GB high', 'five_fifteen': '5 GB critical, 15 GB high',
                     'ten_thirty': '10 GB critical, 30 GB high', 'one_four': '1 GB critical, 4 GB high'}},
    'missing_piece': {'type': 'choice', 'instructions':
        'What is the most important thing this design still lacks?',
        'criteria': {'growth_rate': 'a measured growth rate so the owner is warned days ahead, not at the line',
                     'guest_write_throttle': 'JARVIS reducing its own bulk writes under disk pressure',
                     'host_app_inventory': 'knowing which Windows folders hold the other 200 GB',
                     'nothing_major': 'nothing major'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
