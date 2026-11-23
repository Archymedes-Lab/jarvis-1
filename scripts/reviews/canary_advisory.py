"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'tamper-evident record of planted bait, and a defensive alert to the OWNER when '
            'bait is touched on-box or opened off-box; never any action on the attacker',
    'hard_line': 'tokens are inert data; callback targets are owner-controlled and must be '
                 'configured (no default); nothing contacts, scans, exploits or runs code on '
                 'the attacker or a third party; no hack-back',
    'design': {
        'permanent_ink': 'append-only hash-chained canary journal (same shape as the event log), '
                         'head anchored via OpenTimestamps (32-byte digest only)',
        'onbox_tripwire': 'decoy files fingerprinted at plant time; modified/removed are reliable, '
                          'atime "accessed" is weak and off by default',
        'offbox_callback': 'owner listener writes a JSONL inbox of hits (token, ip, ua, time); '
                           'JARVIS ingests metadata only, bounded read, malformed lines skipped',
        'finding_path': 'normal collector findings; a trip stays reported until the owner retires '
                        'the token; chain-break is critical and halts further journal writes',
    },
    'invariants': [
        'editing, deleting or reordering any journal record is detected and names the first break',
        'a token is inert and runs no code anywhere',
        'callback target is owner-controlled and configured, never defaulted to a third party',
        'absence of a callback never reads as safe; it only ever confirms',
        'JARVIS own access to bait does not trip (it never writes planted decoys)',
        'callback ingestion is metadata only; no attacker payload fetched, stored or executed',
    ],
    'validation': {'tests': '27 unit tests pass: chain verify incl. edit/delete/reorder, inert '
                            'token generation, tripwire modified/removed/weak-access, callback '
                            'ingestion incl. malformed/oversized/dedupe, anchoring with injected '
                            'submit, collector end to end incl. tamper-halts-writes',
                   'not_yet': 'richer Sysmon FileCreate(11)/RawAccessRead(9) read-detection lane; '
                              'owner CLI to plant; live run on the daemon'},
}
QUESTIONS = {
    'stays_defensive': {'type': 'noul', 'instructions':
        'Given the hard_line and invariants, does this design keep the "signal" acting only on '
        'the owner (an alert), with nothing that contacts, scans or runs code on the attacker?',
        'criteria': {'true': 'Yes, defensive only', 'false': 'No, it crosses into acting on the attacker'}},
    'tamper_evident': {'type': 'noul', 'instructions':
        'Does an append-only hash chain whose head is externally anchored make after-the-fact '
        'edits, deletions or reordering of the bait record detectable (not impossible) against '
        'the anchor and an off-box copy?',
        'criteria': {'true': 'Yes, detectable', 'false': 'No, it does not achieve that'}},
    'callback_privacy': {'type': 'noul', 'instructions':
        'Is ingesting only owner-collected connection metadata (address, user-agent, time, token '
        'id) from a bounded local inbox, skipping malformed lines, a safe way to learn the bait '
        'was opened without fetching or trusting attacker content?',
        'criteria': {'true': 'Safe, metadata only', 'false': 'Unsafe'}},
    'onbox_false_positive': {'type': 'noul', 'instructions':
        'Is defaulting the atime-based "accessed" signal OFF (reporting only modified/removed, '
        'which are reliable) the right call to avoid crying wolf on relatime/DrvFs filesystems?',
        'criteria': {'true': 'Right call', 'false': 'Should be on by default'}},
    'validation_gap': {'type': 'noul', 'instructions':
        'Beyond the unit tests, is a live run on the daemon and an owner-facing planting path '
        'still required before calling this feature complete?',
        'criteria': {'true': 'Yes, still required', 'false': 'Unit tests suffice'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
