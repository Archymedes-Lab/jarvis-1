"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'change': [
        'registry-write rules report a change whatever program made it, beside the command rules',
        'each technique row carries the number of separately proven procedures',
        'a technique with two kinds of proof regresses when either stops firing',
        'three techniques recognised only by one attack tool, and three untested ones, are held at claimed',
        'one technique previously counted as validated on one tool\'s syntax was moved back to claimed',
    ],
    'live_before': {'validated': 89, 'claimed': 25, 'blind': 72},
    'projected': {'validated': 91, 'claimed': 31, 'blind': 64, 'validated_more_than_one_way': 49},
    'measured': {
        'recorded_events_replayed_through_the_detector': 752569,
        'findings_from_new_rules_on_that_history': 0,
        'false_positives_found_and_fixed_before_scoring': 2,
        'probes': '121 fire inside the checkout',
    },
    'limits': ['registry rules are silent for keys the event policy does not record',
               'a count of procedures is not a measure of how much of a technique is covered',
               'no adversary emulation'],
}
QUESTIONS = {
    'ways_shown': {'type': 'choice', 'instructions':
        'The page can state how many separate procedures are proven for a validated technique. '
        'Which presentation is least likely to be over-read as completeness?',
        'criteria': {'text_in_detail': 'State the number only in the detail text for that technique',
                     'headline_count': 'Also show how many techniques are proven more than one way in the summary',
                     'brightness': 'Scale the pane brightness by the number',
                     'omit': 'Do not show it'}},
    'demotion': {'type': 'noul', 'instructions':
        'Is moving a technique from validated back to claimed, because its only proof is one named '
        'tool\'s syntax, consistent with holding three new single-tool techniques at claimed?',
        'criteria': {'true': 'Consistent: the same rule is applied to old and new',
                     'false': 'Inconsistent or unnecessary'}},
    'silent_registry': {'type': 'noul', 'instructions':
        'Should a registry rule that is silent because the event policy does not record its key '
        'count toward a technique being proven on that machine?',
        'criteria': {'true': 'It may count', 'false': 'It must not count unless the key is recorded'}},
}
# Second review in the same round: the inventory-baseline fix found while reading the score.
BASELINE_STATE = {
    'component': 'an inventory that compares what is installed now with what was recorded on the previous run',
    'defect_measured': 'one run could not read a mounted drive after standby, recorded the smaller '
                       'inventory as the baseline, and the next run reported 23 long-installed items as new',
    'invariants': ['a real addition or change is still reported once the source is readable again',
                   'a real removal from a readable source is still reported',
                   'a source that could not be read is stated, never silent',
                   'the stored baseline never grows from data that was not observed'],
    'tests': 'outage then return; install and version change during the outage; real uninstall; '
             'one directory erroring while another is compared; unreadable first run',
}
BASELINE_QUESTIONS = {
    'design': {'type': 'choice', 'instructions':
        'Which handling of a source that could not be read on one run best preserves the listed invariants?',
        'criteria': {
            'keep_recorded': 'Keep what was recorded for the unread source, compare the readable sources '
                             'as usual, and report that part of the inventory was not re-read',
            'skip_run': 'Skip the whole comparison on any run where some source could not be read',
            'tombstones': 'Record the entries as removed and suppress a later "new" report for anything '
                          'removed within a set number of days',
            'unchanged': 'Record the smaller inventory and report the entries as new when they return'}},
    'hides_install': {'type': 'noul', 'instructions':
        'With the recorded entries kept for an unread source, could an item installed during the outage '
        'go unreported after the source becomes readable again?',
        'criteria': {'true': 'It could go unreported', 'false': 'It would still be reported'}},
    'gap_severity': {'type': 'choice', 'instructions':
        'What severity fits the statement that part of the inventory could not be re-read on this run, '
        'given that a separate self-audit already reports the unreadable drive itself?',
        'criteria': {'low': 'Low: visible, does not move a security verdict',
                     'medium': 'Medium: lost visibility deserves attention',
                     'high': 'High: treat as a possible compromise'}},
}

if __name__ == '__main__':
    import sys
    if '--baseline' in sys.argv:
        STATE, QUESTIONS = BASELINE_STATE, BASELINE_QUESTIONS
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
