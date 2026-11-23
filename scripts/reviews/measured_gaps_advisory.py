"""Bounded fixed engineering metadata only; advisory, never action authority."""
import json

from jarvis.response import jev

STATE = {
    'baseline': {'linux_cases': 16, 'marker_linked': 11, 'high_or_critical': 10,
                 'missing_classes': ['profile startup', 'dormant PHP dispatcher', 'root cron',
                                     'history link to sink', 'legacy boot script']},
    'constraints': ['local read-only observations', 'no source or command arguments retained',
                    'stable complete reads without ancestor symlinks', 'explicit resource and visibility budgets',
                    'advisory findings stay non-authoritative after persistence',
                    'unchanged cases plus independent benign and failure controls'],
    'startup_options': {
        'literal_invocation': 'Bounded shell command-position parsing of literal staging paths, executable boot-script inspection and metadata-only history sink links.',
        'all_unowned': 'Report all unowned profiles and cron files, including ordinary customization.',
        'more_keywords': 'Add more offensive command names only.'},
    'php_options': {
        'direct_flow': 'Bounded lexical probe for direct request data passed to a command executor, ignoring comments and quoted examples; run on dormant files too.',
        'cooccurrence': 'Report any file mentioning both request data and an executor, even in independent statements.',
        'native_engine_first': 'Require a new full native language/rule engine before covering the measured direct form.'},
}
QUESTIONS = {
    'startup': {'type': 'choice', 'instructions': 'Which initial startup design best meets `constraints` while closing the measured missing classes without treating normal customization as compromise?', 'criteria': STATE['startup_options']},
    'php': {'type': 'choice', 'instructions': 'Which PHP design is the narrowest useful next step for the dormant direct-flow case under `constraints`?', 'criteria': STATE['php_options']},
    'authority': {'type': 'noul', 'instructions': 'Do these static observations alone establish authorization for automatic containment?', 'criteria': {'true': 'They establish authority', 'false': 'They remain advisory evidence requiring independent policy and identity'}}
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=20)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
