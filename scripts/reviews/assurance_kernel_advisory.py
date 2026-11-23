"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'a verification framework a security monitor ships inside itself, so every installed copy '
            'can re-check its own invariants, and the build and installer refuse a copy that fails',
    'today': {
        'rungs': 'lint and type gate on four packages; 11 seeded property checks; 4 exhaustive models, 3 '
                 'driving real code; a daily job and install-time gate run them; 12 invariants live as a '
                 'table in a document, each check wired by hand',
        'measured_gaps': 'two elevated launches still run a script file from the user temp folder; the '
                         'response ladder that applies containment automatically has no model; no check '
                         'evaluates invariants over live state',
        'constraint': 'runtime must stay standard-library only; nothing may be installed for the gates',
    },
    'designs': {
        'A': 'extend the in-tree ladder: an invariant registry every check must map to, a shipped rule '
             'engine over Python syntax trees and script text for the product\'s own bug classes, a model '
             'that drives the real response-ladder code, and runtime monitors reusing the same predicates',
        'B': 'adopt external tools: a third-party static analyser, a property-testing library and a '
             'separate specification language, run only at build time',
        'C': 'keep checks as tests in the repository, not shipped with the product',
    },
}
QUESTIONS = {
    'design': {'type': 'choice', 'instructions':
        'Which design best meets the goal and the standard-library constraint for this product?',
        'criteria': {'A': 'Extend the in-tree ladder (A)', 'B': 'Adopt external tools (B)',
                     'C': 'Tests only (C)', 'uncertain': 'Insufficient information'}},
    'first_slice': {'type': 'choice', 'instructions':
        'Which slice of design A should be built first for the most assurance per effort?',
        'criteria': {'registry_static': 'Invariant registry plus the shipped rule engine with rules for the '
                                        'measured elevation gaps',
                     'ladder_model': 'The response-ladder model driving the real containment code',
                     'runtime': 'Runtime monitors over live state',
                     'uncertain': 'Insufficient information'}},
    'known_violations': {'type': 'noul', 'instructions':
        'When a new rule finds existing violations that need separate work, is it sound to record them '
        'as named, dated known violations the report lists as open (not as passes), and fail only on new '
        'ones?', 'criteria': {'true': 'Sound', 'false': 'Unsound; fix all before enabling the rule'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
