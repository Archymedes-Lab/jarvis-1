"""Fixed engineering metadata only; advisory, never deployment or design authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'no customer install ever needs or accepts the seller payment-provider secret; the web dashboard '
            'buys through the same hosted licence-claim flow and prices as the desktop app',
    'removed': ['daemon module that read a seller payment secret from a local config file and called the '
                'payment API itself', 'four local routes: status, checkout, confirm, signed webhook',
                'desktop shell commands for the local checkout', 'two docs telling owners to set the secret locally'],
    'replaced_by': 'browser and classic dashboard call the existing daemon licence routes (state, upgrade, poll); '
                   'the checkout page opens only after an allow-list check identical to the desktop shell '
                   '(fixed origin, fixed offers, claim id of 32 symbols)',
    'prices': 'desktop view imports one price module pinned by test to the hosted lookup keys; the static '
              'classic dashboard keeps literal amounts pinned by test to that module',
    'tests': ['source scan of the shipped package and built web bundle for payment API host, secret config '
              'names, key literals, webhook header, local billing routes', 'real HTTP handler with a planted '
              'secret in env and old config: old routes 404, upgrade returns hosted claim link, failed claim is an '
              'ordinary error without fallback', 'browser route table and allow-list tests', 'licence never gates '
              'protection test unchanged and green'],
    'hosted_service': 'records per-licence livemode from the paying session; added a read-only health field '
                      'giving only the mode word from the key prefix; not deployed',
    'not_done': ['no live purchase made', 'worker change undeployed', 'old local licence records in the store '
                 'meta are now ignored (protection unaffected)'],
}
QUESTIONS = {
    'remaining_gap': {'type': 'choice', 'instructions':
        'Which remaining gap most deserves another validation before merge?',
        'criteria': {'bundle_drift': 'The built web bundle drifting from source and reintroducing old calls',
                     'price_pinning': 'Static classic dashboard prices pinned by test rather than shared at runtime',
                     'allow_list': 'The checkout allow-list duplicated in three languages',
                     'old_records': 'Previously stored local licence records being ignored',
                     'none': 'No further validation needed beyond CI'}},
    'scan_sufficient': {'type': 'noul', 'instructions':
        'Is a source scan of the shipped package plus an HTTP test with a planted secret a sufficient '
        'regression guard against a seller-secret payment path returning to customer installs?',
        'criteria': {'true': 'Sufficient as a regression guard', 'false': 'Insufficient; another guard is needed'}},
    'health_mode_safe': {'type': 'noul', 'instructions':
        'Is publicly reporting only the word live or test, derived from the configured key prefix, on an '
        'unauthenticated health endpoint an acceptable disclosure?',
        'criteria': {'true': 'Acceptable disclosure', 'false': 'Should not be public'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
