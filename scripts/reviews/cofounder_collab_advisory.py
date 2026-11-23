"""Fixed design metadata only (no keys, emails or code); advisory, never authorization."""
import json

from jarvis.response import jev

STATE = {
    'context': 'two cofounders (both org admins), several AI coding agents, private repo, CI budget stops at $0, '
               'push-only CI',
    'licence_grant': {
        'what': 'operator command creating a complimentary product licence with no payment behind it',
        'storage': 'only HMAC hashes of key and email stored; key shown once to the operator',
        'isolation': 'synthetic session id never matched by payment webhooks, refunds or the receipt page',
        'bounds': 'end date at most 366 days; seats bounded by the plan maximum; audit row with role only',
        'tests': 'activation, seat limit, payment-event isolation, expiry refusal, SQL-text equivalence, bad input',
    },
    'collaboration': {
        'main': 'pull request only; no force push or deletion; required CI checks; no bypass actors',
        'review': 'ordinary code merges on green CI with no reviewer; trust-anchor paths (workflows, release, '
                  'licensing, security docs, agent rules) need the other cofounder via code owners',
        'local_gate': 'pre-push hook runs lint, types and changed tests before CI',
        'agents': 'one agent per worktree and branch; agents on a non-owner machine never deploy',
    },
}
QUESTIONS = {
    'grant_safe': {'type': 'noul', 'instructions':
        'Is this complimentary-licence design safe to use for giving a cofounder a licence?',
        'criteria': {'true': 'Yes', 'false': 'No'}},
    'review_balance': {'type': 'choice', 'instructions':
        'For two cofounders plus agents, which review policy best balances speed and safety?',
        'criteria': {'codeowner_paths': 'Green CI merges; only trust-anchor paths need the other cofounder',
                     'all_reviewed': 'Every pull request needs the other cofounder',
                     'none': 'No required reviews at all'}},
    'top_gap': {'type': 'choice', 'instructions': 'Which remaining collaboration gap matters most?',
        'criteria': {'ci_outage': 'Required checks stop all merges when CI minutes run out',
                     'admin_power': 'Both admins can still edit the rules themselves',
                     'ownership_unclear': 'Area ownership is a guess until both confirm it',
                     'secrets': 'Production secrets in one shared password manager'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
