"""Fixed engineering metadata only; advisory, never deployment or design authorization."""
import json

from jarvis.response import jev

STATE = {
    'change': 'hosted licence service: subscription grace raised from 3 to 14 days to match the end-user '
              'licence; a daily scheduled purge deletes licence records one year after the licence ended',
    'ended_definition': 'revoked with a revocation time, or lapsed where the stored expiry already includes '
                        'the grace period; records with no end are never purged',
    'purge_shape': 'select up to 200 due licences per run; for each delete child rows (activations, releases, '
                   'claims, audit) before the licence row; one count-only audit row per run; idempotent',
    'tests': ['due lapsed and revoked licences removed with all children', 'active, recently ended, exact '
              'one-year boundary, recently revoked, no-end and revoked-without-time kept', 'batch bound and '
              'continuation across runs', 'failure mid-run leaves the licence row and is retried next run',
              'cron and handler wiring', 'grace constant pinned to the licence text'],
    'not_transactional': 'each delete is its own statement; a failure can leave a licence with no children '
                         'until the next run',
    'payment_records': 'kept by the payment provider under its own policy',
}
QUESTIONS = {
    'top_risk': {'type': 'choice', 'instructions':
        'Which property of this purge most deserves another check before deploy?',
        'criteria': {'wrong_end': 'A licence still in use being judged ended and deleted',
                     'partial_delete': 'Non-transactional deletes leaving a licence without its children for a day',
                     'refund_window': 'Records needed for a refund or dispute being gone too early',
                     'unbounded': 'Run time or row count growing without bound',
                     'none': 'No further check needed beyond the tests'}},
    'grace_change_safe': {'type': 'noul', 'instructions':
        'Is raising the post-expiry grace from 3 to 14 days, applied to newly issued and renewed '
        'licences only, safe for existing customers?',
        'criteria': {'true': 'Safe', 'false': 'Unsafe without a migration or notice'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
