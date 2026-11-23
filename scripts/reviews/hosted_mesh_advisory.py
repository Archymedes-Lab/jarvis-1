"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'alternatives': ['Cloudflare SQLite Durable Objects', 'Vercel plus external store', 'both immediately'],
    'selected': 'Cloudflare SQLite Durable Objects',
    'privacy': 'encrypted allowlisted pseudonymous process projection; origin key stays local',
    'authority': 'explicit user requested hosting and continuous publication; model advisory only',
    'invariants': ['authenticated before allocating storage', 'transactional contiguous append',
                   'no delete endpoint or automatic pruning', 'durable commit before receipt',
                   'baseline declares historical prefix unreplicated', 'single-writer supervised publisher',
                   'bounded retries and requests', 'explicit freshness and outage gaps'],
    'limits': ['same account administrators can delete', 'network metadata leaks',
               'host sleep prevents publication', 'keys need independent protected backup'],
}
QUESTIONS = {
    'design': {'type': 'choice', 'instructions':
        'Which alternative best fits the stated integrity, bounds and operator scope?',
        'criteria': {'cloudflare': 'Cloudflare SQLite Durable Objects', 'vercel': 'Vercel plus store',
                     'both': 'Both immediately', 'uncertain': 'Insufficient information'}},
    'privacy': {'type': 'noul', 'instructions':
        'Do metadata leakage and pseudonymization prevent a full anonymity claim?',
        'criteria': {'true': 'Full anonymity unproven', 'false': 'Full anonymity proven'}},
    'custody': {'type': 'noul', 'instructions':
        'Can account administration, local key loss and host outages still defeat survival or continuous capture?',
        'criteria': {'true': 'Explicit limits remain', 'false': 'Guaranteed continuous immutable recovery'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    if STATE['phase'] == 'implementation':
        STATE['validation'] = {
            'hosted_storage_tests': '9 passed including transaction rollback, durability failure and invalid signatures',
            'typescript': 'strict check and Worker build passed',
            'python_full_suite': '1982 passed on final source; prior scheduler timing failure passed isolated and full rerun',
            'publisher_release_tests': '15 publisher/release tests passed; changed dependency refused startup',
            'real_runtime': 'local workerd Python signed append, duplicate, retrieval/decryption and head verified',
            'deployment': 'new cloud Worker deployed; signing-secret upload denied by automatic approval review',
            'live_custody': 'unverified; no protected history sent; publisher not started',
            'edge': 'default Python agent refused; truthful application agent reaches unprovisioned 503',
            'protected_service': 'ready and protection_healthy true on fresh readback',
        }
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
