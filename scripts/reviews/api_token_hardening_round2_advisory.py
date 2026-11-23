"""Fixed engineering metadata only; advisory, never deployment authorization.

Second bounded Jev review of ARGUS-2026-001 (2026-10-30): the two trade-offs the
owner left to engineering judgment. No tokens, source, request contents or
security evidence are sent.
"""
import json

from jarvis.response import jev

STATE = {
    'service': 'loopback-only HTTP dashboard and API of a local security daemon; every '
               'data route now needs a per-start token or a paired, revocable client token',
    'geo_page': {
        'need': 'a 3D globe with tiled satellite imagery, entities, camera flights and picking',
        'option_cdn_pinned': 'load the globe engine from one CDN at an exact version '
                             '(1.121.1), SRI hashes on the script and stylesheet tags, CSP '
                             'restricted to that exact versioned directory; its web workers '
                             'and assets are fetched by the engine and cannot carry SRI',
        'option_vendor': 'ship the engine in the package: about 11.7 MB of the 19.7 MB build '
                         '(the owner set a 10 MB bar for vendoring)',
        'option_rewrite': 'rebuild the page on an already vendored 3D library: large rewrite '
                          'of imagery layers, entities, flights and picking',
        'page_privilege': 'the page is same-origin with the API and its session cookie',
    },
    'cli_store_access': {
        'situation': 'the daemon moves to its own account; about 40 CLI commands read its '
                     'store directly, which the owner account can no longer do',
        'chosen': 'those commands refuse and print a sudo wrapper that runs them as the '
                  'daemon account; API callers use paired client tokens',
        'rejected': 'a generic API route that runs any CLI command inside the daemon',
    },
}
QUESTIONS = {
    'geo_choice': {'type': 'choice', 'instructions':
        'Given `geo_page`, which option best balances the risk of remote code running in the '
        'API origin against package size and rewrite effort?',
        'criteria': {
            'cdn_pinned': 'keep the exact-version CDN with SRI and a path-restricted CSP',
            'vendor': 'vendor the engine despite exceeding the 10 MB bar',
            'rewrite': 'rewrite the page on the already vendored library',
        }},
    'geo_worker_gap': {'type': 'noul', 'instructions':
        'With `option_cdn_pinned`, is the inability to pin the engine\'s workers and assets '
        'with SRI a material residual risk that should be reported to the owner?',
        'criteria': {'true': 'Yes, report it as residual', 'false': 'No, negligible'}},
    'cli_choice_sound': {'type': 'noul', 'instructions':
        'Is `cli_store_access.chosen` a sound interim design compared with the rejected '
        'generic command route?',
        'criteria': {'true': 'Sound interim design', 'false': 'Unsound'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
