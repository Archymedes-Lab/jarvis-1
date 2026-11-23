"""Fixed licensing metadata only; advisory, never legal advice or release authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'make ARGUS-1 unambiguously proprietary commercial software and ship every notice its '
            'third-party components require',
    'found': {
        'own_manifest': 'the product runtime crate declared MIT',
        'artifacts': 'no release artifact carried any licence; the SBOM had no licence data',
        'copyleft': 'the shipped server binary bundled GNU Readline (GPL-3.0) via the Python runtime',
        'site': 'the company site says open source first and never states the Argus licence',
    },
    'change': {
        'licence': 'draft EULA for the object code, licensor Archymedes Inc being incorporated, marked DRAFT',
        'manifests': 'own crates and packages declare the proprietary licence and cannot be published',
        'notices': '497 components, each mapped to a permitted licence with texts; MPL items list source',
        'packaging': 'licence and notices inside every package and beside the Windows exe',
        'gate': 'the release gate refuses any copyleft library by name; it refuses the published '
                'release for exactly the two readline files',
        'build': 'compiler told not to include readline; not yet proven by a CI build (CI is blocked)',
    },
}
QUESTIONS = {
    'resolves_ambiguity': {'type': 'noul', 'instructions':
        'Does this change remove the ambiguity about whether ARGUS-1 is open source or commercial for a '
        'buyer reading the artifacts?', 'criteria': {'true': 'Yes', 'false': 'Ambiguity remains'}},
    'top_risk': {'type': 'choice', 'instructions': 'Which remaining licensing risk matters most before selling?',
        'criteria': {'entity': 'The licensor company does not exist yet',
                     'placeholders': 'Governing law, refunds, privacy and contact are unfilled',
                     'build_unproven': 'Readline removal not yet proven by a real build',
                     'site': 'The site still never states the Argus licence',
                     'openssl': 'An out-of-support OpenSSL 1.1 ships in the server binary'}},
    'keep_draft': {'type': 'noul', 'instructions':
        'Should releases keep the DRAFT marker until the company exists and counsel reviews the text?',
        'criteria': {'true': 'Yes', 'false': 'No, ship it as final'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
