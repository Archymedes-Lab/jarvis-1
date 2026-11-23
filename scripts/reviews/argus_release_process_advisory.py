"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'make the Argus release and deploy process safe and standard',
    'found': ['downloads and SHA256SUMS served from the same origin, no signature',
              'any collaborator with push can deploy production; branch protection unavailable on the plan',
              'two releases built from a local working-tree snapshot that exists in no pushed commit',
              'GitHub Actions pinned by movable tags, Vercel CLI by major version',
              'Windows installers unsigned (no Authenticode)', 'deb maintainer placeholder',
              'build host is a shared development machine'],
    'changes': ['release.py: preflight (commit on private remote), build, VM test, offline ssh-keygen signature, '
                'path-limited publish to a preview branch, explicit promote with live readback; each stage '
                'refuses unless earlier stages passed for the same manifest digest',
                'CI: actions pinned by commit SHA, vercel CLI exact version, read-only token, and a deploy gate '
                'that verifies the downloads signature against a signer fingerprint stored in an admin-only '
                'repository variable'],
}
QUESTIONS = {
    'biggest_remaining': {'type': 'choice', 'instructions':
        'After these changes, which remaining risk most deserves the owner\'s next step?',
        'criteria': {'authenticode': 'Unsigned Windows installers',
                     'key_custody': 'Custody of the offline signing key',
                     'build_host': 'Shared development machine as build host',
                     'reviews': 'No enforced code review on the site repository',
                     'uncertain': 'Insufficient information'}},
    'signer_variable': {'type': 'noul', 'instructions':
        'Does pinning the signer fingerprint in an admin-only repository variable stop a collaborator who '
        'can push but is not an admin from deploying swapped downloads?',
        'criteria': {'true': 'Yes', 'false': 'No'}},
    'commit_only': {'type': 'noul', 'instructions':
        'Is refusing to build from anything but a commit already on the private remote worth the extra step, '
        'compared with building from a local working-tree snapshot?',
        'criteria': {'true': 'Yes', 'false': 'No'}},
    'same_origin_key': {'type': 'noul', 'instructions':
        'Is a public key served next to the downloads sufficient for users to verify releases without '
        'checking its fingerprint against an independent channel?',
        'criteria': {'true': 'Sufficient', 'false': 'Not sufficient'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
