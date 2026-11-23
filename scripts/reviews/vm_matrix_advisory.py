"""Fixed metadata only; advisory on the clean-machine matrix harness (release/vmtest/).

No command lines, file contents or results are sent: only the shape of the design and
its tests. The answers cannot approve a run, a release or an assurance promotion."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'measure a signed security monitor release installing, running, rebooting, upgrading and '
            'uninstalling on fresh Ubuntu and Debian virtual machines, as evidence before a paid service',
    'design': {
        'release_trust': 'checksum list must verify against a releaser key that is both listed and pinned by '
                         'the owner; package must be listed and match; the guest re-hashes what it installs',
        'image_trust': 'Ubuntu images: checksum list signature verified against a pinned key in a lab-only '
                       'keyring; Debian publishes no signature, so its image comes from a fixed dated directory '
                       'over HTTPS and every result is labelled https-only',
        'isolation': 'unchanged lab: network-less container, only the KVM device, copy-on-write overlay '
                     'over a base image re-verified after the run; container and run folder removed on every '
                     'path including interruption',
        'reboot': 'guest may reboot once; a one-shot unit marks itself started before any work so it never '
                  'runs twice; the run timeout bounds the whole cell',
        'verdicts': 'nine scenarios each pass, fail or not run; missing data is not run, never pass; '
                    'footprint compared with an owner budget',
        'tests': '56 unit tests with recorders instead of docker; mutation checks caught 5 of 6 breaks '
                 '(the sixth is covered by a duplicate comparison)',
    },
}
QUESTIONS = {
    'debian_https_ok': {'type': 'noul', 'instructions':
        'Is an unsigned Debian cloud image fetched over HTTPS from a fixed dated directory, labelled '
        'https-only in every result, acceptable for pre-sales install evidence?',
        'criteria': {'true': 'Yes, with the label', 'false': 'No, it needs another trust anchor first'}},
    'top_gap': {'type': 'choice', 'instructions':
        'Which remaining gap most weakens this harness as evidence?',
        'criteria': {'no_network': 'The guest has no network, unlike a real server',
                     'one_vcpu': 'One small virtual machine is not representative of client servers',
                     'no_upgrade_source': 'Only one signed release exists, so upgrade cannot be measured yet',
                     'unit_tests_only': 'The harness is unit-tested with fakes, not yet run end to end',
                     'debian_trust': 'The Debian image trust is HTTPS only'}},
    'smoke_first': {'type': 'noul', 'instructions':
        'Should a short smoke run with a two-minute idle window come before the one-hour runs?',
        'criteria': {'true': 'Yes', 'false': 'No, go straight to the full runs'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=20)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
        sys.exit(0)
