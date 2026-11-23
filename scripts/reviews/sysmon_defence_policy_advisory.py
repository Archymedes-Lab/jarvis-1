"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'close four measured blind spots in the Windows Sysmon policy without refilling the '
            'driver queue at boot (41,383 events were dropped at the last boot, 39,612 of them registry)',
    'changes': {
        'image_load': 'ImageLoad recorded only when Signed is false; signed loads (the bulk of boot '
                      'volume) stay unrecorded; this lets the existing unsigned-DLL and side-load '
                      'detectors fire for the first time',
        'browser_access': 'ProcessAccess recorded for chrome, msedge, firefox, brave targets when the '
                          'source is not the same browser; detector reports VM_READ opens high, '
                          'other non-query opens medium, query-only opens nothing; Defender, csrss, '
                          'svchost, explorer, WerFault, shell hosts are expected and silent',
        'registry': 'value families added: Defender Exclusions and Real-Time Protection, Defender '
                    'policy, CLSID InprocServer32, LSA *Packages, AMSI Providers, WMI Autologger Start; '
                    'six deterministic rules with positive and benign samples replayed by the suite',
        'not_added': 'ClipboardChange (would archive clipboard text), RawAccessRead, loopback '
                     'NetworkConnect, signed ImageLoad',
    },
    'unknowns': {
        'boot_volume': 'unsigned image loads and browser opens at boot are unmeasured on this host; '
                       'the only measurement will be the boot-drop count after the owner applies the '
                       'policy and reboots',
        'false_positives': 'password managers, accessibility tools and screen readers open browser '
                           'memory legitimately; none are on the expected list',
    },
    'validation': '90 targeted tests pass (rule samples, policy structure, detector severities); '
                  'full suite running; the policy is applied only by the owner through one elevated '
                  'prompt with hash check, backup and rollback',
}
QUESTIONS = {
    'boot_safe': {'type': 'noul', 'instructions':
        'Given changes and unknowns.boot_volume, is restricting ImageLoad to unsigned images and '
        'ProcessAccess to cross-program browser opens a design that is unlikely to re-create the '
        'boot-time queue overflow the policy revision was meant to cure?',
        'criteria': {'true': 'Unlikely to overflow', 'false': 'Likely to add enough volume to overflow'}},
    'browser_severity': {'type': 'noul', 'instructions':
        'Is "high for a memory-read open of a browser by an unrecognised program, medium without read '
        'rights, silent for query-only" a proportionate severity ladder given unknowns.false_positives?',
        'criteria': {'true': 'Proportionate', 'false': 'Too loud or too quiet'}},
    'top_risk': {'type': 'choice', 'instructions':
        'Which is the most likely way this policy change causes harm or noise once applied?',
        'criteria': {
            'boot_overflow': 'unsigned loads or browser opens at boot overflow the driver queue again',
            'password_manager_noise': 'legitimate password managers or accessibility tools are reported high',
            'com_installer_noise': 'installers writing CLSID InprocServer32 values fire the COM hijack rule',
            'none_significant': 'no significant harm or noise expected'}},
    'measure_first': {'type': 'noul', 'instructions':
        'Should the owner read the boot-drop count and the new finding volume after one reboot before '
        'this policy is called an improvement, rather than trusting the test suite?',
        'criteria': {'true': 'Yes, measure after a reboot', 'false': 'Tests suffice'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
