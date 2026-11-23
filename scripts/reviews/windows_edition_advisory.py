"""Fixed engineering metadata only; advisory, never deployment authorization.

The native Windows edition (docs/architecture/WINDOWS-EDITION.md), 2026-11-03.
"""
import json

from jarvis.response import jev

STATE = {
    'goal': 'a Windows PC without WSL gets a working engine from one signed-pipeline download, '
            'binary only, no administrator, adapting its checks to the host',
    'alternatives': {
        'compiled': 'engine compiled natively, PowerShell payloads compiled into the program and '
                    'written per user per release only when a task must run a file; existing '
                    'PowerShell service loop supervises the compiled program; per-user installer',
        'ps1_text': 'same engine but the PowerShell payloads shipped as text files in the download',
        'python_supervisor': 'compiled engine that supervises itself; no PowerShell loop at all',
        'sidecar': 'the desktop window starts and stops the engine as its child process',
    },
    'owner_rules': ['only binaries downloadable', 'no elevation in the default edition',
                    'one install per computer', 'never fabricate coverage'],
    'measured': {
        'unit': '21 tests incl. compiled-copy precedence, byte-exact write-out and repair, '
                'unwritable profile, audit fingerprint, port and one-install refusal, token '
                'privacy, gate refusals of scripts/source/home/CI paths; 3 of 3 mutants caught',
        'local_setup_build': 'real makensis build of the Setup from a stand-in engine passed the '
                             'gate after it refused two installer-machinery files',
        'windows': 'not yet compiled or run on Windows; the clean-runner install test with a '
                   'planted-autostart positive control is written but has not run',
    },
    'limits': ['payloads written to a user-writable profile folder can be edited by any program '
               'running as that user between runs', 'no code signing, so SmartScreen and ASR '
               'prevalence rules block or warn', 'elevated sensor and broker not shipped'],
}
QUESTIONS = {
    'design': {'type': 'choice', 'instructions':
        'Which alternative best meets the goal under the owner rules with the least new risk?',
        'criteria': {'compiled': 'compiled', 'ps1_text': 'ps1_text',
                     'python_supervisor': 'python_supervisor', 'sidecar': 'sidecar'}},
    'writable_payloads': {'type': 'noul', 'instructions':
        'Is the user-writable payload folder a material weakness relative to a same-user attacker, '
        'given that the attacker could equally edit the per-user program folder?',
        'criteria': {'true': 'Yes, materially weaker', 'false': 'No, same trust boundary'}},
    'ready_to_claim': {'type': 'noul', 'instructions':
        'Would one passing clean-runner install test with the positive control be enough to call '
        'native Windows validated, without a soak on a real Windows 11 machine?',
        'criteria': {'true': 'Yes', 'false': 'No, a real-machine soak is still needed'}},
    'top_gap': {'type': 'choice', 'instructions':
        'Which gap most deserves the next measured test or change before people download it?',
        'criteria': {'first_ci_run': 'The engine has never been compiled or run on Windows',
                     'signing': 'No code signing',
                     'soak': 'No real-machine soak for CPU, memory and collector health',
                     'elevated': 'Elevated sensor and broker missing'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=20)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
