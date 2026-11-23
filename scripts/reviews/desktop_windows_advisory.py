"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'produce and install a Windows release of the Tauri desktop client on this machine',
    'alternatives': [
        'native Windows cargo build with an ASR exclusion on the user-writable build folder',
        'native Windows cargo build in an administrator-only folder, run elevated',
        'cross-compile in WSL with the installed MSVC and Windows SDK libraries, rust-lld and llvm-rc',
        'cross-compile in WSL with cargo-xwin downloading the MSVC CRT and SDK',
    ],
    'selected': 'cross-compile in WSL with the installed libraries',
    'measured': {
        'asr_prevalence_rule_mode': 'block',
        'native_probe_build': 'first build script blocked, Defender event 1121, access denied',
        'previous_blocks_of_fresh_executables': 39,
        'tauri_build_scripts': 'dozens',
        'release_without_custom_protocol': 'compiles as a development build; now a compile error',
        'machine_restarts_during_heavy_builds_2026_10_23': 2,
    },
    'install_design': {
        'binary_folder': 'administrator-only write',
        'asr_exclusion': 'ASR-only, one exact executable path; malware scanning unchanged',
        'precedent': 'the same exclusion pattern was accepted by the owner for the native sensor',
        'app_runs_as': 'desktop user, limited run level, started by a scheduled task',
        'readback': 'hash, ACL, exclusion, task principal and action',
        'reversal': 'uninstall removes binary, exclusion, task, shortcut, AUMID key',
    },
    'invariants': [
        'no Windows exclusion that an unprivileged program could exploit',
        'build scripts never run elevated',
        'the build stops before exhausting memory and starts only when the machine is idle',
        'installed binary hash equals the build receipt',
        'the client never runs elevated and monitoring never depends on it',
    ],
}
QUESTIONS = {
    'build_path': {'type': 'choice', 'instructions':
        'Which build alternative best preserves the stated invariants given the measured ASR block?',
        'criteria': {'native_excl': 'Native build, exclusion on the build folder',
                     'native_admin': 'Native build, elevated in an admin-only folder',
                     'cross_local': 'Cross-compile with the installed libraries',
                     'cross_xwin': 'Cross-compile with downloaded libraries',
                     'uncertain': 'Insufficient information'}},
    'exclusion_bounded': {'type': 'noul', 'instructions':
        'Is an ASR-only exclusion for one exact executable path in an administrator-only folder '
        'unexploitable by an unprivileged program, provided the read-back confirms no non-admin write access?',
        'criteria': {'true': 'An unprivileged program cannot use it',
                     'false': 'An unprivileged program could still use it'}},
    'owner_decision': {'type': 'noul', 'instructions':
        'Should adding the exclusion wait for explicit owner authorisation rather than be applied by the agent?',
        'criteria': {'true': 'The owner must authorise it', 'false': 'The agent may apply it'}},
    'validation_gap': {'type': 'noul', 'instructions':
        'Is a successful cross-build without launching the binary on Windows insufficient to call the app Windows-ready?',
        'criteria': {'true': 'A real launch against the live daemon is still required',
                     'false': 'The build is sufficient evidence'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    if STATE['phase'] == 'implementation':
        STATE['validation'] = json.loads(sys.stdin.read() or '{}')
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
