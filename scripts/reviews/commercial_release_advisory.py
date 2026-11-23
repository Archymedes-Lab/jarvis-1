"""Fixed release-planning metadata only; advisory, never a business, pricing or launch decision.

Narrow Jev questions that check the CDM run of 2026-11-01 over how to tailor the
first ARGUS-1 commercial release (docs/commercial/RELEASE-PLAN-2026-11.md).
No lead, place name, contact, source or evidence is sent: only aggregate counts.
"""
import json

from jarvis.response import jev

STATE = {
    'goal': 'tailor the first ARGUS-1 commercial release to its launch platforms and audiences',
    'facts': {
        'register': '54 capabilities: 25 partial, 29 unverified, none live-tested',
        'qc': 'not ready for general users; open: one install/update/uninstall path, clean-machine '
              'installs, part of alert noise; API credential fixed in code, unverified live',
        'audiences': 'self-hoster places 72 free vs 10 paying; WSL developer places 49 free vs 9; '
                     'agency places 67 paying vs 9 free; all 30 agency and prospect leads paying',
        'artifacts': 'CI-signed Linux server binary (deb, tar); Windows desktop exe unsigned; web '
                     'dashboard; phone relay; fleet view and billing do not exist',
        'team': 'four people; publishing currently blocked by CI billing',
    },
    'cdm_result': {
        'commit': 'single (baseline: ship current release unchanged)',
        'tied_best_alternatives': 'server_first and audience_profiles, both verify, mean 0.38 vs 0.42',
        'vetoed': 'team_first (overclaim, privacy); design_partners (evidence)',
    },
}
QUESTIONS = {
    'baseline_acceptable': {'type': 'noul', 'instructions':
        'Is shipping the current release unchanged, with generic copy, to general users acceptable '
        'while quality control says it is not ready for general users?',
        'criteria': {'true': 'Yes, acceptable', 'false': 'No, it needs tailoring or fixes first'}},
    'first_edition': {'type': 'choice', 'instructions':
        'Which edition should the first commercial release lead with?',
        'criteria': {'server': 'Linux server edition to self-hosters and sysadmins',
                     'desktop': 'Windows desktop app to WSL agent developers',
                     'team': 'Paid team edition to agencies',
                     'none': 'No public edition until install and alert-noise blockers close'}},
    'profiles_vs_server': {'type': 'choice', 'instructions':
        'Between a server-only terminal first-run and one audience-profile setting that shapes '
        'first-run copy for every edition from the coverage register, which should be built first?',
        'criteria': {'server_only': 'Server terminal first-run only',
                     'profiles': 'Shared audience profiles, server profile first',
                     'neither': 'Neither; fix blockers first'}},
    'limits_first_run': {'type': 'noul', 'instructions':
        'For security-minded self-hosters, does a first-run that plainly lists what is not watched '
        'and that nothing is live-tested build more trust than it costs in adoption?',
        'criteria': {'true': 'Yes, net trust gain', 'false': 'No, it costs more adoption'}},
    'server_gate': {'type': 'choice', 'instructions':
        'Which must be proven first before the server edition is offered publicly?',
        'criteria': {'clean_install': 'Clean install, upgrade, uninstall on fresh VMs',
                     'footprint': 'Measured idle CPU and memory on a small VPS',
                     'silence_alert': 'Off-box alert when the host goes silent',
                     'alert_noise': 'Alert noise on a fresh host',
                     'positive_control': 'One end-to-end positive control measured'}},
    'charge_first': {'type': 'choice', 'instructions':
        'Given these audience counts, whom should Argus charge first?',
        'criteria': {'agency_seats': 'Agencies and small teams, per machine',
                     'server_hosts': 'Self-hosters, per server',
                     'desktop_pro': 'Individual developers, paid desktop tier',
                     'nobody_yet': 'Nobody until a fleet view and clean installs exist'}},
}
# Review of the built slice (jarvis/core/audience.py, `welcome` CLI): metadata only.
REVIEW_STATE = {
    'goal': 'first-run text per edition audience that never claims more than the coverage register',
    'design': {
        'source': 'status word is a fixed map of register status; partial and unverified only',
        'fail_safe': 'unknown or stronger status, or a capability missing from the register, '
                     'is listed as not provided; live-tested count is computed',
        'limits': 'each capability shows only the first clause of its recorded limit, bounded '
                  'to 160 characters; later clauses can name evasions',
        'guard': 'render refuses any line with a phrase from a fixed overclaim list',
        'scope': 'read-only CLI command, no store, no network; JSON for other interfaces; '
                 'server and desktop profiles only, team refused',
        'tests': '17 unit tests incl. three mutation checks that fail when an invariant breaks',
    },
}
REVIEW_QUESTIONS = {
    'first_clause_honest': {'type': 'noul', 'instructions':
        'Is showing only the first clause of each recorded limit honest enough for a first-run, '
        'given the full limits remain in the register and health API?',
        'criteria': {'true': 'Yes', 'false': 'No, users need the full limit text'}},
    'unknown_as_not_provided': {'type': 'noul', 'instructions':
        'Is listing a capability whose register status has no reviewed word as not provided '
        'the right fail-safe, even if the status is stronger?',
        'criteria': {'true': 'Yes', 'false': 'No'}},
    'phrase_list_sufficient': {'type': 'noul', 'instructions':
        'Is a fixed overclaim phrase list plus register-derived status words sufficient to keep '
        'first-run copy from overclaiming?',
        'criteria': {'true': 'Yes', 'false': 'No, wording can still imply more than it says'}},
    'top_gap': {'type': 'choice', 'instructions':
        'Which validation gap in this slice matters most before it ships?',
        'criteria': {'native_build': 'Run the command from the real native server build on a fresh VM',
                     'register_wording': 'Register limit wording written for engineers reads oddly to users',
                     'desktop_consumer': 'Desktop app and dashboard do not yet show this statement',
                     'user_test': 'No real user has read it'}},
}
if __name__ == '__main__':
    import sys
    if sys.argv[1:] == ['review']:
        STATE, QUESTIONS = REVIEW_STATE, REVIEW_QUESTIONS
    try:
        result = jev._call(STATE, QUESTIONS, timeout=20)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
