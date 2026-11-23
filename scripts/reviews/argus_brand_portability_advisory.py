"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'rename the product to ARGUS-1 in every user-visible string and remove '
            'assumptions about one machine account, without breaking existing users',
    'brand': 'display-time rule in web pages, desktop UI and desktop shell: uppercase '
             'product name becomes ARGUS-1, except real Windows task/service names, '
             'lowercase commands, capitalised paths and env names; finding titles keep '
             'the old text at the source because they key acknowledgements, incident '
             'identity and score history; storage keys and the app identifier unchanged',
    'portability': 'Windows profile = explicit setting, else Linux login if a profile of '
                   'that name exists, else the only real profile, else unknown (read '
                   'nothing); root repair helper mounts for the sudo caller only',
    'validation': 'browser check at two widths with a negative control; unit tests in '
                  'Python, TypeScript and Rust; full suite 2943 OK; static gate clean',
}
QUESTIONS = {
    'display_time_brand': {'type': 'noul', 'instructions':
        'Is re-branding at display time, rather than rewriting finding titles at the '
        'source, the safer choice given that titles key acknowledgements and history?',
        'criteria': {'true': 'Display time is safer', 'false': 'Rewrite at the source'}},
    'unknown_profile': {'type': 'noul', 'instructions':
        'When several Windows profiles exist and none matches the Linux login, is '
        'returning unknown (reading nothing) better than picking one?',
        'criteria': {'true': 'Unknown is better', 'false': 'Pick one'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
