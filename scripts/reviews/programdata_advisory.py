import json
from jarvis.response import jev
STATE={'component':'local registry security-family watch',
       'measured':{'shared_data_root_allows_standard_user_writes':True,
                   'one_vendor_security_engine_subfolder_allows_standard_users_read_only':True},
       'current':'all programs under the shared application-data tree are ignored unless named like scripting tools',
       'options':{'report_unknown':'Report security-family writes from the shared tree as provenance unknown; legitimate vendor engines may also appear; no automatic intervention.',
                  'verified_exclusion':'Add an exact executable exception only after independent signature and directory-ACL validation, with bounded caching and failure visibility.',
                  'blanket_ignore':'Keep ignoring the entire tree based on its pathname.'}}
QUESTIONS={'initial_fix':{'type':'choice','instructions':'Which immediate design best preserves visibility and avoids inventing trusted provenance from a directory name? A full signature/ACL resolver is not implemented.','criteria':STATE['options']}}
STATE['socket_read_options'] = {
    'strict_status': 'Attribution opts into fresh bounded reads that validate all required table headers/rows; complete empty is valid, denied/malformed/truncated remains unknown; legacy mapping API unchanged.',
    'nonempty_only': 'Continue treating every empty mapping as failed evidence.',
    'empty_always_clean': 'Treat empty mappings as clean even when the underlying reader swallowed errors.'}
QUESTIONS['socket_design'] = {'type':'choice',
    'instructions':'Which socket read design preserves evidence continuity and distinguishes valid empty state from unavailable evidence?',
    'criteria':STATE['socket_read_options']}
try:
 r=jev._call(STATE,QUESTIONS,timeout=20)
 print(json.dumps({'model':r.get('model'),'answers':r['answers']}))
except jev.JevError as exc:print(json.dumps({'unavailable':str(exc)}))
