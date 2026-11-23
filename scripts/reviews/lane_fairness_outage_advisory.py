import json
from jarvis.response import jev
STATE = {
 'operation': 'collector scheduling fairness and a tamper-evident outage record for a host security monitor',
 'measured_fault': 'one critical collector re-forced every ~30 s by an external watchdog ran back to back for 7 h on the single shared worker; 36 of 51 collectors stale; lane duty 108 percent',
 'alternatives': {'dedupe_only': 'collapse repeated force requests, keep forced floor priority',
                  'starving_first': 'serve collectors past 2x interval first, ordered by real evidence lateness times criticality; dedupe force; move one 314 s IO-bound job to a separate lane',
                  'per_job_threads': 'run every collector on its own worker thread'},
 'constraints': ['host was reset by out-of-memory the same night', 'concurrent powershell launches contend on one interop pipe', 'restart resets in-memory schedule'],
 'outage_record': {'collector_and_daemon': 'transitions spooled durably then appended to a hash-chained log with cursor as commit point, sealed every 5 min, copied to admin-only vault every 15 min, public timestamp anchor every 6 h',
                   'vm_down': 'reconstructed after return from protected Windows system, hypervisor worker and power event logs, carrying source record ids'},
 'remaining_gaps': ['user-level writer can alter unsealed and unvaulted records for up to ~20 min', 'local administrator can rewrite until next anchor', 'no record while Windows itself is off', 'sysmon fallback livelock itself not fixed in this change', 'no soak yet'],
}
QUESTIONS = {
 'design': {'type': 'choice', 'instructions': 'Which scheduling design best removes the measured monopoly and bounds staleness under the stated memory and interop constraints? Advisory only.',
            'criteria': {'dedupe_only': 'Deduplicate force requests only', 'starving_first': 'Starving-first ordering on real lateness plus dedupe plus moving the IO-bound job', 'per_job_threads': 'One worker thread per collector', 'insufficient': 'Information insufficient to compare'}},
 'record_claim': {'type': 'noul', 'instructions': 'Given the stated remaining gaps, would calling this outage record tamper-proof (rather than tamper-evident) overstate it?',
                  'criteria': {'true': 'Some stated party can still alter records before they are vaulted or externally anchored', 'false': 'No stated party can alter records undetectably at any point'}},
 'priority_gap': {'type': 'choice', 'instructions': 'Which remaining gap most limits trust in the outage record?',
                  'criteria': {'unvaulted_window': 'User-level writer can alter records for up to ~20 min before vaulting', 'admin_rewrite': 'A local administrator can rewrite until the next anchor', 'windows_off': 'No record while Windows is off', 'no_soak': 'No soak test yet'}},
}
try:
 result = jev._call(STATE, QUESTIONS, timeout=15)
 print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
except jev.JevError as exc:
 print(json.dumps({'unavailable': str(exc)}))
