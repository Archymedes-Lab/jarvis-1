import json
from jarvis.response import jev
STATE = {
 'operation': 'read-only pre-OS boot integrity comparison on one Windows machine',
 'alternatives': ['replay retained TPM measured-boot logs unelevated against an owner-pinned baseline, inside the existing scheduler',
                  'elevated collector reading UEFI variables, boot configuration and the EFI system partition',
                  'kernel driver or firmware-level agent'],
 'bounds': {'cadence_seconds': 1800, 'probe_seconds': 3, 'max_logs': 64, 'max_log_bytes': 4194304, 'max_events_per_id': 40, 'retries': 0},
 'privacy': 'digests, counters, versions and boot option flags only; model receives only this engineering summary',
 'failure_contract': 'unparsed log, missing log for the current boot, missing attestation verdict or failed probe give a noncomplete receipt; baseline never advances without the owner',
 'authority': 'no firmware, TPM, boot configuration or Secure Boot change; no containment; findings unscored; assurance partial',
 'tests': 'synthetic log fixtures for each drift class, malformed and truncated logs, stale log, failed probe, baseline persistence; one live read of 26 real logs with identical measurements',
 'remaining_gaps': ['no positive control on real hardware', 'firmware that falsifies its own measurements is invisible', 'boot of other media leaves no log',
                    'firmware menus and the POST beep are not observed', 'UEFI variables and EFI partition not read', 'PCR values not read back from the TPM by the collector', 'no soak'],
}
QUESTIONS = {
 'design': {'type': 'choice', 'instructions': 'Which design best meets the stated read-only scope with the least privilege and bounded cost as a first step? Treat unknown runtime measurements as gaps. This is advisory only.',
            'criteria': {'unelevated_replay': 'Unelevated replay of retained measured-boot logs against a pinned baseline', 'elevated': 'An elevated collector reading UEFI variables and the EFI partition',
                         'driver': 'A kernel driver or firmware-level agent', 'insufficient': 'Information insufficient to compare'}},
 'validation_gap': {'type': 'noul', 'instructions': 'Do the stated remaining gaps prevent treating this capability as validated detection of pre-OS attacks?',
                    'criteria': 'Yes when synthetic fixtures and one clean live read, without a positive control on real hardware or a soak, are insufficient for a validated detection claim.'},
 'priority': {'type': 'choice', 'instructions': 'Which single remaining gap most limits detection of an attack that starts before the operating system?',
              'criteria': {'positive_control': 'No positive control on real hardware', 'self_measuring': 'Firmware that falsifies its own measurements', 'other_media': 'A boot of other media leaves no log',
                           'elevated_reads': 'UEFI variables and EFI partition are not read', 'tpm_readback': 'PCR values are not read back from the TPM'}},
}
try:
 result = jev._call(STATE, QUESTIONS, timeout=15)
 print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
except jev.JevError as exc:
 print(json.dumps({'unavailable': str(exc)}))
