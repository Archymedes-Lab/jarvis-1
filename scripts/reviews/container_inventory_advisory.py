import json
from jarvis.response import jev
STATE = {
 'operation': 'read-only local Docker configuration inventory',
 'alternatives': ['bounded per-container inspection using existing scheduler', 'new persistent Docker event consumer', 'new privileged monitoring agent'],
 'bounds': {'command_seconds':20,'audit_seconds':60,'output_bytes':1048576,'max_containers':500,'cadence_seconds':900,'retries':0},
 'privacy': 'explicit selected fields; excludes environment, labels, command lines and raw diagnostics; model receives only this engineering summary',
 'failure_contract': 'malformed or unavailable inspections and truncation produce noncomplete receipts; earlier successful findings retained',
 'authority': 'no Docker mutation, no containment, no compromise verdict; assurance unverified',
 'tests': 'fixtures for risk configurations and malformed identity; real local subprocess timeout, output exhaustion and error redaction; CLI, scheduled dispatch and receipt regression checks',
 'remaining_gaps': ['no isolated adversarial-container run','no scheduled live service measurement','Docker metadata is not independent attestation','snapshot is not atomic','containers between scans can be missed'],
}
QUESTIONS = {
 'design': {'type':'choice','instructions':'Which design best meets the stated read-only inventory scope and privacy, resource and authority bounds? Treat unknown runtime measurements as gaps. This is advisory only.', 'criteria': {'bounded_inspection':'Existing scheduler with bounded per-container reads', 'events':'A new persistent Docker event consumer', 'agent':'A new privileged agent', 'insufficient':'Information insufficient to compare'}},
 'validation_gap': {'type':'noul','instructions':'Do the stated remaining gaps prevent treating this capability as validated detection or containment?', 'criteria':'Yes when fixture tests and read-only inventory without isolated adversarial and actual service measurement are insufficient for validated detection or containment claims.'},
}
try:
 result=jev._call(STATE,QUESTIONS,timeout=15)
 print(json.dumps({'model':result.get('model'),'answers':result['answers']}))
except jev.JevError as exc:
 print(json.dumps({'unavailable':str(exc)}))
