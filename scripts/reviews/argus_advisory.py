"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'secure deployed AI agents that act on the web, on data systems and toward people: '
            'stop hijacked agents from exfiltrating data or taking unauthorized effects, keep a '
            'human in authority over consequential actions, keep a tamper-evident record',
    'threats': ['indirect prompt injection via tool output, web pages, documents, other agents',
                'tool poisoning and rug-pull of tool descriptions (MCP)',
                'exfiltration via attacker-chosen destinations (EchoLeak class)',
                'irreversible actions (production deletion incidents)',
                'credential and privilege abuse', 'cascading failures and rogue agents'],
    'evidence': {
        'detector_defences': 'measured adaptive attacks bypass classifier guardrails; '
                             'red-teaming found a successful hijack on every frontier model tested',
        'capability_defences': 'CaMeL-style control/data-flow separation reported provable '
                               'security on a large share of AgentDojo tasks at ~2.8x token cost',
        'rule_of_two': 'untrusted input + sensitive access + external effect in one session '
                       'should require supervision',
    },
    'alternatives': {
        'A': 'per-value capability tracking: Argus owns the planner and an interpreter; every '
             'value carries provenance; strongest, requires agents built on Argus',
        'B': 'session reference monitor: every tool call passes a deterministic gate; session '
             'taint high-water mark; argument provenance labels; Rule-of-Two forces human '
             'confirmation; works around black-box agents through an SDK or MCP gateway; coarser',
        'C': 'ML guardrail detectors: classify prompts and outputs for injection; easy to deploy, '
             'bypassable by adaptive attacks',
    },
    'proposed': 'B as the enforcing core, A as an optional stricter mode later, C only as an '
                'advisory signal that can raise friction but never allow',
    'invariants': [
        'external content is evidence never authority',
        'approval only from a registered human, bound to the exact call digest, single use, expiring',
        'no session holds untrusted input, sensitive data and an external effect without a human',
        'secret-labelled values never reach an egress call',
        'any monitor failure denies',
        'no allow without a durable hash-chained journal record; journal stores digests not raw args',
        'bounded budgets and a kill switch',
        'a changed tool manifest is denied until re-pinned by the owner',
    ],
}
QUESTIONS = {
    'core_choice': {'type': 'choice', 'instructions':
        'Given the threats, the measured evidence and the invariants, which alternative should '
        'be the enforcing core of a framework that must protect agents the framework does not '
        'itself build?',
        'criteria': {'A': 'Per-value capability tracking', 'B': 'Session reference monitor',
                     'C': 'ML guardrail detectors'}},
    'detectors_advisory_only': {'type': 'noul', 'instructions':
        'Is it right that ML detectors may only raise friction and never turn a deny or a '
        'confirmation into an allow, given that adaptive attacks bypass them?',
        'criteria': {'true': 'Yes, advisory only', 'false': 'No, they can be trusted to allow'}},
    'session_taint_overblocks': {'type': 'noul', 'instructions':
        'Will a session high-water-mark taint, without per-value tracking, force human '
        'confirmation on many benign tasks that mix web reading with sending or writing?',
        'criteria': {'true': 'Yes, notable over-blocking expected',
                     'false': 'No, over-blocking will be rare'}},
    'fail_closed_safe': {'type': 'noul', 'instructions':
        'For an agent gate (not for the protected human\'s own emergency tools), is denying the '
        'agent\'s call on any monitor failure the safer default than allowing it?',
        'criteria': {'true': 'Fail closed is safer', 'false': 'Fail open is safer'}},
    'validation_gap': {'type': 'noul', 'instructions':
        'Beyond unit tests of the gate, is a measured adversarial benchmark (attack success '
        'rate and benign utility on AgentDojo-style tasks against a real agent) still required '
        'before claiming the framework protects agents?',
        'criteria': {'true': 'Yes, still required', 'false': 'Unit tests suffice'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    if '--implementation' in sys.argv and len(sys.argv) > 2:
        STATE['implementation'] = json.loads(sys.argv[-1])
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
