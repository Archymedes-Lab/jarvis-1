"""Spyware and covert-process reasoning: hypotheses over typed evidence.

Observe -> normalize -> reconcile -> hypothesize -> adjudicate -> escalate depth
-> verify -> human decision. Everything here is pure and deterministic; the
optional typed advisory model lives above it (response.reasoning) and can only
add notes or raise observation depth by one step. Nothing in this package
authorizes an action, and no verdict says "malicious": a verdict names what
was observed, what explains it, and what evidence is still missing.
"""
