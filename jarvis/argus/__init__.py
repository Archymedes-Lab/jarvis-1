"""Argus: a reference monitor for deployed AI agents.

JARVIS guards one machine; Argus applies the same contract to agents that act
on the web, on data systems and toward people. Every consequential agent step
(a tool call, an outbound request, a message to a person or another agent)
passes one deterministic gate before it happens. The design and its evidence
are in docs/architecture/ARGUS.md.

The gate never trusts a model to police a model. Content the agent read is
evidence, never authority; only a registered human can approve, and that
approval is bound to the one call it was shown. Detectors (including Jev) may
add friction; nothing they say can turn a deny or a confirmation into an allow.
"""

from jarvis.argus.labels import Label, Sensitivity, Trust
from jarvis.argus.monitor import Call, Decision, Monitor, Verdict
from jarvis.argus.policy import Effect, Policy, ToolSpec, manifest_digest

__all__ = ["Call", "Decision", "Effect", "Label", "Monitor", "Policy",
           "Sensitivity", "ToolSpec", "Trust", "Verdict", "manifest_digest"]
