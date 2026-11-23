"""Provenance labels: where a value came from and how much it matters.

A label is two facts about a value. Trust says whether a principal with
authority produced it (the owner, the deploying operator) or whether it arrived
from the world (a web page, a tool result, a document, another agent). Trust is
about authority, not honesty: a pinned, authenticated peer agent is still
UNTRUSTED, because knowing who sent a message does not make its instructions
ours. Sensitivity says what leaking it would cost.

Joining labels is the information-flow rule: anything derived from several
values is as untrusted as the least trusted and as sensitive as the most
sensitive of them. Labels only ever get worse by mixing.
"""

from dataclasses import dataclass, field
from enum import IntEnum


class Trust(IntEnum):
    UNTRUSTED = 0       # the world: web, tool output, documents, other agents
    TRUSTED = 1         # a principal with authority: owner, operator config


class Sensitivity(IntEnum):
    PUBLIC = 0
    INTERNAL = 1        # not for the public, harmless to the user if leaked
    PRIVATE = 2         # personal data, private communications, documents
    SECRET = 3          # credentials, keys, recovery codes: never egress


@dataclass(frozen=True)
class Label:
    trust: Trust = Trust.UNTRUSTED
    sensitivity: Sensitivity = Sensitivity.PUBLIC
    origins: frozenset = field(default_factory=frozenset)

    def join(self, other):
        return Label(min(self.trust, other.trust),
                     max(self.sensitivity, other.sensitivity),
                     self.origins | other.origins)

    def summary(self):
        """Metadata for the journal: levels and origin kinds, never content."""
        return {"trust": self.trust.name, "sensitivity": self.sensitivity.name,
                "origins": sorted(self.origins)}


# The label a value gets when an integration cannot say where it came from.
# Unknown provenance is the world's, never the owner's.
UNKNOWN = Label(Trust.UNTRUSTED, Sensitivity.PUBLIC, frozenset({"unknown"}))
OWNER = Label(Trust.TRUSTED, Sensitivity.PUBLIC, frozenset({"owner"}))


def join_all(labels, start=None):
    out = start
    for lab in labels:
        out = lab if out is None else out.join(lab)
    return out
