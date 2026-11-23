"""What each tool can do, who may approve, and how much an agent may spend.

Policy is operator configuration, so it is TRUSTED by construction and never
read from anything the agent saw. A tool is described by its effect class, not
its name: the monitor reasons about "this sends data out" or "this cannot be
undone", which is what the Rule of Two and the irreversible-action gate need.

Tool descriptions are pinned. An MCP server can change a tool's description or
schema after it was approved (a rug-pull) and hide instructions in it (tool
poisoning). The digest of the description and schema is recorded when the owner
approves the tool; a different digest at call time is a different tool, denied
until the owner pins it again.
"""

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum


class Effect(Enum):
    READ = "read"                   # observes; changes nothing outside the agent
    WRITE = "write"                 # changes state, and the change can be undone
    EGRESS = "egress"               # sends data beyond the trust boundary
    COMMUNICATE = "communicate"     # speaks to a person or another agent
    IRREVERSIBLE = "irreversible"   # delete, overwrite, execute, deploy
    SPEND = "spend"                 # moves money or consumes paid resources
    IDENTITY = "identity"           # changes credentials, permissions, accounts


# Effects that reach outside the session: the third leg of the Rule of Two.
EXTERNAL = frozenset({Effect.WRITE, Effect.EGRESS, Effect.COMMUNICATE,
                      Effect.IRREVERSIBLE, Effect.SPEND, Effect.IDENTITY})
# Effects that send data somewhere a value could leak to.
OUTBOUND = frozenset({Effect.EGRESS, Effect.COMMUNICATE})
# Effects a human approves every time, whatever the session saw.
ALWAYS_CONFIRM = frozenset({Effect.IRREVERSIBLE, Effect.SPEND, Effect.IDENTITY})


def manifest_digest(description, input_schema):
    """SHA-256 over a tool's description and input schema, canonically encoded."""
    body = json.dumps({"description": description, "schema": input_schema},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(body.encode()).hexdigest()


@dataclass(frozen=True)
class ToolSpec:
    name: str
    effect: Effect
    digest: str                         # pinned manifest_digest
    reads_sensitive: bool = False       # results carry PRIVATE or SECRET data
    destination_args: tuple = ()        # arguments that name where data goes


@dataclass
class Policy:
    tools: dict = field(default_factory=dict)            # name -> ToolSpec
    destinations: frozenset = frozenset()                # owner-approved targets
    approvers: frozenset = frozenset()                   # human principal ids
    max_calls: int = 200
    max_external: int = 50
    max_irreversible: int = 3
    approval_ttl_s: int = 600
    version: str = "argus-2026-10-17"

    def pin(self, spec):
        self.tools[spec.name] = spec
