"""Protocol models for the model checker. Each module exposes `model()` and
documents what it abstracts away."""

from jarvis.verify.models import interop_gate, lanes, privacy_seal, release, response_ladder

# (invariant id, name, builder): the L2 catalogue. Kept here, below both the
# report that runs it and the invariant registry that checks it, so neither
# imports the other.
MODELS = (
    ("V6", "privacy seal lifecycle", privacy_seal.model),
    ("V7", "release switch", release.model),
    ("V8", "scheduler lanes", lanes.model),
    ("V11", "interop gate recovery", interop_gate.model),
    ("V13", "response ladder", response_ladder.model),
)
