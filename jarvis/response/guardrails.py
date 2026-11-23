"""Model guardrails: the local model speaks like a security system.

Drawn from the Maximum Assurance directive. A small local model left to
itself will reassure ("you're 100% safe") — the exact false green the
directive forbids. Two mechanisms, both deterministic and tested:

  PREAMBLE  behavioral contract appended to model system prompts:
            uncertainty-preserving, evidence-first, graduated language.
  scrub()   post-pass over model text that downgrades absolute safety
            claims to honest ones. The model may still be wrong about
            facts; it may not sound certain about safety it cannot see.

Neither mechanism grants authority: model text never acts, authorizes,
or verifies. It explains, within bounds.
"""

import re

PREAMBLE = (
    " Speak as a careful endpoint security monitor, never as a cheerleader: "
    "absence of alerts never establishes absence of compromise, so never "
    "claim the machine is safe, clean, or fully protected. State what the "
    "evidence shows and what it cannot show. Match the response to the "
    "stakes: ordinary observations stay advisory, consequential actions "
    "require explicit human approval. Never instruct wiping disks, deleting "
    "files, disabling protection, or editing firmware."
)

# (pattern, replacement): absolute safety claims -> honest equivalents.
# Word-boundaried and case-insensitive; ordinary prose passes through.
_CLAIMS = [
    (r"\b100%\s*(secure|safe|protected|clean|threat-?free)\b",
     r"with no active findings in the latest evidence (which never proves safety)"),
    (r"\bcompletely\s+(secure|safe|protected|clean)\b", r"with no active findings"),
    (r"\bfully\s+(secure|safe|protected)\b", r"with no active findings"),
    (r"\bguaranteed?\s+(safe|secure|safety|security)\b", r"not currently indicating risk"),
    (r"\bthere\s+are\s+no\s+threats\b", r"the latest evidence shows no active findings"),
    (r"\bno\s+threats\s+(detected|found)\b", r"no active findings in the latest evidence"),
    (r"\byour\s+system\s+is\s+clean\b", r"no active findings are recorded right now"),
    (r"\bnothing\s+to\s+worry\s+about\b", r"nothing in the current evidence needs you"),
]


def scrub(text):
    """Downgrade absolute safety claims. Pure; untestable-model safe."""
    out = str(text or "")
    for pattern, replacement in _CLAIMS:
        out = re.sub(pattern, replacement, out, flags=re.IGNORECASE)
    return out
