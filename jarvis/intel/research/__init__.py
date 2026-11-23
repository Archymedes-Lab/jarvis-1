"""Threat intelligence acquisition: turn published security research into
candidate indicators this machine can actually check.

The pipeline is deliberately one-directional and lossy:

    Exa search  ->  structured extraction  ->  vet.py  ->  indicators table
                                                  |
                                            most things die here

What survives is never authoritative. An indicator is a reason to go and look
at something, evaluated against the live system by hunt.py. Nothing fetched is
executed, and nothing fetched can clear an existing finding — see vet.py for
why that invariant is the whole design.

Two things dominate output quality, in this order:

  1. **Which sources are searched.** An early test run without a source
     allowlist returned a 2007 academic paper on registry forensics as the top
     hit for a Linux rootkit query. The allowlist below is the single highest
     leverage knob in this file.
  2. **What the extraction is told to refuse.** Language models fill empty
     fields with plausible filler: `evil.com`, `192.168.1.100`, and the SHA-256
     of the empty string all arrived from one real article. The prompt spends
     most of its length on refusal rules for that reason.
"""

# The topic list is part of this package's public surface (the CLI offers it).
from jarvis.intel.corpus import CORPUS, SOURCES  # noqa: E402,F401

from .client import (
    BudgetExceeded,
    IntelError,
    daily_budget,
    load_key,
    save_key,
    search,
    spent_today,
)
from .extraction import ingest_result
from .run import daemon_options, refresh, revet, summary
