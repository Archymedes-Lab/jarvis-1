"""Provenance: who caused an action, established before asking whether it was bad.

Four parts, each usable alone:

  release      content-addressed release identity (release_id)
  persistence  declarations of the persistence JARVIS itself installs
  identity     signed execution identities bound to (pid, start time, boot)
  capsule      a launcher that gives an agent or test session one identity

Provenance is attribution, never permission (docs/architecture/EVIDENCE-FABRIC.md,
invariant P2). `lookup` and `attribute` return None whenever anything about an
identity fails to verify. Callers must read None as "no provenance", never as
"benign".
"""

from jarvis.platform.provenance.identity import Provenance, attribute, lookup

__all__ = ["Provenance", "attribute", "lookup"]
