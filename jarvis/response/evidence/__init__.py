"""Persistent, per-case evidence collection.

Investigative output lives under ~/.jarvis/evidence/<case>/ and never in a
temporary directory. Each case owns its artefacts, its SHA-256 manifest, its
notes and its scan results, so it survives a restart and can be handed over
or deleted on its own.
"""

from . import collect, scan, sources
from .case import Case, list_cases
from .collect import PROFILES, collect_profile, profile_names
from .manifest import Manifest, sha256_file
from .paths import EVIDENCE_ROOT, TOOLS_ROOT, evidence_root, tools_root

__all__ = [
    "Case", "list_cases", "Manifest", "sha256_file",
    "PROFILES", "collect_profile", "profile_names",
    "EVIDENCE_ROOT", "TOOLS_ROOT", "evidence_root", "tools_root",
    "collect", "scan", "sources",
]
