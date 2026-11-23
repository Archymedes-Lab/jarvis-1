"""Reversible actions JARVIS can take against a threat, and the ladder base.

Importing the package registers every action, so decision code can just call
`base.registry()`.
"""

from . import (  # noqa: F401  (registration)
    ban_source,
    block_network,
    disable_autostart,
    quarantine,
    suspend,
    suspend_windows,
)
from .base import APPROVE, AUTO, Action, get, register, registry

__all__ = ["Action", "AUTO", "APPROVE", "register", "registry", "get"]
