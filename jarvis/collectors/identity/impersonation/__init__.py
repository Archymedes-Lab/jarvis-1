"""Is someone else acting on this machine, or something acting as you?

The input hook answers "was this event synthesised?". It cannot answer "was
the person who caused it you?" — a remote session, an unattended automatic
logon, a hardware implant and assistive technology driving the UI all produce
input that is either genuine or invisible.

  `collect` samples logon sessions, lock state, remote sessions, stored
  credentials, registered assistive technology and automatic logon;
  `rules` turns that into findings and correlates the lock state with the
  real, un-flagged input the hook counted;
  `run` executes them together.
"""

from .collect import PS_IMPERSONATION, sample
from .rules import audit_data
from .run import audit, sort_findings

__all__ = ["PS_IMPERSONATION", "sample", "audit_data", "audit",
           "sort_findings"]
