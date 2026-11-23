"""Scheduled tasks jarvis itself installs, verified so their names buy no trust.

The control audit reports every scheduled task that can run code. A handful are
jarvis's own watchdogs and the reviewed IDE keepalive tasks. Each is declared
once in jarvis/platform/provenance/persistence.py and accepted only when the whole live
definition matches its declaration: one PowerShell action with exact
arguments, a limited principal, the current Windows user, the expected
LocalAppData path, and the reviewed script fingerprint. A renamed or modified
script therefore stays a critical persistence finding.
"""

from jarvis.core.paths import REPO_ROOT, SOURCE_ROOT, win_script  # noqa: F401 (tests)
from jarvis.platform.provenance import persistence
from jarvis.platform.provenance.persistence import WSL_START_ARGS, normalized_text_hash

__all__ = ["TRUSTED_IDE_TASKS", "WSL_START_ARGS", "normalized_text_hash",
           "verified_maintenance_task"]

TRUSTED_IDE_TASKS = {
    t.name: {"script": t.script, "hash": t.fixed_hash, "logon": t.logon}
    for t in persistence.MANAGED_TASKS if t.fixed_hash
}


def verified_maintenance_task(task, data):
    """Verify a live task against its declaration without trusting its name.

    Script fingerprints are checked against the code actually running
    (REPO_ROOT: the sealed, root-owned release in production). Arguments are
    checked against the checkout the tasks were installed from (SOURCE_ROOT).
    """
    return persistence.verify_task(task, data, code_root=REPO_ROOT,
                                   checkout_root=SOURCE_ROOT)
