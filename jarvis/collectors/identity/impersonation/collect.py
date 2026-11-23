"""What Windows can tell us about who is acting on this machine.

One PowerShell round-trip, every block independently guarded so a provider
that is unavailable degrades that row instead of losing the sample.
"""

from jarvis.core.paths import load_win_script
from jarvis.platform.windows import ps_json

PS_IMPERSONATION = load_win_script("impersonation.ps1")


def sample():
    return ps_json(PS_IMPERSONATION)
