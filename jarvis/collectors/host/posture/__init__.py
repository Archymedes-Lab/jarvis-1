"""Windows security posture: what is on, what is off, and what it should be.

Every other module asks whether something bad is present. This one asks whether
the defenses that would have stopped it are switched on — and says what to set
when they are not, because "SmartScreen is off" is only useful if you also know
what to turn on.

On activation, since it is the question everyone asks: **an unactivated Windows
is not an insecure Windows.** Activation gates personalisation, not security.
Defender still runs, Windows Update still delivers security patches, and the
firewall still works. What actually carries risk is the method used to activate
— a script piped from the internet into an elevated shell is a total-trust
event regardless of what it does afterwards. So this module reports the
activation *state* as information, and treats the activation *method* as the
thing worth thinking about.

Each finding names the setting to change rather than just the problem. The
severities reflect exploitability on a personal workstation, not a domain
controller: Memory Integrity being off is common and worth fixing; Tamper
Protection being off means malware can switch Defender off silently, which is
worse than it sounds.
"""

from .collect import elevated_data
from .common import SEV_ORDER, sort_findings
from .run import audit
from .sections import ASR_KEY, CONHOST
