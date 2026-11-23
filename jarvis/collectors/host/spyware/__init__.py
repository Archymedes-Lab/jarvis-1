"""Look for commodity spyware, stalkerware and unwanted monitoring.

The sophisticated end of this problem needs a kernel driver. The unsophisticated
end — which is most of it — leaves obvious traces, and those are what this
module reads:

  * Windows records which application used the microphone, camera or location
    and exactly when, in the CapabilityAccessManager consent store. Nothing that
    records you through the normal APIs escapes this ledger.
  * Monitoring tools have to survive reboot, so they appear in autostart. Almost
    none of them are signed by a recognizable vendor. Checking the Authenticode
    signature of every autostart binary is a very high-signal, cheap test.
  * Anything that can change your volume or type for you is either an HID device
    sending consumer-control codes, or software with an input hook. Both are
    enumerable.
"""

from .common import SEV_ORDER, sort_findings
from .linux import audit_linux
from .run import audit
from .windows import audit_windows
