"""Continuous network-state logging, and what changes in it mean.

Most of this repo answers questions about the present. This module exists
because the useful network questions are all about the past: when did the link
drop, did the adapter go down on its own, has this network always been on this
hardware, did the gateway's MAC change while the SSID stayed the same.

None of those can be answered by looking now. They need a record that was
already being kept, so `sample()` runs on a short interval and every sample is
stored — not just the interesting ones. Storage is trivial (a few hundred bytes
a minute) and the alternative is discovering that the one moment you needed is
the one you did not keep.

What the transitions mean:

  adapter disabled      Nothing disables a working adapter by accident. On a
                        machine whose owner says they never turn it off, this
                        is the highest-signal event here.
  link lost             Ordinary on its own, and the reason the log exists:
                        a drop that lines up with something else in the
                        timeline is the thing worth seeing.
  same SSID, new BSSID  Roaming between access points looks exactly like an
                        evil twin. The difference is whether the new BSSID has
                        ever been seen before and whether the encryption held.
  encryption weakened   A network that was WPA3 yesterday and open today is
                        not the same network, whatever it calls itself.
  gateway MAC changed   The address the traffic leaves through is now different
                        hardware. That is what ARP spoofing looks like.
"""

from .record import record
from .run import SEV_ORDER, audit, sort_findings, timeline
from .sample import PS_NET, sample
