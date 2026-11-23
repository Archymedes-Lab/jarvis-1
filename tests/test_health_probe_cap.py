"""Windows supervisors must read a whole 503 health reply.

.NET HttpWebRequest cuts a non-200 body at 64 KB (DefaultMaximumErrorResponseLength).
/api/health answers 503 while the daemon is degraded and is ~90 KB, so a probe with
the default read a live daemon as "not answering" and the reviver restarted it every
few minutes (reproduced from Windows on 2026-11-04: 65 536 of 89 814 characters read,
JSON failed; with the cap raised the same reply parsed, live=True).
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAP = "[Net.HttpWebRequest]::DefaultMaximumErrorResponseLength = 4096"


def _probes_health(text):
    return "/api/health" in text or "$HealthUrl" in text


class HealthProbeCap(unittest.TestCase):
    def scripts(self):
        found = [p for p in ROOT.glob("*.ps1") if _probes_health(p.read_text(encoding="utf-8-sig", errors="replace"))
                 and "HttpWebRequest]::Create" in p.read_text(encoding="utf-8-sig", errors="replace")]
        self.assertTrue(found)
        return found

    def test_every_health_probe_reads_more_than_64_kb(self):
        for path in self.scripts():
            text = path.read_text(encoding="utf-8-sig", errors="replace")
            with self.subTest(script=path.name):
                self.assertIn(CAP, text)
                # Set before the first request is created (it applies to requests made afterwards).
                first = re.search(r"\[Net\.HttpWebRequest\]::Create", text).start()
                self.assertLess(text.index(CAP), first)

    def test_the_reviver_and_health_monitor_are_covered(self):
        names = {p.name for p in self.scripts()}
        self.assertTrue({"jarvis-reviver.ps1", "jarvis-health-monitor.ps1"} <= names, names)


if __name__ == "__main__":
    unittest.main()


class ReviverSilenceClock(unittest.TestCase):
    """2026-11-04: five restarts (17:24-18:05) of a live daemon. "Alive but degraded"
    and "silent" shared firstFailure, so after hours degraded a single missed probe
    counted as hours of silence and restarted at once."""

    def test_silence_has_its_own_clock_reset_by_any_live_answer(self):
        text = (ROOT / "jarvis-reviver.ps1").read_text(encoding="utf-8-sig")
        alive = text.index("if ($h.answered -and $h.live) {")
        silent_age = text.index("$age = $now - [long]$st.silentSince")
        self.assertIn("$st.silentSince = 0", text[alive:alive + 600])
        self.assertLess(alive, silent_age)
        self.assertNotIn("$age = $now - [long]$st.firstFailure", text)
