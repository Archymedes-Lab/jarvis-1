import tempfile
import time
import unittest
from pathlib import Path

from jarvis.collectors.network import netwatch
from jarvis.collectors.network.netwatch.sample import _parse_wlan
from jarvis.core.store import Store


class WlanParseTests(unittest.TestCase):
    def test_windows_11_ap_bssid_field(self):
        wlan = _parse_wlan(
            "State : connected\nSSID : Example\n"
            "AP BSSID : 01:23:45:67:89:ab\n"
            "Authentication : WPA3-Personal\nCipher : CCMP\n")
        self.assertEqual(wlan["bssid"], "01:23:45:67:89:ab")
        self.assertEqual(wlan["auth"], "WPA3-Personal")


class WlanConsentFindingTests(unittest.TestCase):
    def test_background_denial_does_not_recommend_privilege_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(str(Path(tmp) / "netwatch.db"))
            try:
                store.set_meta("netwatch_wlan_blocked", "1")
                finding = next(f for f in netwatch.audit(store)
                               if f["title"] == "SSID and access point are invisible to this audit")
                self.assertEqual(finding["severity"], "medium")
                self.assertIn("user-session sampling", finding["detail"])
                self.assertNotIn("run elevated", finding["detail"])
            finally:
                store.close()


class DropPatternTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(str(Path(self.tmp.name) / "j.db"))
        self.addCleanup(self.store.close)
        self.now = time.time()

    def event(self, kind, ago, severity="medium"):
        self.store.db.execute(
            "INSERT INTO net_events(ts,iface,kind,severity,detail,prev,curr) VALUES(?,?,?,?,?,?,?)",
            (self.now - ago, "Wi-Fi", kind, severity, "d", "", ""))
        self.store.db.commit()

    def drops(self):
        return {f["title"]: f["severity"] for f in netwatch.audit(self.store)
                if "disconnected" in f["title"] or "link lost" in f["title"]}

    def test_isolated_drops_are_low(self):
        self.event("wlan-disconnected", 7200)
        self.event("wlan-disconnected", 3600)
        self.assertEqual(set(self.drops().values()), {"low"})

    def test_a_burst_is_medium(self):
        for ago in (900, 700, 500):
            self.event("wlan-disconnected", ago)
        self.assertEqual(set(self.drops().values()), {"medium"})

    def test_a_drop_during_a_gateway_change_is_medium(self):
        self.event("wlan-disconnected", 3600)
        self.event("gateway-changed", 3500, severity="high")
        self.assertEqual(self.drops()["wlan disconnected"], "medium")


if __name__ == "__main__":
    unittest.main()
