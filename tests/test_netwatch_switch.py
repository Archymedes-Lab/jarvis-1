import tempfile
import time
import unittest
from pathlib import Path

from jarvis.collectors.network import netwatch
from jarvis.core.store import Store


def sample(ts, ssid, bssid, gateway, mac, dns, auth="WPA3-Personal"):
    return {
        "ts": ts, "iface": "Wi-Fi", "state": "connected", "ssid": ssid,
        "bssid": bssid, "channel": "6", "band": "5 GHz", "auth": auth,
        "cipher": "CCMP", "signal": 80, "ipv4": "192.0.2.10",
        "gateway": gateway, "gw_mac": mac, "dns": dns,
    }


class NetworkSwitchTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = Store(str(Path(tmp.name) / "j.db"))
        self.addCleanup(self.store.close)
        self.ts = int(time.time()) - 100

    def test_distinct_identified_networks_keep_transition_without_false_high(self):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        second = sample(self.ts + 1, "Network B", "66:77:88:99:aa:bb",
                        "198.51.100.1", "66-77-88-99-AA-BB", "1.1.1.1",
                        auth="WPA2-Personal")
        netwatch.record(self.store, first)
        events = netwatch.record(self.store, second)
        self.assertEqual([(e["kind"], e["severity"]) for e in events],
                         [("network-switched", "low")])
        stored = self.store.db.execute(
            "SELECT kind FROM net_events ORDER BY ts DESC LIMIT 1").fetchone()[0]
        self.assertEqual(stored, "network-switched")

    def test_same_network_gateway_and_dns_change_remain_high(self):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        second = sample(self.ts + 1, "Network A", "00:11:22:33:44:55",
                        "192.0.2.1", "66-77-88-99-AA-BB", "1.1.1.1")
        netwatch.record(self.store, first)
        events = netwatch.record(self.store, second)
        self.assertEqual({e["kind"]: e["severity"] for e in events},
                         {"gateway-changed": "high", "dns-changed": "high"})
        findings = netwatch.audit(self.store)
        high = {f["title"] for f in findings if f["severity"] == "high"}
        self.assertIn("gateway changed", high)
        self.assertIn("dns changed", high)

    def test_repeat_sighting_does_not_turn_an_unverified_ap_into_trust(self):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        other = sample(self.ts + 1, "Network A", "66:77:88:99:aa:bb",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        back = dict(first, ts=self.ts + 2)
        repeat = dict(other, ts=self.ts + 3)
        netwatch.record(self.store, first)
        first_roam = netwatch.record(self.store, other)
        netwatch.record(self.store, back)
        second_roam = netwatch.record(self.store, repeat)
        self.assertIn(("ap-unknown", "medium"),
                      [(event["kind"], event["severity"]) for event in first_roam])
        self.assertIn(("ap-repeat-unverified", "medium"),
                      [(event["kind"], event["severity"]) for event in second_roam])
        findings = netwatch.audit(self.store)
        self.assertTrue(any(f["title"].startswith("ap repeat unverified") and
                            f["severity"] == "medium" and
                            "ownership is unverified" in f["detail"] for f in findings))
        kinds = [row[0] for row in self.store.db.execute(
            "SELECT kind FROM net_events WHERE kind LIKE 'ap-%' ORDER BY ts")]
        self.assertEqual(kinds, ["ap-unknown", "ap-repeat-unverified",
                                 "ap-repeat-unverified"])

    def test_historical_high_roam_is_contextualized_without_editing_event(self):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        second = sample(self.ts + 300, "Network A", "66:77:88:99:aa:bb",
                        "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        netwatch.record(self.store, first)
        netwatch.record(self.store, second)
        self.store.db.execute(
            "UPDATE net_events SET severity='high' WHERE kind='ap-unknown'")
        self.store.commit()
        finding = next(f for f in netwatch.audit(self.store)
                       if f["title"].startswith("ap unknown"))
        self.assertEqual(finding["severity"], "medium")
        self.assertIn("ownership is unverified", finding["detail"])
        raw = self.store.db.execute(
            "SELECT severity FROM net_events WHERE kind='ap-unknown'").fetchone()[0]
        self.assertEqual(raw, "high")

    def test_missing_pair_preserves_historical_ap_high(self):
        self.store.db.execute(
            "INSERT INTO net_events(ts,iface,kind,severity,detail,prev,curr) "
            "VALUES(?,?,?,?,?,?,?)",
            (self.ts, "Wi-Fi", "ap-unknown", "high", "raw alert", "old", "new"))
        self.store.commit()
        finding = next(f for f in netwatch.audit(self.store)
                       if f["title"] == "ap unknown")
        self.assertEqual(finding["severity"], "high")

    def test_missing_gateway_mac_requires_same_ap_confirmation(self):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        second = sample(self.ts + 300, "Network A", "66:77:88:99:aa:bb",
                        "192.0.2.1", "", "192.0.2.1")
        confirmed = dict(second, ts=self.ts + 310,
                         gw_mac="00-11-22-33-44-55")
        netwatch.record(self.store, first)
        self.assertIn(("ap-unknown", "high"), [
            (event["kind"], event["severity"])
            for event in netwatch.record(self.store, second)])
        before = next(f for f in netwatch.audit(self.store)
                      if f["title"] == "ap unknown")
        self.assertEqual(before["severity"], "high")
        netwatch.record(self.store, confirmed)
        after = next(f for f in netwatch.audit(self.store)
                     if f["title"].startswith("ap unknown"))
        self.assertEqual(after["severity"], "medium")
        self.assertEqual(self.store.db.execute(
            "SELECT severity FROM net_events WHERE kind='ap-unknown'").fetchone()[0],
            "high")

    def test_missing_gateway_mac_conflict_stays_high(self):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        second = sample(self.ts + 300, "Network A", "66:77:88:99:aa:bb",
                        "192.0.2.1", "", "192.0.2.1")
        different = dict(second, ts=self.ts + 310,
                         gw_mac="66-77-88-99-AA-BB")
        netwatch.record(self.store, first)
        netwatch.record(self.store, second)
        netwatch.record(self.store, different)
        finding = next(f for f in netwatch.audit(self.store)
                       if f["title"] == "ap unknown")
        self.assertEqual(finding["severity"], "high")

    def test_missing_gateway_mac_before_roam_uses_recent_same_ap_sample(self):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        missing = dict(first, ts=self.ts + 300, gw_mac="")
        second = sample(self.ts + 600, "Network A", "66:77:88:99:aa:bb",
                        "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        for item in (first, missing, second):
            netwatch.record(self.store, item)
        finding = next(f for f in netwatch.audit(self.store)
                       if f["title"].startswith("ap unknown"))
        self.assertEqual(finding["severity"], "medium")

    def test_missing_gateway_mac_confirmation_expires(self):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        second = sample(self.ts + 300, "Network A", "66:77:88:99:aa:bb",
                        "192.0.2.1", "", "192.0.2.1")
        late = dict(second, ts=self.ts + 901,
                    gw_mac="00-11-22-33-44-55")
        for item in (first, second, late):
            netwatch.record(self.store, item)
        finding = next(f for f in netwatch.audit(self.store)
                       if f["title"] == "ap unknown")
        self.assertEqual(finding["severity"], "high")

    def test_missing_gateway_mac_confirmation_is_bounded(self):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        second = sample(self.ts + 300, "Network A", "66:77:88:99:aa:bb",
                        "192.0.2.1", "", "192.0.2.1")
        netwatch.record(self.store, first)
        netwatch.record(self.store, second)
        for offset in range(1, 14):
            netwatch.record(self.store, dict(
                second, ts=second["ts"] + offset,
                gw_mac="00-11-22-33-44-55"))
        finding = next(f for f in netwatch.audit(self.store)
                       if f["title"] == "ap unknown")
        self.assertEqual(finding["severity"], "high")

    def test_roam_requires_fresh_strong_complete_topology(self):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        cases = (
            {"auth": "Open"},
            {"auth": "Unknown"},
            {"cipher": ""},
            {"gateway": "192.0.2.2"},
            {"gw_mac": "66-77-88-99-AA-BB"},
            {"dns": "8.8.8.8"},
            {"dns": ""},
            {"ts": self.ts + 901},
        )
        from jarvis.collectors.network.netwatch.record import coherent_unverified_roam
        for change in cases:
            with self.subTest(change=change):
                second = dict(first, ts=self.ts + 300,
                              bssid="66:77:88:99:aa:bb")
                second.update(change)
                self.assertFalse(coherent_unverified_roam(first, second))

    def test_historical_high_event_is_preserved_but_contextualized(self):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        second = sample(self.ts + 1, "Network B", "66:77:88:99:aa:bb",
                        "198.51.100.1", "66-77-88-99-AA-BB", "1.1.1.1")
        netwatch.record(self.store, first)
        netwatch.record(self.store, second)
        self.store.db.execute(
            "INSERT INTO net_events(ts,iface,kind,severity,detail,prev,curr) "
            "VALUES(?,?,?,?,?,?,?)",
            (second["ts"], "Wi-Fi", "gateway-changed", "high", "raw alert",
             first["gw_mac"], second["gw_mac"]))
        self.store.commit()
        finding = next(f for f in netwatch.audit(self.store)
                       if f["title"] == "gateway changed during identified network switch")
        self.assertEqual(finding["severity"], "low")
        self.assertIn("original event remains", finding["detail"])
        raw = self.store.db.execute(
            "SELECT severity FROM net_events WHERE kind='gateway-changed'").fetchone()[0]
        self.assertEqual(raw, "high")

    def test_missing_paired_samples_keep_original_high(self):
        self.store.db.execute(
            "INSERT INTO net_events(ts,iface,kind,severity,detail,prev,curr) "
            "VALUES(?,?,?,?,?,?,?)",
            (self.ts, "Wi-Fi", "dns-changed", "high", "raw alert", "old", "new"))
        self.store.commit()
        finding = next(f for f in netwatch.audit(self.store)
                       if f["title"] == "dns changed")
        self.assertEqual(finding["severity"], "high")

    def test_same_time_other_interface_cannot_explain_event(self):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        second = sample(self.ts + 1, "Network B", "66:77:88:99:aa:bb",
                        "198.51.100.1", "66-77-88-99-AA-BB", "1.1.1.1")
        netwatch.record(self.store, first)
        netwatch.record(self.store, second)
        self.store.db.execute(
            "INSERT INTO net_events(ts,iface,kind,severity,detail,prev,curr) "
            "VALUES(?,?,?,?,?,?,?)",
            (second["ts"], "Ethernet", "dns-changed", "high", "raw alert",
             "old", "new"))
        self.store.commit()
        finding = next(f for f in netwatch.audit(self.store)
                       if f["title"] == "dns changed")
        self.assertEqual(finding["severity"], "high")

    def test_missing_bssid_cannot_explain_historical_high(self):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        second = sample(self.ts + 1, "Network B", "",
                        "198.51.100.1", "66-77-88-99-AA-BB", "1.1.1.1")
        netwatch.record(self.store, first)
        netwatch.record(self.store, second)
        self.store.db.execute(
            "INSERT INTO net_events(ts,iface,kind,severity,detail,prev,curr) "
            "VALUES(?,?,?,?,?,?,?)",
            (second["ts"], "Wi-Fi", "gateway-changed", "high", "raw alert",
             "old", "new"))
        self.store.commit()
        finding = next(f for f in netwatch.audit(self.store)
                       if f["title"].startswith("gateway changed"))
        self.assertEqual(finding["severity"], "high")

    def _roam(self, second_bssid="66:77:88:99:aa:bb", mac="00-11-22-33-44-55"):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", mac, "192.0.2.1")
        second = sample(self.ts + 300, "Network A", second_bssid,
                        "192.0.2.1", mac, "192.0.2.1")
        return first, second

    def _ap_finding(self):
        return next(f for f in netwatch.audit(self.store)
                    if f["title"].startswith(("ap unknown", "ap repeat")))

    def test_roam_between_owner_confirmed_aps_is_low(self):
        from jarvis.collectors.network.netwatch import confirmed
        first, second = self._roam()
        netwatch.record(self.store, first)
        netwatch.record(self.store, dict(second, ts=self.ts + 10))   # both APs recorded
        confirmed.confirm(self.store, "Network A", "coworking space", now=self.ts)
        netwatch.record(self.store, dict(first, ts=self.ts + 200))
        netwatch.record(self.store, second)
        finding = next(f for f in netwatch.audit(self.store)
                       if "owner-confirmed" in f["title"])
        self.assertEqual(finding["severity"], "low")
        self.assertIn("original event remains", finding["detail"])

    def test_confirmation_is_pinned_to_recorded_aps_and_gateway(self):
        from jarvis.collectors.network.netwatch import confirmed
        first, second = self._roam()
        netwatch.record(self.store, first)
        confirmed.confirm(self.store, "Network A", "coworking space", now=self.ts)
        netwatch.record(self.store, second)                 # AP added after the pin
        self.assertEqual(self._ap_finding()["severity"], "medium")

        pins = confirmed.load(self.store)
        moved = dict(first, gw_mac="66-77-88-99-aa-bb"), dict(second, gw_mac="66-77-88-99-aa-bb")
        pins["Network A"]["bssids"].append("66:77:88:99:aa:bb")
        self.assertFalse(confirmed.covers(pins, *moved))    # other gateway hardware
        self.assertTrue(confirmed.covers(pins, first, second))

    def test_confirmed_network_still_reports_dns_and_gateway_changes(self):
        from jarvis.collectors.network.netwatch import confirmed
        first, _ = self._roam()
        netwatch.record(self.store, first)
        confirmed.confirm(self.store, "Network A", "coworking space", now=self.ts)
        netwatch.record(self.store, dict(first, ts=self.ts + 60, dns="1.1.1.1"))
        high = {f["title"] for f in netwatch.audit(self.store) if f["severity"] == "high"}
        self.assertIn("dns changed", high)

    def test_confirm_needs_a_reason_and_one_gateway(self):
        from jarvis.collectors.network.netwatch import confirmed
        first, _ = self._roam()
        netwatch.record(self.store, first)
        with self.assertRaises(confirmed.ConfirmError):
            confirmed.confirm(self.store, "Network A", " ")
        with self.assertRaises(confirmed.ConfirmError):
            confirmed.confirm(self.store, "Unknown SSID", "mine")
        netwatch.record(self.store, dict(first, ts=self.ts + 60, gw_mac="66-77-88-99-aa-bb"))
        with self.assertRaises(confirmed.ConfirmError):
            confirmed.confirm(self.store, "Network A", "mine")

    def _drop(self, ts):
        self.store.db.execute(
            "INSERT INTO net_events(ts,iface,kind,severity,detail,prev,curr) "
            "VALUES(?,?,?,?,?,?,?)", (ts, "", "wlan-disconnected", "medium", "d", "", ""))
        self.store.commit()

    def _drop_severity(self):
        return next(f["severity"] for f in netwatch.audit(self.store)
                    if f["title"].startswith("wlan disconnected"))

    def test_drop_beside_an_identified_switch_is_isolated(self):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        second = sample(self.ts + 30, "Network B", "66:77:88:99:aa:bb",
                        "198.51.100.1", "66-77-88-99-AA-BB", "1.1.1.1")
        netwatch.record(self.store, first)
        netwatch.record(self.store, second)
        self.store.db.execute(      # historical raw high from before switch gating
            "INSERT INTO net_events(ts,iface,kind,severity,detail,prev,curr) "
            "VALUES(?,?,?,?,?,?,?)", (second["ts"], "Wi-Fi", "dns-changed", "high", "raw", "", ""))
        self._drop(self.ts + 20)
        self.assertEqual(self._drop_severity(), "low")

    def test_drop_beside_unconfirmed_ap_change_stays_medium_until_confirmed(self):
        from jarvis.collectors.network.netwatch import confirmed
        first, second = self._roam()
        netwatch.record(self.store, first)
        netwatch.record(self.store, dict(second, ts=self.ts + 10))
        netwatch.record(self.store, dict(first, ts=self.ts + 200))
        netwatch.record(self.store, second)
        self._drop(self.ts + 290)
        self.assertEqual(self._drop_severity(), "medium")
        confirmed.confirm(self.store, "Network A", "coworking space", now=self.ts)
        self.assertEqual(self._drop_severity(), "low")

    def test_a_burst_of_drops_stays_medium_on_a_confirmed_network(self):
        from jarvis.collectors.network.netwatch import confirmed
        first, _ = self._roam()
        netwatch.record(self.store, first)
        confirmed.confirm(self.store, "Network A", "coworking space", now=self.ts)
        for offset in (10, 20, 30):
            self._drop(self.ts + offset)
        self.assertEqual(self._drop_severity(), "medium")

    def test_missing_network_identity_does_not_clear_changes(self):
        first = sample(self.ts, "Network A", "00:11:22:33:44:55",
                       "192.0.2.1", "00-11-22-33-44-55", "192.0.2.1")
        second = sample(self.ts + 1, "", "66:77:88:99:aa:bb",
                        "198.51.100.1", "66-77-88-99-AA-BB", "1.1.1.1")
        netwatch.record(self.store, first)
        events = netwatch.record(self.store, second)
        high = {e["kind"] for e in events if e["severity"] == "high"}
        self.assertIn("gateway-changed", high)
        self.assertIn("dns-changed", high)
