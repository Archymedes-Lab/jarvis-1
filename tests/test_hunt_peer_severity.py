"""How serious a connection to a listed address is depends on what the list claims.

2026-10-30 quality control: Chrome reaching a Google address (142.251.37.78)
and Windows Update reaching a Microsoft address (4.247.188.233) were reported
critical "known attacker" because blocklist.de, which lists hosts seen
attacking services (often shared or reassigned cloud addresses), carried them.

Invariants (revised 2026-11-08, docs/security/ALERT-QUALITY-2026-11-08.md):
  * a match from a malware infrastructure feed (ThreatFox, Feodo, URLhaus) is
    high on that list's word alone and critical only with an independent
    second signal (the process image in a temp/download folder, its digest
    matching a malware sample, beacon-shaped repeated contact outside a
    peer-to-peer swarm, or the address also in a Spamhaus DROP range);
  * a match from an attack-source reputation list (blocklist.de, CINS, Binary
    Defense, IPsum) is medium "reported attack source": still reported, never
    called a known attacker on that list's word alone;
  * a shared Google / Google Cloud address is medium whatever the feed;
  * collapsing per process counts only the corroborated (critical) matches.
"""

import os
import tempfile
import unittest

from jarvis.core.store import Store
from jarvis.core.util import now
from jarvis.intel import hunt


class PeerSeverity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "jarvis.db"))
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.store.close)

    def listed(self, ip, feed, context="attacking host"):
        t = now()
        self.store.db.execute(
            "INSERT INTO indicators(kind,value,norm,confidence,topic,context,source_url,"
            "first_seen,last_seen,status,source) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("ipv4", ip, ip, "high", feed, context, f"https://{feed}.test/list", t, t, "active", feed))

    def connected(self, ip, pname="chrome.exe", fp=None):
        t, fp = now(), fp or f"fp-{pname}"
        self.store.db.execute("INSERT OR IGNORE INTO procs(fp,host,name,exe,first_seen,last_seen) "
                              "VALUES(?,?,?,?,?,?)", (fp, "win", pname, f"C:\\{pname}", t, t))
        self.store.db.execute("INSERT INTO peers(key,host,fp,remote_ip,remote_port,scope,rdns,"
                              "first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?)",
                              (f"{fp}|{ip}", "win", fp, ip, 443, "public", "", t, t))

    def findings(self):
        return [f for f in hunt.check_peers(self.store) if f.get("category") == "c2 match"]

    def test_an_attack_source_list_alone_is_medium_not_known_attacker(self):
        for feed in ("blocklist-de", "cins", "binarydefense", "ipsum"):
            with self.subTest(feed=feed):
                self.setUp()
                self.listed("142.251.37.78", feed)
                self.connected("142.251.37.78")
                out = self.findings()
                self.assertEqual([f["severity"] for f in out], ["medium"], out)
                self.assertNotIn("known attacker", out[0]["title"])
                self.assertIn("reported attack source", out[0]["title"] + out[0]["detail"])

    def test_malware_infrastructure_alone_is_high_not_critical(self):
        for feed in ("threatfox", "feodo", "urlhaus", "threatfox-full", "urlhaus-full"):
            with self.subTest(feed=feed):
                self.setUp()
                self.listed("45.155.205.7", feed, "botnet C2")
                self.connected("45.155.205.7", "evil.exe")
                out = self.findings()
                self.assertEqual([f["severity"] for f in out], ["high"], out)
                self.assertNotIn("known attacker", out[0]["title"])
                self.assertIn("no second signal", out[0]["detail"])

    def test_malware_infrastructure_with_a_dropped_image_is_critical(self):
        self.listed("45.155.205.7", "threatfox", "botnet C2")
        t = now()
        self.store.db.execute("INSERT INTO procs(fp,host,name,exe,first_seen,last_seen) VALUES(?,?,?,?,?,?)",
                              ("fp-drop", "win", "upd.exe", "C:\\Users\\u\\AppData\\Local\\Temp\\upd.exe", t, t))
        self.store.db.execute("INSERT INTO peers(key,host,fp,remote_ip,remote_port,scope,rdns,first_seen,last_seen)"
                              " VALUES(?,?,?,?,?,?,?,?,?)", ("k", "win", "fp-drop", "45.155.205.7", 443, "public", "", t, t))
        out = self.findings()
        self.assertEqual([f["severity"] for f in out], ["critical"], out)
        self.assertIn("known attacker", out[0]["title"])
        self.assertIn("temp or download folder", out[0]["detail"])

    def test_malware_infrastructure_inside_a_drop_range_is_critical(self):
        t = now()
        self.listed("45.155.205.7", "threatfox", "botnet C2")
        self.store.db.execute(
            "INSERT INTO indicators(kind,value,norm,confidence,topic,context,source_url,"
            "first_seen,last_seen,status,source) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("cidr", "45.155.205.0/24", "45.155.205.0/24", "high", "spamhaus-drop", "hijacked network",
             "https://www.spamhaus.org/drop/drop.txt", t, t, "active", "spamhaus-drop"))
        self.connected("45.155.205.7", "evil.exe")
        out = self.findings()
        # One finding per peer for a single process: the address hit (critical,
        # corroborated by the range) and the range hit itself (high).
        self.assertEqual(sorted(f["severity"] for f in out), ["critical", "high"], out)

    def beacon(self, ip, pname, seen, span_s, fp=None):
        self.connected(ip, pname, fp=fp)
        t = now()
        self.store.db.execute("UPDATE peers SET seen_count=?, first_seen=?, last_seen=? WHERE remote_ip=?",
                              (seen, t - span_s, t, ip))

    def test_repeated_contact_to_a_c2_listing_is_critical(self):
        self.listed("45.155.205.7", "threatfox", "AsyncRAT")
        self.beacon("45.155.205.7", "svc.exe", seen=12, span_s=6 * 3600)
        out = self.findings()
        self.assertEqual([f["severity"] for f in out], ["critical"], out)
        self.assertIn("reached it repeatedly", out[0]["detail"])

    def test_a_brief_repeat_is_not_a_second_signal(self):
        self.listed("45.155.205.7", "threatfox", "AsyncRAT")
        self.beacon("45.155.205.7", "svc.exe", seen=12, span_s=600)
        self.assertEqual([f["severity"] for f in self.findings()], ["high"])

    def test_a_peer_to_peer_swarm_member_recurring_is_not_a_second_signal(self):
        for i in range(hunt.PEER_SINGLE_THRESHOLD + 1):
            ip = f"45.155.205.{10 + i}"
            self.listed(ip, "threatfox", "AsyncRAT")
            self.beacon(ip, "btweb.exe", seen=40, span_s=8 * 3600, fp="fp-bt")
        out = self.findings()
        self.assertEqual([f["severity"] for f in out], ["high"], out)
        self.assertIn("(0 corroborated)", out[0]["title"])

    def test_a_shared_provider_address_is_medium_even_on_a_c2_feed(self):
        for ip in ("142.251.38.238", "35.190.43.134"):
            with self.subTest(ip=ip):
                self.setUp()
                self.listed(ip, "threatfox", "Quasar RAT")
                self.connected(ip, "firefox.exe")
                out = self.findings()
                self.assertEqual([f["severity"] for f in out], ["medium"], out)
                self.assertIn("shared Google", out[0]["detail"])

    def test_collapsed_counts_only_corroborated_matches(self):
        feeds = ["threatfox"] + ["blocklist-de", "cins"] * hunt.PEER_SINGLE_THRESHOLD   # over the threshold
        for i, feed in enumerate(feeds):
            ip = f"45.155.205.{10 + i}"
            self.listed(ip, feed)
            self.connected(ip, "btweb.exe", fp="fp-bt")
        out = self.findings()
        self.assertEqual(len(out), 1, out)
        self.assertIn("(0 corroborated)", out[0]["title"])
        self.assertEqual(out[0]["severity"], "high")
        self.assertIn("1 high", out[0]["detail"])


if __name__ == "__main__":
    unittest.main()
