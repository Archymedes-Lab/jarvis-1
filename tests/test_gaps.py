import os
import tempfile
import time
import unittest

from jarvis.core.store import Store
from jarvis.intel import gaps


class GapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.addCleanup(self.store.close)
        now = int(time.time())
        self.store.db.executemany(
            "INSERT INTO attack_techniques(tid,name,tactics,platforms,updated) VALUES(?,?,?,?,?)",
            [("T1043", "Commonly Used Port", "command-and-control", "Linux,macOS,Windows", now),
             ("T1571", "Non-Standard Port", "command-and-control", "Linux,macOS,Windows", now),
             ("T1064", "Scripting", "stealth,execution", "Linux,macOS,Windows", now),
             ("T1059", "Command and Scripting Interpreter", "execution", "Linux,macOS,Windows", now),
             ("T1578", "Modify Cloud Compute Infrastructure", "defense-impairment", "IaaS", now),
             ("T1221", "Template Injection", "stealth", "Windows", now)])
        self.store.db.executemany(
            "INSERT INTO indicators(kind,value,norm,status,doc_count,context,source_url,first_seen,last_seen)"
            " VALUES('attack',?,?,'active',?,'','',?,?)",
            [("T1043", "T1043", 7, now, now), ("T1064", "T1064", 6, now, now),
             ("T1578", "T1578", 5, now, now), ("T1221", "T1221", 5, now, now)])
        self.store.db.commit()

    def test_revoked_ids_are_judged_under_their_successor(self):
        out, covered, closeable = gaps.gaps(self.store)
        by_title = {f["title"]: f for f in out}
        self.assertNotIn("T1043 Commonly Used Port", by_title)
        self.assertNotIn("T1064 Scripting", by_title)
        self.assertIn(("T1043", 7), [(c[0], c[1]) for c in covered])
        self.assertTrue(any(c[0] == "T1043" and "retired id T1043, now T1571" in c[2]
                            for c in covered))
        self.assertTrue(any(c[0] == "T1064" and "now T1059" in c[2] for c in covered))

    def test_cloud_only_techniques_are_not_gaps_for_a_laptop(self):
        out, _, closeable = gaps.gaps(self.store)
        cloud = [f for f in out if f["title"].startswith("T1578")]
        self.assertEqual(len(cloud), 1)
        self.assertEqual((cloud[0]["category"], cloud[0]["severity"]), ("not applicable", "low"))
        self.assertIn("IaaS", cloud[0]["detail"])
        self.assertNotIn("T1578", [c[0] for c in closeable])

    def test_a_real_windows_gap_still_reads_high(self):
        out, _, closeable = gaps.gaps(self.store)
        hit = [f for f in out if f["title"].startswith("T1221")]
        self.assertEqual(len(hit), 1)
        self.assertEqual((hit[0]["category"], hit[0]["severity"]), ("coverage gap", "high"))
        self.assertIn("T1221", [c[0] for c in closeable])


if __name__ == "__main__":
    unittest.main()
