"""Popular infrastructure must never become an attacker domain by association."""

import os
import tempfile
import unittest

from jarvis.core import warninglist
from jarvis.core.store import Store


class MatchDomainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.addCleanup(self.store.close)
        self.store.db.executemany("INSERT INTO popular_domains(domain, rank) VALUES(?,?)",
                                  [("azure.com", 28), ("cloudinary.com", 1037),
                                   ("docsend.com", 17749)])
        for norm, source, conf in (("azure.com", "exa", "medium"),
                                   ("res.cloudinary.com", "urlhaus", "high"),
                                   ("evil.eastus.cloudapp.azure.com", "threatfox", "high"),
                                   ("docsend.com", "exa", "medium"),
                                   ("files.docsend.com", "threatfox", "high"),
                                   ("kynxdev.xyz", "exa", "medium")):
            self._indicator(norm, source, conf)
        self.store.commit()

    def _indicator(self, norm, source, confidence):
        self.store.db.execute(
            """INSERT INTO indicators(kind,value,norm,confidence,topic,context,malware,
                                      source_url,first_seen,last_seen,source)
               VALUES('domain',?,?,?,'','ctx','fam','u',0,0,?)""",
            (norm, norm, confidence, source))

    def match(self, name):
        m = warninglist.match_domain(self.store, name)
        return m and (m["severity"], m["indicator"])

    def test_a_popular_registrable_domain_is_never_an_indicator(self):
        # Measured: Windows telemetry hosts matched a writeup's `azure.com`.
        self.assertIsNone(self.match("onedscolprdneu53.northeurope.cloudapp.azure.com"))

    def test_a_feed_tenant_host_under_a_popular_zone_keeps_full_strength(self):
        self.assertEqual(self.match("evil.eastus.cloudapp.azure.com"),
                         ("critical", "evil.eastus.cloudapp.azure.com"))

    def test_a_shared_service_host_on_a_top_domain_is_weak_evidence(self):
        self.assertEqual(self.match("res.cloudinary.com"), ("low", "res.cloudinary.com"))
        # ...and never a parent for other hosts on that platform.
        self.assertIsNone(self.match("x.res.cloudinary.com"))

    def test_prose_extracted_brand_is_dropped_but_feeds_below_top_10k_count(self):
        self.assertIsNone(self.match("docsend.com"))
        self.assertEqual(self.match("files.docsend.com"), ("critical", "files.docsend.com"))

    def test_unknown_domains_are_unaffected(self):
        self.assertEqual(self.match("cdn.kynxdev.xyz"), ("medium", "kynxdev.xyz"))

    def test_fallback_list_applies_before_the_first_download(self):
        self.store.db.execute("DELETE FROM popular_domains")
        self.assertIsNone(self.match("onedscolprdneu53.northeurope.cloudapp.azure.com"))
