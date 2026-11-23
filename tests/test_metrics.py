import re
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from jarvis.core.store import Store
from jarvis.response import acknowledge
from jarvis.service.scheduler import Scheduler
from jarvis.web import metrics
from jarvis.web.server import Handler
from tests import _apiauth

JOBS = {"alpha": (60, "Alpha"), "beta": (300, "Beta"), "never": (60, "Never ran")}
SECRET = "203.0.113.77 /home/victim/.ssh/id_ed25519"

# One exposition line: a comment, or `name{labels} value`.
LINE = re.compile(r'^(# (HELP|TYPE) [a-z_]+ .+|[a-z_]+(\{[a-z_]+="[^"\n]*"(,[a-z_]+="[^"\n]*")*\})? '
                  r'(-?[0-9.e+-]+|NaN|\+Inf|-Inf))$')


def samples(text, name):
    out = {}
    for line in text.splitlines():
        m = re.match(rf'^{name}(?:\{{(.*)\}})? (\S+)$', line)
        if m:
            out[m.group(1) or ""] = float(m.group(2))
    return out


class MetricsRenderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "state.db")
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.scheduler = Scheduler(self.path, ("wsl",))
        self.crit = {"host": "wsl", "category": "network", "severity": "critical",
                     "title": f"contacted {SECRET}", "detail": SECRET, "where": SECRET}
        self.high = {"host": "wsl", "category": "access", "severity": "high",
                     "title": "new key", "detail": "x", "where": "y"}
        self.store.save_snapshot("alpha", [self.crit, self.high, {"severity": "ok", "title": "fine"}])
        self.store.save_snapshot("beta", [], error="bridge down")
        self.store.db.commit()

    def render(self, stamp=None):
        return metrics.render(self.path, self.scheduler, stamp=stamp, jobs=JOBS)

    def test_every_line_is_valid_exposition_and_families_are_contiguous(self):
        text = self.render()
        self.assertTrue(text.endswith("\n"))
        seen, current = set(), None
        for line in text.splitlines():
            self.assertRegex(line, LINE)
            if line.startswith("# TYPE "):
                current = line.split()[2]
                self.assertNotIn(current, seen, "family declared twice")
                seen.add(current)
            elif not line.startswith("#"):
                self.assertEqual(re.match(r"[a-z_]+", line).group(0), current,
                                 "sample outside its family block")

    def test_no_evidence_leaks_into_labels_or_values(self):
        text = self.render()
        for fragment in ("203.0.113.77", "victim", "id_ed25519", "contacted", "new key"):
            self.assertNotIn(fragment, text)
        labels = set(re.findall(r'([a-z_]+)="', text))
        self.assertLessEqual(labels, {"severity", "job"})
        jobs = set(re.findall(r'job="([^"]*)"', text))
        self.assertLessEqual(jobs, set(JOBS))

    def test_findings_counted_by_severity_and_ok_is_not_a_finding(self):
        open_ = samples(self.render(), "jarvis_findings_open")
        self.assertEqual(open_['severity="critical"'], 1)
        self.assertEqual(open_['severity="high"'], 1)
        self.assertEqual(open_['severity="medium"'], 0)
        self.assertEqual(len(open_), 4)

    def test_acknowledged_finding_moves_out_of_open(self):
        acknowledge.acknowledge(self.store, self.high, "alpha", "expected key rotation")
        text = self.render()
        self.assertEqual(samples(text, "jarvis_findings_open")['severity="high"'], 0)
        self.assertEqual(samples(text, "jarvis_findings_acknowledged")['severity="high"'], 1)
        # A critical stays open: only what was acknowledged moves.
        self.assertEqual(samples(text, "jarvis_findings_open")['severity="critical"'], 1)

    def test_never_reported_collector_has_no_age_and_is_not_passing(self):
        text = self.render()
        self.assertEqual(samples(text, "jarvis_collector_observed")['job="never"'], 0)
        self.assertNotIn('job="never"', "\n".join(
            line for line in text.splitlines()
            if line.startswith(("jarvis_collector_last_run_age_seconds",
                                "jarvis_collector_failing"))))
        self.assertEqual(samples(text, "jarvis_collector_observed")['job="alpha"'], 1)

    def test_failing_collector_and_age_are_reported(self):
        stamp = time.time() + 1000
        text = self.render(stamp=stamp)
        self.assertEqual(samples(text, "jarvis_collector_failing")['job="beta"'], 1)
        self.assertEqual(samples(text, "jarvis_collector_failing")['job="alpha"'], 0)
        self.assertGreaterEqual(samples(text, "jarvis_collector_last_run_age_seconds")['job="alpha"'], 999)
        self.assertEqual(samples(text, "jarvis_collector_interval_seconds")['job="beta"'], 300)

    def test_unreadable_store_is_unavailable_not_zeros(self):
        with patch("jarvis.web.metrics.Store.get_snapshots", side_effect=OSError("disk")):
            with self.assertRaises(metrics.Unavailable):
                self.render()

    def test_score_failure_drops_the_score_not_the_scrape(self):
        with patch("jarvis.web.metrics.score.stable", side_effect=RuntimeError("bug")):
            text = self.render()
        self.assertNotIn("jarvis_security_score", text)
        self.assertIn("jarvis_findings_open", text)

    def test_cache_bounds_renders(self):
        metrics._cache.update(at=0.0, body=None, db=None)
        with patch("jarvis.web.metrics.render", return_value="x 1\n") as render:
            metrics.cached(self.path, self.scheduler, now=1000.0)
            metrics.cached(self.path, self.scheduler, now=1000.0 + metrics.CACHE_S - 1)
            self.assertEqual(render.call_count, 1)
            metrics.cached(self.path, self.scheduler, now=1000.0 + metrics.CACHE_S + 1)
            self.assertEqual(render.call_count, 2)
        metrics._cache.update(at=0.0, body=None, db=None)

    def test_render_failure_is_not_cached(self):
        metrics._cache.update(at=0.0, body=None, db=None)
        with patch("jarvis.web.metrics.render", side_effect=metrics.Unavailable("x")):
            with self.assertRaises(metrics.Unavailable):
                metrics.cached(self.path, self.scheduler, now=5.0)
        self.assertIsNone(metrics._cache["body"])


class MetricsRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = str(Path(self.tmp.name) / "state.db")
        Store(path).close()
        Handler.db_path = path
        Handler.scheduler = Scheduler(path, ("wsl",))
        metrics._cache.update(at=0.0, body=None, db=None)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.port = self.httpd.server_address[1]

    def get(self, host=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/metrics",
                                     headers=_apiauth.grant(self))
        if host:
            req.add_header("Host", host)
        return urllib.request.urlopen(req, timeout=10)

    def test_scrape_returns_exposition(self):
        with self.get() as r:
            self.assertEqual(r.status, 200)
            self.assertTrue(r.headers["Content-Type"].startswith("text/plain; version=0.0.4"))
            self.assertIn("jarvis_up 1", r.read().decode())

    def test_rebound_host_is_refused(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.get(host="attacker.example:8787")
        self.assertEqual(ctx.exception.code, 403)

    def test_store_failure_is_503(self):
        with patch("jarvis.web.metrics.render", side_effect=metrics.Unavailable("OSError")):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self.get()
        self.assertEqual(ctx.exception.code, 503)


if __name__ == "__main__":
    unittest.main()
