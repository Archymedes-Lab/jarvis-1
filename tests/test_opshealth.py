"""Operational health (jarvis/collectors/host/opshealth.py): each test names
the invariant it holds. systemctl and journalctl are faked; certificates are
real ones made with openssl in a temporary root."""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from jarvis.collectors.host import opshealth


class MetaStore:
    def __init__(self):
        self.meta = {}

    def get_meta(self, key, default=""):
        return self.meta.get(key, default)

    def set_meta(self, key, value):
        self.meta[key] = value


class FakeRun:
    """argv prefix -> (code, stdout)."""

    def __init__(self, table=None):
        self.table = dict(table or {})
        self.calls = []

    def __call__(self, argv, timeout=30):
        self.calls.append(argv)
        for prefix, result in self.table.items():
            if tuple(argv[:len(prefix)]) == prefix:
                return result(argv) if callable(result) else result
        return 0, ""


HEALTHY = {("systemctl", "list-units"): (0, ""),
           ("journalctl", "-k"): (0, ""),
           ("journalctl", "--list-boots"): (0, json.dumps([{"boot_id": "a" * 32}, {"boot_id": "b" * 32}])),
           ("journalctl", "-b"): (0, "systemd-journald[1]: Journal stopped\n")}


def make_cert(path, days, cn="example.test"):
    if days >= 0:
        valid = ["-days", str(days)]
        r = subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                            "-nodes", "-keyout", path + ".key", "-out", path, "-subj", f"/CN={cn}", *valid],
                           capture_output=True, check=False)
        return r.returncode == 0
    return False


@unittest.skipUnless(shutil.which("openssl"), "needs openssl to make test certificates")
class Certificates(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="opshealth-")
        os.makedirs(os.path.join(self.root, "etc/nginx/sites-enabled"))
        os.makedirs(os.path.join(self.root, "etc/ssl/site"))
        os.makedirs(os.path.join(self.root, "etc/letsencrypt/live/le.test"))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def site(self, text):
        with open(os.path.join(self.root, "etc/nginx/sites-enabled/default"), "w") as fh:
            fh.write(text)

    def run_audit(self, now=None):
        return opshealth.audit(MetaStore(), now=now, root=self.root, run=FakeRun(HEALTHY))

    def test_expiry_tiers(self):
        soon = os.path.join(self.root, "etc/ssl/site/soon.pem")
        later = os.path.join(self.root, "etc/letsencrypt/live/le.test/cert.pem")
        self.assertTrue(make_cert(soon, 5, "soon.test") and make_cert(later, 90, "le.test"))
        self.site("server {\n  ssl_certificate /etc/ssl/site/soon.pem;\n"
                  "  ssl_certificate_key /etc/ssl/site/soon.pem.key;\n}\n")
        out = self.run_audit()
        by = {f["title"]: f for f in out}
        self.assertIn("TLS certificate for soon.test expires in 4 days", by)
        self.assertEqual(by["TLS certificate for soon.test expires in 4 days"]["severity"], "high")
        self.assertFalse(any("le.test" in t for t in by))
        # 80 days later the 90-day one is inside the renewal-failing band, the other expired.
        out = self.run_audit(now=time.time() + 80 * 86400)
        by = {f["title"]: f["severity"] for f in out}
        self.assertEqual(by["TLS certificate for soon.test has expired"], "critical")
        self.assertEqual(by["TLS certificate for le.test expires in 9 days"], "medium")

    def test_missing_certificate_named_by_config(self):
        self.site("ssl_certificate /etc/ssl/site/gone.pem;\n")
        titles = {f["title"] for f in self.run_audit()}
        self.assertIn("web server names a certificate that is missing", titles)

    def test_key_files_are_never_opened(self):  # I3
        opened = []
        self.site("ssl_certificate /etc/ssl/site/a.key;\nSSLCertificateFile /etc/letsencrypt/live/x/privkey.pem\n")

        def reader(p):
            opened.append(p)
            raise ValueError("unexpected")
        opshealth.audit(MetaStore(), root=self.root, run=FakeRun(HEALTHY), cert_reader=reader)
        self.assertEqual(opened, [])

    def test_unparseable_certificate_is_not_observed(self):  # I1
        bad = os.path.join(self.root, "etc/ssl/site/bad.pem")
        with open(bad, "w") as fh:
            fh.write("not a certificate\n")
        self.site("ssl_certificate /etc/ssl/site/bad.pem;\n")
        vis = [f for f in self.run_audit() if f["category"] == "visibility"]
        self.assertTrue(vis and "bad.pem" in vis[0]["detail"])

    def test_certificate_count_is_bounded(self):  # I2
        self.site("".join(f"ssl_certificate /etc/ssl/site/c{i}.pem;\n" for i in range(opshealth.MAX_CERTS + 3)))
        paths, extra = opshealth.cert_paths(self.root)
        self.assertEqual(len(paths), opshealth.MAX_CERTS)
        self.assertEqual(extra, 3)


class Units(unittest.TestCase):
    def test_failed_units_reported_with_result(self):
        run = FakeRun({**HEALTHY,
                       ("systemctl", "list-units"): (0, "nginx.service loaded failed failed A high performance web server\n"
                                                        "backup.timer loaded failed failed Nightly backup\n"),
                       ("systemctl", "show"): (0, "Result=exit-code\nExecMainStatus=1\n")})
        out = opshealth.audit(MetaStore(), root="/nonexistent-root", run=run)
        by = {f["title"]: f for f in out}
        self.assertIn("service nginx.service has failed", by)
        self.assertIn("Result exit-code", by["service nginx.service has failed"]["detail"])
        self.assertIn("service backup.timer has failed", by)

    def test_no_systemd_is_not_applicable(self):  # I1
        run = FakeRun({("systemctl",): (None, "missing"), ("journalctl",): (None, "missing")})
        self.assertEqual(opshealth.audit(MetaStore(), root="/nonexistent-root", run=run), [])

    def test_systemctl_error_is_not_healthy(self):  # I1
        run = FakeRun({**HEALTHY, ("systemctl", "list-units"): (4, "")})
        vis = [f for f in opshealth.audit(MetaStore(), root="/nonexistent-root", run=run)
               if f["category"] == "visibility"]
        self.assertTrue(vis and "exited 4" in vis[0]["detail"])


class Kernel(unittest.TestCase):
    def kernel(self, *messages, cursor="c1"):
        lines = [json.dumps({"MESSAGE": m, "__REALTIME_TIMESTAMP": str(int(time.time() * 1e6)), "__CURSOR": cursor})
                 for m in messages]
        return 0, "\n".join(lines) + "\n"

    def test_oom_kills_reported_and_cursor_kept(self):
        store = MetaStore()
        run = FakeRun({**HEALTHY, ("journalctl", "-k"): self.kernel(
            "Out of memory: Killed process 4242 (php-fpm8.3) total-vm:812345kB", "eth0: link up")})
        out = opshealth.audit(store, root="/nonexistent-root", run=run)
        f = [f for f in out if f["title"].startswith("the kernel killed")][0]
        self.assertIn("php-fpm8.3", f["detail"])
        self.assertEqual(json.loads(store.meta[opshealth.STATE_META])["cursor"], "c1")
        # The next run reads after the cursor, and the kill stays reported for a day.
        run2 = FakeRun({**HEALTHY, ("journalctl", "-k"): (0, "")})
        out = opshealth.audit(store, root="/nonexistent-root", run=run2)
        self.assertTrue(any(f["title"].startswith("the kernel killed") for f in out))
        self.assertIn("--after-cursor", [a for argv in run2.calls for a in argv])
        out = opshealth.audit(store, now=time.time() + 2 * 86400, root="/nonexistent-root", run=FakeRun(HEALTHY))
        self.assertFalse(any(f["title"].startswith("the kernel killed") for f in out))

    def test_unclean_boot_reported_once_learning_first(self):
        store = MetaStore()
        boots = (0, json.dumps([{"boot_id": "a" * 32}, {"boot_id": "c" * 32}]))
        clean = FakeRun({**HEALTHY, ("journalctl", "--list-boots"): boots})
        self.assertFalse([f for f in opshealth.audit(store, root="/x", run=clean) if "went down" in f["title"]])
        # A new previous boot appears that ended with no shutdown record.
        boots2 = (0, json.dumps([{"boot_id": "a" * 32}, {"boot_id": "c" * 32}, {"boot_id": "d" * 32}]))
        crash = FakeRun({**HEALTHY, ("journalctl", "--list-boots"): boots2,
                         ("journalctl", "-b"): lambda argv: (0, "kernel: something\n") if argv[2] == "c" * 32
                         else (0, "Journal stopped\n")})
        out = opshealth.audit(store, root="/x", run=crash)
        self.assertEqual(len([f for f in out if "went down without shutting down" in f["title"]]), 1)

    def test_a_forged_shutdown_marker_does_not_make_a_crash_clean(self):
        # The journal as journalctl would filter it: the only "Journal stopped" in
        # boot c was written by uid 1000 (`logger "Journal stopped"`), so it is
        # returned only when the read is not limited to root's records.
        def tail(argv):
            if argv[2] == "c" * 32:
                return (0, "kernel: something\n") if "_UID=0" in argv else (0, "Journal stopped\n")
            return 0, "Journal stopped\n"
        boots = (0, json.dumps([{"boot_id": "a" * 32}, {"boot_id": "c" * 32}, {"boot_id": "d" * 32}]))
        endings, _p = opshealth.boot_endings(FakeRun({**HEALTHY, ("journalctl", "--list-boots"): boots,
                                                      ("journalctl", "-b"): tail}))
        self.assertEqual(endings, {"a" * 32: "clean", "c" * 32: "unclean"})

    def test_each_unclean_boot_has_its_own_identity(self):
        store = MetaStore()
        opshealth.audit(store, root="/x", run=FakeRun(HEALTHY))          # learn
        boots = [{"boot_id": c * 32} for c in "abcde"]
        run = FakeRun({**HEALTHY, ("journalctl", "--list-boots"): (0, json.dumps(boots)),
                       ("journalctl", "-b"): (0, "kernel: something\n")})
        out = [f for f in opshealth.audit(store, root="/x", run=run) if "went down" in f["title"]]
        self.assertGreaterEqual(len(out), 2)
        self.assertEqual(len({(f["category"], f["title"], f["where"]) for f in out}), len(out))

    def test_volatile_journal_is_said(self):  # I1
        run = FakeRun({**HEALTHY, ("journalctl", "--list-boots"): (0, json.dumps([{"boot_id": "a" * 32}]))})
        real = os.path.isdir
        os.path.isdir = lambda p: False if p == "/var/log/journal" else real(p)
        try:
            vis = [f for f in opshealth.audit(MetaStore(), root="/x", run=run) if f["category"] == "visibility"]
        finally:
            os.path.isdir = real
        self.assertTrue(vis and "not persistent" in vis[0]["detail"])

    def test_unreadable_journal_is_not_observed(self):  # I1
        class R:
            returncode, stdout = 0, ""
            stderr = "Hint: You are currently not seeing messages from other users and the system.\n" \
                     "No journal files were opened due to insufficient permissions.\n"
        real = subprocess.run
        subprocess.run = lambda *a, **k: R()
        try:
            code, why = opshealth._run(["journalctl", "-k"])
        finally:
            subprocess.run = real
        self.assertIsNone(code)
        self.assertIn("not readable", why)
        run = FakeRun({**HEALTHY, ("journalctl", "-k"): (None, why)})
        vis = [f for f in opshealth.audit(MetaStore(), root="/x", run=run) if f["category"] == "visibility"]
        self.assertTrue(vis and "not readable" in vis[0]["detail"])

    def test_kernel_lines_are_bounded(self):  # I2
        run = FakeRun(HEALTHY)
        opshealth.audit(MetaStore(), root="/x", run=run)
        argv = next(a for a in run.calls if a[:2] == ["journalctl", "-k"])
        self.assertEqual(argv[argv.index("-n") + 1], str(opshealth.MAX_LINES))

    def test_corrupt_state_restarts_and_says_so(self):
        store = MetaStore()
        store.meta[opshealth.STATE_META] = "[broken"
        vis = [f for f in opshealth.audit(store, root="/x", run=FakeRun(HEALTHY)) if f["category"] == "visibility"]
        self.assertTrue(vis and "starting again" in vis[0]["detail"])


if __name__ == "__main__":
    unittest.main()
