"""Package ownership: one dpkg call per path, answers reused only while the
package database is unchanged (perf/lighter-faster, 2026-11-04)."""

import os
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from jarvis.core import util

REAL_STAMP = util.pkgdb_stamp


def _reply(rc, out="", err=""):
    return SimpleNamespace(returncode=rc, stdout=out, stderr=err)


class FakeDpkg:
    """dpkg -S over a fixed ownership table, counting launches."""

    def __init__(self, owned):
        self.owned = dict(owned)
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        out, err = [], []
        for cand in argv[2:]:
            if cand in self.owned:
                out.append(f"{self.owned[cand]}: {cand}")
            else:
                err.append(f"dpkg-query: no path found matching pattern {cand}")
        rc = 1 if err else 0
        return _reply(rc, "\n".join(out) + ("\n" if out else ""), "\n".join(err))


class DpkgOwnsCache(unittest.TestCase):
    def setUp(self):
        util._OWNS.clear()
        util._OWNS_STAMP[0] = None
        self.stamp = ["db-1"]
        patcher = mock.patch.object(util, "pkgdb_stamp", lambda manager: (manager, self.stamp[0]))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.now = [1000.0]
        self.clock = lambda: self.now[0]

    def ask(self, path, run):
        return util.dpkg_owns(path, "dpkg", run=run, clock=self.clock)

    def test_every_spelling_is_asked_in_one_launch(self):
        # dpkg knows fusermount3 only under /bin; the /usr spelling is on disk.
        fake = FakeDpkg({"/bin/fusermount3": "fuse3"})
        self.assertTrue(self.ask("/usr/bin/fusermount3", fake))
        self.assertEqual(len(fake.calls), 1)
        self.assertIn("/bin/fusermount3", fake.calls[0])
        self.assertIn("/usr/bin/fusermount3", fake.calls[0])

    def test_unowned_stays_unowned_and_is_not_asked_again(self):
        fake = FakeDpkg({})
        self.assertFalse(self.ask("/usr/lib/x86_64-linux-gnu/security/pam_evil.so", fake))
        self.assertFalse(self.ask("/usr/lib/x86_64-linux-gnu/security/pam_evil.so", fake))
        self.assertEqual(len(fake.calls), 1)

    def test_package_database_change_drops_every_answer(self):
        fake = FakeDpkg({})
        self.assertFalse(self.ask("/usr/bin/newtool", fake))
        fake.owned["/usr/bin/newtool"] = "newpkg"      # a package was installed
        self.stamp[0] = "db-2"
        self.assertTrue(self.ask("/usr/bin/newtool", fake))
        self.assertEqual(len(fake.calls), 2)

    def test_removal_is_seen_once_the_database_changes(self):
        fake = FakeDpkg({"/usr/bin/tool": "pkg"})
        self.assertTrue(self.ask("/usr/bin/tool", fake))
        del fake.owned["/usr/bin/tool"]
        self.stamp[0] = "db-2"
        self.assertFalse(self.ask("/usr/bin/tool", fake))

    def test_an_answer_expires_after_the_ttl_even_with_an_unchanged_database(self):
        fake = FakeDpkg({"/usr/bin/tool": "pkg"})
        self.assertTrue(self.ask("/usr/bin/tool", fake))
        self.now[0] += util.OWNS_TTL_S + 1
        del fake.owned["/usr/bin/tool"]
        self.assertFalse(self.ask("/usr/bin/tool", fake))
        self.assertEqual(len(fake.calls), 2)

    def test_a_clock_that_steps_back_is_not_trusted(self):
        fake = FakeDpkg({"/usr/bin/tool": "pkg"})
        self.ask("/usr/bin/tool", fake)
        self.now[0] -= 10
        self.ask("/usr/bin/tool", fake)
        self.assertEqual(len(fake.calls), 2)

    def test_launch_failure_is_unknown_and_never_remembered(self):
        def broken(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 8)
        self.assertFalse(self.ask("/usr/bin/tool", broken))
        fake = FakeDpkg({"/usr/bin/tool": "pkg"})
        self.assertTrue(self.ask("/usr/bin/tool", fake))   # asked again, not a cached False

    def test_dpkg_error_status_falls_back_per_spelling_and_does_not_cache_false(self):
        calls = []

        def locked(argv, **kwargs):
            calls.append(argv)
            return _reply(2, "", "dpkg-query: error: database locked")
        self.assertFalse(self.ask("/usr/bin/tool", locked))
        self.assertGreater(len(calls), 1)                   # batch, then one per spelling
        fake = FakeDpkg({"/usr/bin/tool": "pkg"})
        self.assertTrue(self.ask("/usr/bin/tool", fake))

    def test_a_diverted_path_reads_as_owned_as_before(self):
        def diverted(argv, **kwargs):
            return _reply(0, "diversion by libreadline8t64 from: /lib/x/libhistory.so.8.2\n"
                             "diversion by libreadline8t64 to: /lib/x/libhistory.so.8.2.usr-is-merged\n")
        with mock.patch.object(util, "dpkg_candidates", lambda p: [p]):
            self.assertTrue(self.ask("/lib/x/libhistory.so.8.2", diverted))

    def test_a_repointed_symlink_is_a_new_question(self):
        fake = FakeDpkg({})
        with tempfile.TemporaryDirectory() as tmp:
            a, b, link = (os.path.join(tmp, n) for n in ("a", "b", "link"))
            for f in (a, b):
                open(f, "w").close()
            os.symlink(a, link)
            fake.owned[a] = "pkg"
            self.assertTrue(self.ask(link, fake))
            os.remove(link)
            os.symlink(b, link)                             # now points at an unowned file
            self.assertFalse(self.ask(link, fake))
            self.assertEqual(len(fake.calls), 2)

    def test_rpm_false_is_not_remembered(self):
        calls = []

        def rpm(argv, **kwargs):
            calls.append(argv)
            return _reply(1, "file /usr/bin/tool is not owned by any package\n")
        self.assertFalse(util.dpkg_owns("/usr/bin/tool", "rpm", run=rpm, clock=self.clock))
        self.assertFalse(util.dpkg_owns("/usr/bin/tool", "rpm", run=rpm, clock=self.clock))
        self.assertEqual(len(calls), 2 * len(util.dpkg_candidates("/usr/bin/tool")))

    def test_the_cache_is_bounded(self):
        fake = FakeDpkg({})
        for i in range(util.OWNS_MAX + 5):
            self.ask(f"/opt/x/{i}", fake)
        self.assertLessEqual(len(util._OWNS), util.OWNS_MAX)

    def test_real_stamp_names_the_package_database(self):
        seen = []

        def fake_stat(path):
            seen.append(path)
            raise OSError
        out = REAL_STAMP("dpkg", stat=fake_stat)
        self.assertIn("/var/lib/dpkg/status", seen)
        self.assertIn("/var/lib/dpkg/info", seen)
        self.assertIn("/var/lib/dpkg/diversions", seen)
        self.assertEqual(out[0], "dpkg")
        self.assertNotEqual(out, REAL_STAMP("rpm", stat=fake_stat))

if __name__ == "__main__":
    unittest.main()
