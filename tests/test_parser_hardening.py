"""Hostile files under a scanned root (security review 2026-10-30, ARGUS-2026-002).

Each test is a file a local user or a repository author can plant: it must not
hang a lane, exhaust memory, read past a link, or abort the whole scan.
"""

import os
import random
import shutil
import tempfile
import threading
import time
import unittest

from jarvis.collectors import credentials
from jarvis.collectors.appcode import lockfiles, rules


def _bounded(fn, seconds=10):
    """fn() in a daemon thread; (finished, result). A blocked call is reported,
    not waited for."""
    out = []
    t = threading.Thread(target=lambda: out.append(fn()), daemon=True)
    t.start()
    t.join(seconds)
    return (not t.is_alive()), (out[0] if out else None)


class HostileFiles(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="hostile-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def path(self, name):
        return os.path.join(self.dir, name)

    def fifo(self, name):
        p = self.path(name)
        os.mkfifo(p)

        def unblock():
            try:
                os.close(os.open(p, os.O_WRONLY | os.O_NONBLOCK))
            except OSError:
                pass
        self.addCleanup(unblock)
        return p

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no FIFOs here")
    def test_fifo_swapped_in_after_the_walk_blocks_no_reader(self):
        for name, fn, empty in (("app.py", rules.scan_file, None),
                                ("package-lock.json", lockfiles.parse, []),
                                (".env", lambda p: credentials.scan_file(p, follow=False), [])):
            p = self.fifo(name)
            done, result = _bounded(lambda fn=fn, p=p: fn(p))
            self.assertTrue(done, f"{name}: blocked on a FIFO")
            self.assertEqual(result, empty, name)

    @unittest.skipUnless(os.path.exists("/dev/zero"), "no /dev/zero")
    def test_link_to_dev_zero_is_not_read(self):
        for name, fn in (("app.py", rules.scan_file), ("package-lock.json", lockfiles.parse),
                         (".env", credentials.scan_file)):
            os.symlink("/dev/zero", self.path(name))
            done, result = _bounded(lambda fn=fn, name=name: fn(self.path(name)))
            self.assertTrue(done, name)
            self.assertFalse(result, name)

    def test_appcode_reads_do_not_follow_a_link_out_of_the_repository(self):
        outside = self.path("outside.txt")
        with open(outside, "w") as fh:
            fh.write('AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
                     'requests==2.0.0\n')
        os.symlink(outside, self.path(".env"))
        os.symlink(outside, self.path("requirements.txt"))
        self.assertTrue(credentials.scan_file(self.path(".env")))           # the secrets job follows
        self.assertEqual(credentials.scan_file(self.path(".env"), follow=False), [])
        self.assertEqual(lockfiles.parse(self.path("requirements.txt")), [])
        self.assertTrue(lockfiles._requirements("requests==2.0.0\n"))

    def test_deeply_nested_lockfiles_do_not_abort_the_scan(self):
        for name, text in (("package-lock.json", "[" * 100000),
                           ("Cargo.lock", "a = " + "[" * 100000),
                           ("composer.lock", '{"packages": ' + "[" * 100000)):
            with open(self.path(name), "w") as fh:
                fh.write(text)
            self.assertEqual(lockfiles.parse(self.path(name)), [], name)


class PrivateKeyBlocks(unittest.TestCase):
    def test_unterminated_begin_lines_are_linear(self):
        text = "-----BEGIN PRIVATE KEY-----\n" * 16000          # ~450 KB: 40 s before
        start = time.monotonic()
        self.assertEqual(list(credentials._private_blocks(text)), [])
        self.assertLess(time.monotonic() - start, 2.0)

    def test_same_blocks_and_lines_as_the_regex(self):
        rng = random.Random(7)
        parts = ["-----BEGIN PRIVATE KEY-----\n", "-----END PRIVATE KEY-----\n",
                 "-----BEGIN RSA PRIVATE KEY-----\n", "-----END RSA PRIVATE KEY-----\n",
                 "-----BEGIN OPENSSH PRIVATE KEY-----\n", "-----END OPENSSH PRIVATE KEY-----\n",
                 "Proc-Type: 4,ENCRYPTED\n", "QUJDRA==\n", "plain line\n"]
        for _ in range(300):
            text = "".join(rng.choice(parts) for _ in range(rng.randint(0, 30)))
            want = []
            for m in credentials._PRIVATE_BLOCK.finditer(text):
                want.append((m.group(0), m.group(1), m.group(2), text.count("\n", 0, m.start()) + 1))
            got = [(b.group(0), *b.group(1, 2)) for b in credentials._block_matches(text)]
            self.assertEqual(got, [w[:3] for w in want], text)
            self.assertEqual([r[2] for r in credentials._private_blocks(text)], [w[3] for w in want])


class BruteForceAttribution(unittest.TestCase):
    """The SSH username is chosen by the remote client; the journal's authpriv
    facility is writable by any local user. Neither may pick the source."""

    def test_username_cannot_name_the_source_address(self):
        from jarvis.collectors.identity import bruteforce
        lines = [f"sshd[9]: Failed password for invalid user admin from 192.0.2.10 from 203.0.113.{i % 2} "
                 f"port 4{i:04d} ssh2" for i in range(bruteforce.SPIKE_ONE_SOURCE * 2)]
        titles = " ".join(f["title"] for f in bruteforce._linux(lines=lines))
        self.assertNotIn("192.0.2.10", titles)
        self.assertIn("203.0.113.0", titles)

    def test_sshd_formats_still_count(self):
        from jarvis.collectors.identity import bruteforce
        for line, ip, user in (
                ("sshd[9]: Failed password for root from 203.0.113.5 port 22 ssh2", "203.0.113.5", "root"),
                ("Failed password for invalid user bob from 2001:db8::1 port 22 ssh2", "2001:db8::1", "bob"),
                ("message repeated 2 times: [ Failed password for root from 203.0.113.5 port 22 ssh2]",
                 "203.0.113.5", "root"),
                ("sshd[9]: Invalid user oracle from 203.0.113.7 port 5000", "203.0.113.7", "oracle"),
                ("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
                 "rhost=203.0.113.8  user=root", "203.0.113.8", "root")):
            m = bruteforce._LINUX_FAIL.search(line)
            self.assertTrue(m, line)
            self.assertEqual(m.group("ip") or m.group("ip2") or m.group("ip3"), ip, line)
            self.assertEqual(m.group("user") or m.group("user2") or m.group("user3"), user, line)

    def test_journal_lines_from_unprivileged_writers_are_ignored(self):
        import json

        from jarvis.collectors.identity import bruteforce
        forged = "Failed password for x from 192.0.2.10 port 1 ssh2"
        out = "\n".join(json.dumps(e) for e in (
            {"_UID": "1000", "MESSAGE": forged},
            {"_UID": "0", "MESSAGE": "Failed password for root from 203.0.113.5 port 22 ssh2"},
            {"_UID": "0", "MESSAGE": list(b"Failed password for \xff from 203.0.113.6 port 22 ssh2")},
            {"MESSAGE": forged}, "not an object")) + "\nnot json"
        msgs = bruteforce._journal_messages(out)
        self.assertEqual(len(msgs), 2)
        self.assertNotIn(forged, msgs)
        self.assertIn("203.0.113.6", msgs[1])
        self.assertEqual(msgs.untrusted, 2)
        # Left out of the count, but stated, so an unprivileged sshd is not invisible.
        out = bruteforce._linux(lines=msgs)
        self.assertIn("ok", [f["severity"] for f in out])
        self.assertTrue(any("non-root" in f["title"] and f["severity"] == "low" for f in out))
        empty = bruteforce._linux(lines=bruteforce._journal_messages(json.dumps({"_UID": "0", "MESSAGE": "x"})))
        self.assertEqual([f["severity"] for f in empty], ["ok"])


if __name__ == "__main__":
    unittest.main()
