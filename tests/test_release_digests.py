"""release/digests.py: a consuming job accepts exactly the files a build recorded."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
import digests  # noqa: E402

SCRIPT = str(ROOT / "release" / "digests.py")


class Digests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "out"
        self.dir.mkdir()
        (self.dir / "a.deb").write_bytes(b"package")
        (self.dir / "a-build.json").write_text("{}")
        self.out = Path(self.tmp.name) / "github_output"
        self.out.touch()

    def tearDown(self):
        self.tmp.cleanup()

    def recorded(self):
        with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(self.out), "GITHUB_RUN_ID": "42"}):
            digests.record(self.dir, "server")
        lines = dict(line.split("=", 1) for line in self.out.read_text().splitlines())
        return lines["server"], lines["server_key"]

    def verify(self, *blobs):
        return subprocess.run([sys.executable, SCRIPT, "verify", str(self.dir), *blobs],
                              capture_output=True, text=True)

    def test_exact_files_pass_and_the_key_names_run_and_content(self):
        blob, key = self.recorded()
        self.assertTrue(key.startswith("argus-release-42-server-"))
        r = self.verify(blob)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_changed_missing_and_extra_files_are_refused(self):
        blob, _ = self.recorded()
        (self.dir / "a.deb").write_bytes(b"swapped by another job")
        self.assertIn("digest differs", self.verify(blob).stdout)
        (self.dir / "a.deb").unlink()
        self.assertIn("a.deb: missing", self.verify(blob).stdout)
        (self.dir / "a.deb").write_bytes(b"package")
        (self.dir / "planted.exe").write_bytes(b"x")
        r = self.verify(blob)
        self.assertEqual(r.returncode, 1)
        self.assertIn("planted.exe: not produced by a recorded build", r.stdout)

    def test_two_builds_cannot_claim_the_same_file(self):
        blob, _ = self.recorded()
        r = self.verify(blob, blob)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("two builds claim the same file", r.stdout + r.stderr)

    def test_empty_records_and_links_are_refused(self):
        self.assertNotEqual(self.verify("").returncode, 0)
        os.symlink("/etc/hostname", self.dir / "link")
        with self.assertRaises(SystemExit):
            digests.digest_folder(self.dir)

    def test_a_different_content_gets_a_different_key(self):
        _, key1 = self.recorded()
        (self.dir / "a.deb").write_bytes(b"other")
        self.out.write_text("")
        _, key2 = self.recorded()
        self.assertNotEqual(key1, key2)
        self.assertEqual(json.loads(self.recorded()[0])["a.deb"], digests.digest_folder(self.dir)["a.deb"])


if __name__ == "__main__":
    unittest.main()
