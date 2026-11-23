"""The signed host-bound-test attestation: what it accepts and what it refuses.

Throwaway keys and a throwaway git repository; never a real release key.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
import host_attest  # noqa: E402
import signers  # noqa: E402

HAVE = shutil.which("ssh-keygen") and shutil.which("git")
TESTS = ["test_a.A.test_one", "test_b.B.test_two"]


def run(cwd, *cmd):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def make_key(folder, name):
    key = Path(folder) / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key)], check=True)
    pub = Path(str(key) + ".pub").read_text().split()
    return key, f"{pub[0]} {pub[1]}"


def sign(key, path):
    Path(str(path) + ".sig").unlink(missing_ok=True)
    subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", signers.NAMESPACE, str(path)],
                   check=True, capture_output=True)


@unittest.skipUnless(HAVE, "ssh-keygen and git are needed")
class Attestation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.repo = self.dir / "repo"
        for d in ("tests", "jarvis", "release", "scripts/dev"):
            (self.repo / d).mkdir(parents=True)
        (self.repo / "jarvis/core.py").write_text("x = 1\n")
        self.write_list(TESTS)
        run(self.repo, "git", "init", "-q")
        run(self.repo, "git", "config", "user.email", "t@example.invalid")
        run(self.repo, "git", "config", "user.name", "t")
        run(self.repo, "git", "add", "-A")
        run(self.repo, "git", "commit", "-q", "-m", "base")
        self.alice_key, self.alice = make_key(self.dir, "alice")
        self.mallory_key, self.mallory = make_key(self.dir, "mallory")
        self.allowed = (f'alice namespaces="argus-release" {self.alice}\n'
                        f'mallory namespaces="argus-release" {self.mallory}\n')
        self.pinned = {signers.fingerprint(self.alice)}
        self.path = self.repo / host_attest.ATTEST

    def tearDown(self):
        self.tmp.cleanup()

    def write_list(self, ids):
        (self.repo / "tests/host-bound.txt").write_text("# header\n" + "".join(i + "\n" for i in ids))

    def attest(self, key=None, **override):
        rec = {"schema": 1, "environment": host_attest.ENVIRONMENT,
               "commit": run(self.repo, "git", "rev-parse", "HEAD"),
               "host_bound_sha256": host_attest.sha(self.repo),
               "result": {"environment": host_attest.ENVIRONMENT, "ran": len(TESTS), "failed": [],
                          "skipped": 0, "tests": TESTS}}
        for k, v in override.items():
            if k in rec:
                rec[k] = v
            else:
                rec["result"][k] = v
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")
        sign(key or self.alice_key, self.path)

    def check(self):
        return host_attest.check(self.repo, self.allowed, self.pinned)

    def test_a_valid_signed_attestation_passes(self):
        self.attest()
        self.assertEqual(self.check(), [])

    def test_attestation_files_themselves_do_not_count_as_changes(self):
        self.attest()
        run(self.repo, "git", "add", "-A")
        run(self.repo, "git", "commit", "-q", "-m", "add attestation")
        self.assertEqual(self.check(), [])

    def test_missing_unsigned_and_unpinned_are_refused(self):
        self.assertTrue(any("missing" in p for p in self.check()))
        self.attest()
        Path(str(self.path) + ".sig").unlink()
        self.assertTrue(any("signature" in p for p in self.check()))
        self.attest(key=self.mallory_key)  # listed in allowed_signers, never pinned
        self.assertTrue(any("signature" in p for p in self.check()))

    def test_tampering_after_signing_is_refused(self):
        self.attest()
        rec = json.loads(self.path.read_text())
        rec["result"]["failed"] = []
        rec["commit"] = "0" * 40
        self.path.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")
        self.assertTrue(any("does not verify" in p for p in self.check()))

    def test_failures_or_an_incomplete_run_are_refused(self):
        self.attest(failed=["test_a.A.test_one"])
        self.assertTrue(any("failures" in p for p in self.check()))
        self.attest(ran=1)
        self.assertTrue(any("incomplete" in p for p in self.check()))

    def test_wrong_environment_is_refused(self):
        self.attest(environment="ci-runner")
        self.assertTrue(any("environment" in p for p in self.check()))

    def test_a_changed_host_bound_list_needs_a_new_attestation(self):
        self.attest()
        self.write_list(TESTS + ["test_c.C.test_new"])
        self.assertTrue(any("exactly the tests" in p for p in self.check()))

    def test_code_changed_since_the_attested_commit_is_refused(self):
        self.attest()
        (self.repo / "jarvis/core.py").write_text("x = 2\n")
        run(self.repo, "git", "commit", "-qam", "change code")
        self.assertTrue(any("changed since the attested commit" in p for p in self.check()))

    def test_an_unknown_or_unrelated_commit_is_refused(self):
        self.attest(commit="1" * 40)
        self.assertTrue(any("not in this repository" in p for p in self.check()))
        run(self.repo, "git", "switch", "-q", "-c", "other")
        (self.repo / "jarvis/other.py").write_text("y = 1\n")
        run(self.repo, "git", "add", "-A")
        run(self.repo, "git", "commit", "-q", "-m", "other")
        other = run(self.repo, "git", "rev-parse", "HEAD")
        run(self.repo, "git", "switch", "-q", "-")
        self.attest(commit=other)
        self.assertTrue(any("not an ancestor" in p for p in self.check()))


if __name__ == "__main__":
    unittest.main()
