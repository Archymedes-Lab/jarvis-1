"""Release signatures: one pinned releaser's key is required, and enough.

Uses throwaway ed25519 keys made for each test, never a real release key.
"""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
import signers  # noqa: E402

HAVE_SSH_KEYGEN = shutil.which("ssh-keygen") is not None


def make_key(folder, name):
    key = Path(folder) / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key)], check=True)
    pub = (Path(str(key) + ".pub")).read_text().split()
    return key, f"{pub[0]} {pub[1]}"


def sign(key, path, namespace=signers.NAMESPACE):
    subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", namespace, str(path)],
                   check=True, capture_output=True)


@unittest.skipUnless(HAVE_SSH_KEYGEN, "ssh-keygen is needed")
class Signatures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.alice_key, self.alice = make_key(self.dir, "alice")
        self.bob_key, self.bob = make_key(self.dir, "bob")
        self.mallory_key, self.mallory = make_key(self.dir, "mallory")
        self.sums = self.dir / "SHA256SUMS"
        self.sums.write_text("0" * 64 + "  argus-server-linux-x86_64.tar.gz\n")
        self.sig = self.dir / "SHA256SUMS.sig"
        self.allowed = (f'alice namespaces="argus-release" {self.alice}\n'
                        f'bob namespaces="argus-release" {self.bob}\n'
                        f'mallory namespaces="argus-release" {self.mallory}\n')
        self.pinned = {signers.fingerprint(self.alice), signers.fingerprint(self.bob)}

    def tearDown(self):
        self.tmp.cleanup()

    def verify(self, pinned=None, allowed=None):
        return signers.verify(self.sums, self.sig, self.allowed if allowed is None else allowed,
                              self.pinned if pinned is None else pinned)

    def test_any_one_pinned_releaser_is_enough(self):
        sign(self.alice_key, self.sums)
        self.assertEqual(self.verify()[0], "alice")
        self.sig.unlink()
        sign(self.bob_key, self.sums)
        self.assertEqual(self.verify()[0], "bob")

    def test_listed_but_not_pinned_key_is_refused(self):
        # A push can add a line to allowed_signers; it cannot pin the key.
        sign(self.mallory_key, self.sums)
        with self.assertRaisesRegex(signers.SignatureError, "not made by a pinned"):
            self.verify()

    def test_tampered_sums_are_refused(self):
        sign(self.alice_key, self.sums)
        self.sums.write_text("1" * 64 + "  argus-server-linux-x86_64.tar.gz\n")
        with self.assertRaisesRegex(signers.SignatureError, "does not verify"):
            self.verify()

    def test_other_namespace_is_refused(self):
        sign(self.alice_key, self.sums, namespace="git")
        with self.assertRaises(signers.SignatureError):
            self.verify()

    def test_missing_signature_and_no_pins_fail_closed(self):
        with self.assertRaisesRegex(signers.SignatureError, "missing"):
            self.verify()
        sign(self.alice_key, self.sums)
        with self.assertRaisesRegex(signers.SignatureError, "no pinned"):
            self.verify(pinned=set())

    def test_pinned_key_relabelled_in_the_file_keeps_its_owner_only_if_pinned(self):
        # Mallory's key under alice's name is still mallory's (unpinned) key.
        sign(self.mallory_key, self.sums)
        allowed = f'alice namespaces="argus-release" {self.mallory}\n'
        with self.assertRaises(signers.SignatureError):
            self.verify(allowed=allowed)

    def test_lines_without_the_namespace_do_not_count(self):
        sign(self.alice_key, self.sums)
        with self.assertRaises(signers.SignatureError):
            self.verify(allowed=f"alice {self.alice}\n")

    def test_pinned_parsing(self):
        fp = signers.fingerprint(self.alice)
        self.assertEqual(signers.pinned_from(f"chris={fp}, sonia=nothing"), {fp})


class RepositorySigners(unittest.TestCase):
    def test_every_listed_releaser_is_well_formed(self):
        entries = signers.parse_allowed(signers.ALLOWED.read_text())
        self.assertTrue(entries, "release/allowed_signers lists no releaser")
        for principal, ktype, _key in entries:
            self.assertRegex(principal, r"^[A-Za-z0-9-]+$")
            self.assertEqual(ktype, "ssh-ed25519")


class LauncherRefusesArbitraryModules(unittest.TestCase):
    def test_only_the_four_named_modules_run(self):
        sys.path.insert(0, str(ROOT / "release"))
        import launcher
        self.assertEqual(set(launcher.CHILD_MODULES), {
            "jarvis.service.collector_worker", "jarvis.collectors.host.fridaydefender", "jarvis.verify",
            "jarvis.core.rulepack"})
        r = subprocess.run([sys.executable, str(ROOT / "release" / "launcher.py"), "-m", "os"],
                           capture_output=True, text=True, env={"JARVIS_QUIET_SEAL": "1", "PATH": "/usr/bin:/bin"},
                           cwd=str(ROOT), timeout=60)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("-m runs only", r.stderr)


if __name__ == "__main__":
    unittest.main()
