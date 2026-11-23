"""Releaser key lifecycle: a second releaser, a lost key, a revoked key, rotation.

The trust rule (release/signers.py) is that a key counts only if it is listed in
release/allowed_signers AND its fingerprint is pinned outside the repository.
These tests show what that means for each situation in docs/guides/RELEASER-KEYS.md.
Throwaway keys only.
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

HAVE = shutil.which("ssh-keygen") is not None


def make_key(folder, name):
    key = Path(folder) / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key)], check=True)
    pub = Path(str(key) + ".pub").read_text().split()
    return key, f"{pub[0]} {pub[1]}"


def sign(key, path):
    Path(str(path) + ".sig").unlink(missing_ok=True)
    subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", signers.NAMESPACE, str(path)],
                   check=True, capture_output=True)


def line(name, pub):
    return f'{name} namespaces="argus-release" {pub}\n'


@unittest.skipUnless(HAVE, "ssh-keygen is needed")
class KeyLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.alice_key, self.alice = make_key(d, "alice")
        self.bob_key, self.bob = make_key(d, "bob")
        self.eve_key, self.eve = make_key(d, "eve")
        self.sums = d / "SHA256SUMS"
        self.sums.write_text("0" * 64 + "  argus.tar.gz\n")
        self.sig = d / "SHA256SUMS.sig"
        self.fp = {n: signers.fingerprint(k) for n, k in (("alice", self.alice), ("bob", self.bob), ("eve", self.eve))}

    def tearDown(self):
        self.tmp.cleanup()

    def verify(self, allowed, pinned):
        return signers.verify(self.sums, self.sig, allowed, set(pinned))

    def test_second_releaser_works_only_once_listed_and_pinned(self):
        listed = line("alice", self.alice) + line("bob", self.bob)
        sign(self.bob_key, self.sums)
        with self.assertRaises(signers.SignatureError):      # listed, not yet pinned
            self.verify(listed, [self.fp["alice"]])
        self.assertEqual(self.verify(listed, [self.fp["alice"], self.fp["bob"]])[0], "bob")

    def test_losing_one_key_does_not_disable_the_other_releaser(self):
        # Alice's key is lost: nobody can sign as her, but Bob still can, and nothing is relaxed.
        listed = line("alice", self.alice) + line("bob", self.bob)
        pinned = [self.fp["alice"], self.fp["bob"]]
        sign(self.bob_key, self.sums)
        self.assertEqual(self.verify(listed, pinned)[0], "bob")
        sign(self.eve_key, self.sums)                          # an unlisted, unpinned stranger still fails
        with self.assertRaises(signers.SignatureError):
            self.verify(listed, pinned)

    def test_revoking_a_key_rejects_everything_it_signed(self):
        listed = line("alice", self.alice) + line("bob", self.bob)
        sign(self.alice_key, self.sums)
        self.assertEqual(self.verify(listed, [self.fp["alice"], self.fp["bob"]])[0], "alice")
        # Revoke: drop the pin (the variable is admin-only). Her old signature stops counting at once,
        # even though her line is still in the file, so a release she signed must be re-signed.
        with self.assertRaises(signers.SignatureError):
            self.verify(listed, [self.fp["bob"]])

    def test_removing_every_pin_fails_closed(self):
        sign(self.alice_key, self.sums)
        with self.assertRaisesRegex(signers.SignatureError, "no pinned"):
            self.verify(line("alice", self.alice), [])

    def test_a_replacement_key_pushed_to_the_repository_is_not_trusted(self):
        # A compromised push adds Eve to allowed_signers and signs with her key.
        listed = line("alice", self.alice) + line("eve", self.eve)
        sign(self.eve_key, self.sums)
        with self.assertRaisesRegex(signers.SignatureError, "not made by a pinned"):
            self.verify(listed, [self.fp["alice"]])

    def test_rotation_is_pin_new_then_unpin_old(self):
        listed = line("alice", self.alice) + line("alice2", self.bob)   # bob's key is alice's new key
        sign(self.bob_key, self.sums)
        with self.assertRaises(signers.SignatureError):
            self.verify(listed, [self.fp["alice"]])                      # before the admin pins the new key
        self.assertEqual(self.verify(listed, [self.fp["alice"], self.fp["bob"]])[0], "alice2")
        self.assertEqual(self.verify(listed, [self.fp["bob"]])[0], "alice2")   # old key unpinned afterwards
        sign(self.alice_key, self.sums)
        with self.assertRaises(signers.SignatureError):
            self.verify(listed, [self.fp["bob"]])                        # the old key no longer signs

    def test_listing_one_key_under_two_names_adds_no_authority(self):
        listed = line("alice", self.alice) + line("alias", self.alice)
        sign(self.alice_key, self.sums)
        self.assertIn(self.verify(listed, [self.fp["alice"]])[0], {"alice", "alias"})
        with self.assertRaises(signers.SignatureError):                # unpinning the key removes both names
            self.verify(listed, [self.fp["bob"]])


if __name__ == "__main__":
    unittest.main()
