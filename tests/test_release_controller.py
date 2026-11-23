"""Release controller: content-addressed identity, one writer, no stale base.

Invariants (docs/architecture/EVIDENCE-FABRIC.md): P1 a release is its
files, not its path; P5 only one deploy runs and a candidate staged on base X
never replaces a newer live release Y; P6 no build source under a
world-writable directory.
"""

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from jarvis.platform.provenance import release as rel

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "deploy_root_runtime_rc", ROOT / "scripts" / "deploy_root_runtime.py")
deploy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(deploy)

A = "a" * 64
B = "b" * 64


def private_tmp():
    """A temp root no other account can write, whatever TMPDIR is: these
    tests assert that world-writable locations are refused (P6)."""
    base = os.path.expanduser("~/.cache/jarvis-tests")
    os.makedirs(base, mode=0o700, exist_ok=True)
    return base


class ReleaseIdentityTests(unittest.TestCase):
    def test_identity_depends_only_on_files(self):
        one = rel.release_id({"x.py": A, "y/z.py": B})
        self.assertEqual(one, rel.release_id({"y/z.py": B, "x.py": A}))
        self.assertTrue(one.startswith("sha256:"))
        self.assertNotEqual(one, rel.release_id({"x.py": B, "y/z.py": A}))
        self.assertNotEqual(one, rel.release_id({"x.py": A}))
        # A path boundary cannot be shifted into the digest.
        self.assertNotEqual(rel.release_id({"ab": A}), rel.release_id({"a": A, "b": A}))

    def test_manifest_location_fields_do_not_change_identity(self):
        files = {"x.py": A}
        m1 = {"source": "/home/u/.cache/stage-1", "checkout": "/home/u/jarvis", "files": files}
        m2 = {"source": "/somewhere/else", "built_at": 5, "files": files}
        self.assertEqual(rel.manifest_release_id(m1), rel.manifest_release_id(m2))

    def test_tampered_or_malformed_manifest_is_refused(self):
        with self.assertRaises(ValueError):
            rel.manifest_release_id({"files": {"x.py": A}, "release_id": "sha256:" + "0" * 64})
        for files in ({}, None, {"../x": A}, {"/abs": A}, {"x": "nothex" * 8}, {"x": A[:10]}):
            with self.assertRaises(ValueError):
                rel.release_id(files)

    def test_world_writable_ancestor(self):
        with tempfile.TemporaryDirectory(dir=private_tmp()) as tmp:
            private = os.path.join(tmp, "private", "stage")
            os.makedirs(private)
            os.chmod(os.path.join(tmp, "private"), 0o700)
            os.chmod(tmp, 0o700)
            self.assertEqual(rel.world_writable_ancestor(private), "")
            os.chmod(tmp, 0o1777)
            self.assertEqual(rel.world_writable_ancestor(private), os.path.realpath(tmp))
        self.assertEqual(rel.world_writable_ancestor("/tmp/x/y"), "/tmp")


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=private_tmp())
        self.addCleanup(self.tmp.cleanup)
        self.base = self.tmp.name

    def test_expected_base_must_be_the_live_release(self):
        live = {"files": {"x.py": A}}
        live_id = rel.release_id(live["files"])
        self.assertEqual(deploy.check_expected_base(live_id, live), live_id)
        self.assertEqual(deploy.check_expected_base(None, live), live_id)
        stale = rel.release_id({"x.py": B})
        with self.assertRaises(SystemExit) as ctx:
            deploy.check_expected_base(stale, live)
        self.assertIn("restage", str(ctx.exception))
        with self.assertRaises(SystemExit):
            deploy.check_expected_base(live_id, None)
        with self.assertRaises(SystemExit):
            deploy.check_expected_base(None, {"files": {"x.py": A},
                                              "release_id": stale})

    def test_second_deploy_is_refused_while_one_holds_the_lock(self):
        with deploy.DeployLock(self.base):
            with self.assertRaises(SystemExit) as ctx:
                with deploy.DeployLock(self.base):
                    pass
            self.assertIn("another deploy", str(ctx.exception))
        with deploy.DeployLock(self.base):     # released after the first exits
            pass

    def test_lock_is_released_when_a_deploy_fails(self):
        with self.assertRaises(RuntimeError):
            with deploy.DeployLock(self.base):
                raise RuntimeError("tests failed")
        with deploy.DeployLock(self.base):
            pass

    def test_source_under_world_writable_directory_is_refused(self):
        with self.assertRaises(SystemExit):
            deploy.check_source_location("/tmp/jarvis-netwatch-narrow-20260924")
        private = os.path.join(self.base, "stage")
        os.makedirs(private)
        os.chmod(self.base, 0o700)
        deploy.check_source_location(private)

    def test_install_record_round_trips_and_wins(self):
        self.assertIsNone(deploy.read_install(self.base))
        deploy.write_install(self.base, "/home/u/jarvis", owner=os.getuid())
        installed = deploy.read_install(self.base)
        self.assertEqual(installed["checkout"], "/home/u/jarvis")
        self.assertFalse(os.stat(os.path.join(self.base, deploy.INSTALL)).st_mode & 0o022)

    def test_deploy_provisions_the_key_where_the_daemon_reads_it(self):
        # 2026-09-24: a package move rewrote identity.KEY_DIR, so the deploy
        # created the key in /etc/jarvis/provenance while the daemon looked
        # elsewhere and logged "unavailable".
        from jarvis.platform.provenance import identity
        self.assertEqual(Path(deploy.PROVENANCE_KEYS), identity.KEY_DIR)
        self.assertEqual(str(identity.KEY_DIR), "/etc/jarvis/provenance")
        self.assertEqual(identity.STATE_DIR, Path(os.path.expanduser("~/.jarvis/provenance")))
        keys = os.path.join(self.base, "keys")
        deploy.ensure_provenance_key.__globals__["_own_module"]("identity").generate_keypair(
            keys, owner=os.getuid())
        self.assertEqual(sorted(os.listdir(keys)),
                         sorted([identity.PRIVATE_KEY.name, identity.PUBLIC_KEY.name]))
        self.assertIsNotNone(identity.load_private_key(Path(keys, identity.PRIVATE_KEY.name)))

    def test_build_records_identity_and_base(self):
        src = os.path.join(self.base, "src")
        os.makedirs(os.path.join(src, "jarvis", "cli"))
        os.makedirs(os.path.join(src, "jarvis", "platform"))
        for name in deploy.REQUIRED:
            Path(src, name).write_text("# x\n")
        for args in (["init", "-q"], ["add", "."], ["-c", "user.email=a@b", "-c",
                     "user.name=a", "commit", "-q", "-m", "x"]):
            subprocess.run(["git", "-C", src, *args], check=True, capture_output=True)
        out = io.BytesIO()
        deploy.pack(src, out)
        releases = os.path.join(self.base, "releases")
        os.makedirs(releases)
        base_id = rel.release_id({"old.py": A})
        path, manifest = deploy.build(out.getvalue(), releases, owner=os.getuid(),
                                      checkout="/home/u/jarvis", base_release_id=base_id)
        self.assertEqual(manifest["release_id"], rel.release_id(manifest["files"]))
        self.assertEqual(manifest["base_release_id"], base_id)
        self.assertIn(rel.short(manifest["release_id"]), os.path.basename(path))
        with open(os.path.join(path, "RELEASE.json")) as fh:
            on_disk = json.load(fh)
        self.assertEqual(rel.manifest_release_id(on_disk), manifest["release_id"])
        # The same tree built again has the same identity at a new path.
        out2 = io.BytesIO()
        deploy.pack(src, out2)
        path2, manifest2 = deploy.build(out2.getvalue(), releases, owner=os.getuid(),
                                        checkout="/elsewhere")
        self.assertNotEqual(path, path2)
        self.assertEqual(manifest2["release_id"], manifest["release_id"])


class StageTests(unittest.TestCase):
    """The unprivileged stager: sealed base + named reviewed files only."""

    def setUp(self):
        from jarvis.platform.provenance import stage
        self.stage = stage
        self.tmp = tempfile.TemporaryDirectory(dir=private_tmp())
        self.addCleanup(self.tmp.cleanup)
        os.chmod(self.tmp.name, 0o700)
        self.live = Path(self.tmp.name, "live")
        self.checkout = Path(self.tmp.name, "checkout")
        files = {"jarvis-release.py": "# launcher\n", "jarvis/cli/__init__.py": "",
                 "jarvis/platform/privilege.py": "", "jarvis/x.py": "X = 1\n",
                 "old.py": "gone\n"}
        for root in (self.live, self.checkout):
            for name, body in files.items():
                Path(root, name).parent.mkdir(parents=True, exist_ok=True)
                Path(root, name).write_text(body)
        Path(self.checkout, "jarvis/x.py").write_text("X = 2\n")
        Path(self.checkout, "jarvis/new.py").write_text("N = 1\n")
        Path(self.checkout, "jarvis/unreviewed.py").write_text("EVIL = 1\n")
        digests = {name: hashlib.sha256(body.encode()).hexdigest()
                   for name, body in files.items()}
        Path(self.live, "RELEASE.json").write_text(json.dumps({"files": digests}))
        self.base_id = rel.release_id(digests)
        self.staging = Path(self.tmp.name, "staging")

    def run_stage(self, files, removals=()):
        return self.stage.stage(files, removals, checkout=self.checkout, live=self.live,
                                staging=self.staging, name="s1")

    def test_stage_is_the_sealed_base_plus_named_files_only(self):
        info = self.run_stage(["jarvis/x.py", "jarvis/new.py"], ["old.py"])
        tree = Path(info["stage"])
        self.assertEqual(info["base_release_id"], self.base_id)
        self.assertEqual((info["changed"], info["added"], info["removed"]),
                         (["jarvis/x.py"], ["jarvis/new.py"], ["old.py"]))
        self.assertEqual((tree / "jarvis/x.py").read_text(), "X = 2\n")
        self.assertFalse((tree / "old.py").exists())
        self.assertFalse((tree / "jarvis/unreviewed.py").exists())
        self.assertIn("--expect-base", info["deploy"])
        self.assertEqual(info["deploy"][info["deploy"].index("--expect-base") + 1], self.base_id)
        # The root deploy can pack and build it, and it has a new identity.
        out = io.BytesIO()
        deploy.pack(str(tree), out)
        releases = Path(self.tmp.name, "releases")
        releases.mkdir()
        _, manifest = deploy.build(out.getvalue(), str(releases), owner=os.getuid(),
                                   checkout=str(self.checkout), base_release_id=self.base_id)
        self.assertNotEqual(manifest["release_id"], self.base_id)
        self.assertNotIn("jarvis/unreviewed.py", manifest["files"])

    def test_tampered_live_base_is_refused_and_leaves_nothing(self):
        Path(self.live, "jarvis/x.py").write_text("tampered\n")
        with self.assertRaises(self.stage.StageError):
            self.run_stage(["jarvis/new.py"])
        self.assertFalse(Path(self.staging, "s1").exists())

    def test_paths_are_confined(self):
        os.symlink("/etc/passwd", self.checkout / "link.py")
        for bad in (["../outside"], ["/etc/passwd"], ["RELEASE.json"], [".git/config"],
                    ["link.py"], ["missing.py"], []):
            with self.assertRaises(self.stage.StageError, msg=bad):
                self.run_stage(bad)
        with self.assertRaises(self.stage.StageError):
            self.run_stage([], ["not-in-release.py"])

    def test_world_writable_staging_is_refused(self):
        shared = Path(self.tmp.name, "shared")
        shared.mkdir()
        os.chmod(shared, 0o1777)
        with self.assertRaises(self.stage.StageError):
            self.stage.stage(["jarvis/x.py"], checkout=self.checkout, live=self.live,
                             staging=shared / "staging")


if __name__ == "__main__":
    unittest.main()
