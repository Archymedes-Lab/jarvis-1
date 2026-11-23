"""Root-owned release: packing, building, switching and the launcher seal.

Root-only steps (chown to 0, systemd) are exercised with the test user as
owner; the logic that decides what is shipped and what is refused is the
same code path.
"""

import importlib.util
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


deploy = _load("deploy_root_runtime", ROOT / "scripts" / "deploy_root_runtime.py")
launcher = _load("jarvis_release", ROOT / "jarvis-release.py")


class PackAndBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.src = os.path.join(self.tmp.name, "checkout")
        os.makedirs(os.path.join(self.src, "jarvis"))
        self.write("jarvis/__init__.py", "X = 1\n")
        for rel in deploy.REQUIRED:
            os.makedirs(os.path.dirname(os.path.join(self.src, rel)) or self.src, exist_ok=True)
            if rel != "jarvis/__init__.py":
                self.write(rel, "")
        self.write("tool.sh", "#!/bin/sh\n", mode=0o775)
        self.write(".gitignore", "ignored.txt\n")
        self.write("ignored.txt", "secret\n")
        secret = os.path.join(self.tmp.name, "outside-secret")
        with open(secret, "w") as fh:
            fh.write("root only\n")
        os.symlink(secret, os.path.join(self.src, "link-to-secret"))
        for args in (["init", "-q"], ["add", "."], ["-c", "user.email=a@b", "-c",
                     "user.name=a", "commit", "-q", "-m", "x"]):
            subprocess.run(["git", "-C", self.src, *args], check=True, capture_output=True)
        self.write("untracked.py", "Y = 2\n")
        self.releases = os.path.join(self.tmp.name, "releases")
        os.makedirs(self.releases)

    def write(self, rel, body, mode=0o664):
        path = os.path.join(self.src, rel)
        with open(path, "w") as fh:
            fh.write(body)
        os.chmod(path, mode)

    def packed(self):
        out = io.BytesIO()
        deploy.pack(self.src, out)
        return out.getvalue()

    def test_pack_ships_tracked_and_untracked_but_not_ignored_or_links(self):
        with tarfile.open(fileobj=io.BytesIO(self.packed())) as tar:
            names = set(tar.getnames())
        self.assertIn("jarvis/__init__.py", names)
        self.assertIn("untracked.py", names)
        self.assertNotIn("ignored.txt", names)
        self.assertNotIn("link-to-secret", names)

    def test_build_seals_modes_and_records_manifest(self):
        release, manifest = deploy.build(self.packed(), self.releases, owner=os.getuid())
        self.assertTrue(os.path.basename(release).endswith("-dirty"))
        self.assertTrue(manifest["dirty"])
        self.assertEqual(manifest["source"], self.src)
        self.assertEqual(manifest["checkout"], self.src)
        self.assertEqual(os.stat(os.path.join(release, "tool.sh")).st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(os.path.join(release, "untracked.py")).st_mode & 0o777, 0o644)
        with open(os.path.join(release, "RELEASE.json")) as fh:
            self.assertEqual(json.load(fh)["files"], manifest["files"])
        self.assertIn("jarvis/__init__.py", manifest["files"])
        self.assertTrue(os.path.isdir(os.path.join(release, "jarvis", "__pycache__")))
        for dirpath, dirnames, filenames in os.walk(release):
            for name in dirnames + filenames:
                mode = os.lstat(os.path.join(dirpath, name)).st_mode
                self.assertFalse(mode & 0o022, os.path.join(dirpath, name))

    def hostile(self, member):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w") as tar:
            meta = json.dumps({"source": "/x", "commit": "c" * 40, "dirty": False}).encode()
            info = tarfile.TarInfo(deploy.PACK_META)
            info.size = len(meta)
            tar.addfile(info, io.BytesIO(meta))
            tar.addfile(member, io.BytesIO(b"x" * member.size))
        return out.getvalue()

    def test_links_and_escaping_paths_are_refused_and_leave_nothing(self):
        link = tarfile.TarInfo("evil")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/shadow"
        escape = tarfile.TarInfo("../../escaped")
        escape.size = 1
        for member in (link, escape):
            with self.assertRaises((SystemExit, tarfile.FilterError)):
                deploy.build(self.hostile(member), self.releases, owner=os.getuid())
        self.assertEqual(os.listdir(self.releases), [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "escaped")))

    def test_switch_changes_and_prune_keep_the_live_release(self):
        base = self.tmp.name
        first, m1 = deploy.build(self.packed(), self.releases, owner=os.getuid())
        deploy.switch(base, first)
        self.assertEqual(deploy.current_manifest(base)["files"], m1["files"])
        self.write("jarvis/__init__.py", "X = 3\n")
        second = os.path.join(self.releases, "99990101T000000Z-new")
        release, m2 = deploy.build(self.packed(), self.releases, owner=os.getuid())
        os.rename(release, second)
        self.assertEqual(deploy.changes(m1, m2)["changed"], ["jarvis/__init__.py"])
        deploy.prune(base, keep=1)                 # would drop `first`, but it is live
        self.assertTrue(os.path.isdir(first))

    def test_dropin_pairs_capabilities_with_the_isolated_release(self):
        text = deploy.dropin_text("/opt/jarvis")
        self.assertIn("ExecStart=\n", text)
        self.assertIn("/usr/bin/python3 -I /opt/jarvis/current/jarvis-release.py serve", text)
        self.assertIn("AmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_SYSLOG", text)
        self.assertNotIn("SYS_ADMIN", text)


class LauncherTests(unittest.TestCase):
    def test_user_owned_tree_is_not_sealed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(launcher.sealed_problems(tmp))

    def test_unsealed_release_drops_capabilities_before_importing(self):
        calls = []
        with mock.patch.object(launcher, "sealed_problems", return_value=["writable"]), \
             mock.patch.object(launcher, "drop_capabilities", side_effect=lambda: calls.append(1)), \
             mock.patch.dict("sys.modules", {"jarvis.cli": mock.Mock(main=lambda: 0)}):
            self.assertEqual(launcher.main(), 0)
        self.assertEqual(calls, [1])

    def test_drop_capabilities_is_harmless_without_any(self):
        from jarvis.platform import privilege
        launcher.drop_capabilities()
        self.assertEqual(privilege.effective(), 0)


class SourceRootTests(unittest.TestCase):
    def test_release_manifest_names_the_checkout(self):
        from jarvis.core import paths
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "RELEASE.json"
            manifest.write_text(json.dumps({"source": "/home/u/jarvis"}))
            with mock.patch.object(paths, "RELEASE_MANIFEST", manifest):
                self.assertEqual(paths._source_root(), Path("/home/u/jarvis"))
            manifest.write_text("{bad")
            with mock.patch.object(paths, "RELEASE_MANIFEST", manifest):
                self.assertEqual(paths._source_root(), paths.REPO_ROOT)

    def test_checkout_wins_over_a_temporary_build_source(self):
        # A narrow release built from /tmp must still verify the tasks that
        # were installed from the real checkout.
        from jarvis.core import paths
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "RELEASE.json"
            manifest.write_text(json.dumps({"source": "/tmp/narrow",
                                            "checkout": "/home/u/jarvis"}))
            with mock.patch.object(paths, "RELEASE_MANIFEST", manifest):
                self.assertEqual(paths._source_root(), Path("/home/u/jarvis"))
            manifest.write_text(json.dumps({"source": "/tmp/narrow", "checkout": "rel"}))
            with mock.patch.object(paths, "RELEASE_MANIFEST", manifest):
                self.assertEqual(paths._source_root(), Path("/tmp/narrow"))

    def test_deploy_resolves_the_checkout_explicit_then_inherited_then_source(self):
        with tempfile.TemporaryDirectory() as checkout, \
                tempfile.TemporaryDirectory() as clone:
            self.assertEqual(deploy.resolve_checkout(checkout, None, clone), checkout)
            self.assertEqual(deploy.resolve_checkout(None, {"source": clone,
                                                            "checkout": checkout}, clone),
                             checkout)
            # The installation's recorded checkout beats the previous release's.
            self.assertEqual(deploy.resolve_checkout(None, {"checkout": clone}, clone,
                                                     {"checkout": checkout}), checkout)
            # A release from before "checkout" existed must not make the build
            # source the checkout: that guess turned JARVIS's own watchdog
            # tasks critical on 2026-09-24. Refuse unless it is a first install.
            with self.assertRaises(SystemExit):
                deploy.resolve_checkout(None, {"source": "/gone"}, clone)
            self.assertEqual(deploy.resolve_checkout(None, None, clone, None,
                                                     first_install=True), clone)
            with self.assertRaises(SystemExit):
                deploy.resolve_checkout(os.path.join(clone, "missing"), None, clone)


class ServiceCodeTests(unittest.TestCase):
    def test_isolated_root_owned_launcher_is_not_reported(self):
        from jarvis.collectors.persistence import backdoor
        props = {"ExecStart": "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I "
                              "/usr/lib/python3/dist-packages/x.py serve ; x }",
                 "WorkingDirectory": "/home/someone"}
        self.assertEqual([p for p in backdoor._unit_code_paths(props)
                          if backdoor._user_writable(p)], [])


class CoverageSealTests(unittest.TestCase):
    def test_capabilities_on_editable_code_is_a_high_visibility_finding(self):
        from jarvis.platform import privilege
        from jarvis.service import coverage
        with mock.patch.object(privilege, "missing", return_value=[]), \
             mock.patch.object(privilege.os, "geteuid", return_value=1000):
            titles = {f["title"]: f["severity"] for f in coverage.visibility()}
        # This checkout is user-owned, so holding capabilities here is unsafe.
        self.assertEqual(titles.get("privileged monitor runs editable code"), "high")
        self.assertNotIn("least-privilege visibility", titles)


if __name__ == "__main__":
    unittest.main()


class RequiredFilesTests(unittest.TestCase):
    def test_release_without_launcher_is_refused(self):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w") as tar:
            meta = json.dumps({"source": "/x", "commit": "c" * 40, "dirty": False}).encode()
            info = tarfile.TarInfo(deploy.PACK_META)
            info.size = len(meta)
            tar.addfile(info, io.BytesIO(meta))
        with tempfile.TemporaryDirectory() as releases:
            with self.assertRaises(SystemExit):
                deploy.build(out.getvalue(), releases, owner=os.getuid())
            self.assertEqual(os.listdir(releases), [])
