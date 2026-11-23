"""Argus self-protection (jarvis/collectors/host/selfguard.py): G1-G5 over a fake
filesystem root, with success and failure paths for each check."""

import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.collectors.host import selfguard
from jarvis.core import assurance, mechanisms


class FakeStore:
    def __init__(self):
        self.meta = {}

    def get_meta(self, key, default=None):
        return self.meta.get(key, default)

    def set_meta(self, key, value):
        self.meta[key] = value


def titles(findings):
    return [(f["severity"], f["title"]) for f in findings]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "fs"
        self.site = self.root / "usr/lib/python3/dist-packages"
        self.site.mkdir(parents=True)
        self.home = Path(self.tmp.name) / "home"
        self.home.mkdir()
        self.env = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        self.env.start()
        self.state_root = self.root / "state"
        self.state_root.mkdir(mode=0o700)
        os.chmod(self.state_root, 0o700)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()


class StartupHooks(Base):
    def run_hooks(self, learned):
        # system site dirs must be root-owned for no writability finding; the
        # test tree is not, so that check is exercised separately below.
        with mock.patch.object(selfguard, "_writable_by_others", return_value=False):
            return selfguard.hook_findings(learned, str(self.root))

    def test_first_run_learns_and_reports_inventory_only_as_low(self):
        (self.site / "distutils-precedence.pth").write_text("import os; x = 1\n")
        (self.site / "plain.pth").write_text("/opt/extra/path\n")       # a path line runs nothing
        out, learned, problems = self.run_hooks(None)
        self.assertEqual(titles(out), [("low", "1 Python startup hook(s) present at first observation")])
        self.assertEqual(list(learned), [str(self.site / "distutils-precedence.pth")])
        self.assertEqual(problems, [])

    def test_new_hook_is_high_whatever_its_name(self):
        _, learned, _ = self.run_hooks(None)
        # A name from the old toolchain allowlist does not help here.
        (self.site / "distutils-precedence.pth").write_text("import _distutils_hack; exec('x')\n")
        (self.site / "sitecustomize.py").write_text("print('hi')\n")
        out, _, _ = self.run_hooks(learned)
        self.assertEqual(sorted(titles(out)), [
            ("high", "Python startup hook added: distutils-precedence.pth"),
            ("high", "Python startup hook added: sitecustomize.py")])

    def test_changed_hook_reported_and_unchanged_hook_quiet(self):
        hook = self.site / "a.pth"
        hook.write_text("import a\n")
        _, learned, _ = self.run_hooks(None)
        out, learned2, _ = self.run_hooks(learned)
        self.assertEqual(out, [])
        hook.write_text("import a; import b\n")
        out, _, _ = self.run_hooks(learned2)
        self.assertEqual(titles(out), [("high", "Python startup hook changed: a.pth")])

    def test_package_record_lowers_but_never_hides(self):
        _, learned, _ = self.run_hooks(None)
        body = b"import pkg_shim\n"
        (self.site / "pkg.pth").write_bytes(body)
        digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
        rec = self.site / "pkg-1.0.dist-info"
        rec.mkdir()
        (rec / "RECORD").write_text(f"pkg.pth,sha256={digest},{len(body)}\n")
        out, _, _ = self.run_hooks(learned)
        self.assertEqual(titles(out), [("low", "Python startup hook added: pkg.pth")])
        self.assertIn("pkg-1.0", out[0]["detail"])

    def test_user_site_hook_is_medium_and_removal_low(self):
        user = self.root / "home-site"
        user.mkdir()
        with mock.patch.object(selfguard, "USER_SITE_GLOBS", (str(user.relative_to(self.root)),)):
            _, learned, _ = self.run_hooks(None)
            (user / "usercustomize.py").write_text("x = 1\n")
            out, learned, _ = self.run_hooks(learned)
            self.assertEqual(titles(out), [("medium", "Python startup hook added: usercustomize.py")])
            (user / "usercustomize.py").unlink()
            out, _, _ = self.run_hooks(learned)
            self.assertEqual(titles(out), [("low", "Python startup hook removed: usercustomize.py")])

    def test_writable_system_site_directory_is_an_invariant_break(self):
        out, _, _ = selfguard.hook_findings({}, str(self.root))     # tmp tree: not root-owned
        self.assertIn(("high", "system Python site directory writable by a non-root account"), titles(out))

    def test_unreadable_hook_is_not_observed_not_clean(self):
        hook = self.site / "x.pth"
        hook.write_text("import x\n")
        with mock.patch.object(selfguard, "_sha", return_value=(None, "Permission denied")):
            out, learned, problems = self.run_hooks({})
        self.assertEqual(learned, {})
        self.assertTrue(any("Permission denied" in p for p in problems))

    def test_hooks_are_read_never_imported(self):
        (self.site / "sitecustomize.py").write_text("raise SystemExit('executed')\n")
        (self.site / "evil.pth").write_text("import os; os._exit(9)\n")
        self.run_hooks(None)            # would exit the test run if executed


class OwnCode(Base):
    def make_release(self):
        rel = self.root / "opt/argus/current"
        (rel / "jarvis/core/__pycache__").mkdir(parents=True)
        files = {}
        for name, body in (("jarvis/core/a.py", b"A = 1\n"), ("jarvis/__init__.py", b"")):
            (rel / name).write_bytes(body)
            files[name] = hashlib.sha256(body).hexdigest()
        (rel / "jarvis/core/__pycache__/a.cpython-312.pyc").write_bytes(b"\x00")
        (rel / "RELEASE.json").write_text(json.dumps({"files": files}))
        return rel

    def check(self, rel):
        with mock.patch.object(selfguard, "_writable_by_others", return_value=False):
            return selfguard.code_findings(str(rel))

    def test_intact_release_is_quiet(self):
        out, problems = self.check(self.make_release())
        self.assertEqual((out, problems), ([], []))

    def test_edited_missing_and_planted_code(self):
        rel = self.make_release()
        (rel / "jarvis/core/a.py").write_bytes(b"A = 2\n")
        (rel / "jarvis/__init__.py").unlink()
        (rel / "jarvis/core/evil.py").write_text("x")
        (rel / "jarvis/core/__pycache__/evil.cpython-312.pyc").write_bytes(b"\x00")
        os.symlink("/etc/passwd", rel / "jarvis/link")
        out, _ = self.check(rel)
        self.assertEqual(sorted(titles(out)), [
            ("critical", "Argus code differs from its release manifest"),
            ("high", "Argus code missing from its release"),
            ("high", "unlisted code inside the Argus release")])
        planted = [f for f in out if f["title"].startswith("unlisted")][0]["detail"]
        for name in ("evil.py", "evil.cpython-312.pyc", "jarvis/link"):
            self.assertIn(name, planted)

    def test_writable_release_and_bad_manifest(self):
        rel = self.make_release()
        out, _ = selfguard.code_findings(str(rel))      # tmp tree is owned by this user
        self.assertIn(("high", "Argus release writable by a non-root account"), titles(out))
        (rel / "RELEASE.json").write_text("{")
        out, _ = self.check(rel)
        self.assertEqual(titles(out), [("high", "Argus release manifest unreadable or malformed")])

    def test_checkout_without_manifest_is_not_observed(self):
        out, problems = self.check(self.root)
        self.assertEqual(out, [])
        self.assertIn("development checkout", problems[0])


class Units(Base):
    def test_learn_then_edit_add_dropin_and_remove(self):
        units = self.root / "etc/systemd/system"
        units.mkdir(parents=True)
        (units / "argus.service").write_text("[Service]\nExecStart=/opt/argus/bin/argus-server\n")
        out, learned, _ = selfguard.unit_findings(None, str(self.root))
        self.assertEqual(out, [])
        self.assertEqual(len(learned), 1)
        (units / "argus.service").write_text("[Service]\nExecStart=/bin/true\n")
        (units / "argus.service.d").mkdir()
        (units / "argus.service.d/override.conf").write_text("[Service]\nExecStart=\n")
        out, learned2, _ = selfguard.unit_findings(learned, str(self.root))
        self.assertEqual(sorted(titles(out)), [("high", "Argus service unit added: override.conf"),
                                               ("high", "Argus service unit edited: argus.service")])
        self.assertIn("drop-in", [f for f in out if "override" in f["title"]][0]["detail"])
        (units / "argus.service").unlink()
        out, _, _ = selfguard.unit_findings(learned2, str(self.root))
        self.assertEqual(titles(out), [("high", "Argus service unit removed: argus.service")])


class StateDirectory(Base):
    def test_clean_private_state_is_quiet_even_with_group_writable_files_inside(self):
        (self.state_root / "seg").write_text("x")
        os.chmod(self.state_root / "seg", 0o664)        # measured live: 0664 inside a 0700 root
        out, problems = selfguard.state_findings(str(self.state_root))
        self.assertEqual((out, problems), ([], []))

    def test_exposed_root_symlink_out_and_foreign_owner(self):
        os.chmod(self.state_root, 0o777)
        (self.state_root / "db").write_text("x")
        os.chmod(self.state_root / "db", 0o666)
        os.symlink("/etc", self.state_root / "out")
        os.symlink(str(self.state_root / "db"), self.state_root / "inside")
        out, _ = selfguard.state_findings(str(self.state_root))
        got = titles(out)
        self.assertIn(("high", "Argus state writable by another account"), got)
        self.assertIn(("high", "link out of Argus's state directory"), got)
        self.assertNotIn("inside", [f for f in out if f["title"].startswith("link")][0]["detail"])
        out, _ = selfguard.state_findings(str(self.state_root), uid=os.geteuid() + 1)
        self.assertIn(("high", "Argus state written by another account"), titles(out))

    def test_missing_state_root_is_not_observed(self):
        out, problems = selfguard.state_findings(str(self.root / "nope"))
        self.assertEqual(out, [])
        self.assertIn("does not exist", problems[0])

    def test_entry_ceiling(self):
        for i in range(5):
            (self.state_root / f"f{i}").write_text("")
        with mock.patch.object(selfguard, "MAX_STATE_ENTRIES", 3):
            _, problems = selfguard.state_findings(str(self.state_root))
        self.assertTrue(any("over 3 entries" in p for p in problems))


class RulePackChannel(unittest.TestCase):
    def test_every_non_active_state_is_reported(self):
        self.assertEqual(selfguard.rule_findings({"status": "builtin"}, {}), [])
        self.assertEqual(selfguard.rule_findings({"status": "active"}, {}), [])
        for status, sev in (("missing", "high"), ("rollback", "high"), ("rejected", "high"),
                            ("expired", "medium"), ("no-signers", "medium")):
            with self.subTest(status):
                out = selfguard.rule_findings({"status": status, "problem": "p"}, {})
                self.assertEqual([f["severity"] for f in out], [sev])


class RuleFloor(Base):
    def test_floor_kept_twice_detects_a_reset_state_file(self):
        store = FakeStore()
        kw = dict(root=str(self.root), release_root=str(self.root), state_root=str(self.state_root),
                  suspended={})
        with mock.patch.object(selfguard, "_writable_by_others", return_value=False):
            selfguard.audit(store, rules={"status": "active", "version": 7}, **kw)
            out = selfguard.audit(store, rules={"status": "active", "version": 8}, **kw)
            self.assertNotIn("rule-pack acceptance record reset", [f["title"] for f in out])
            out = selfguard.audit(store, rules={"status": "builtin", "version": None}, **kw)
            self.assertIn(("high", "rule-pack acceptance record reset"), titles(out))
            # still reported on the next run: the recorded floor is not lowered
            out = selfguard.audit(store, rules={"status": "active", "version": 3}, **kw)
            self.assertIn(("high", "rule-pack acceptance record reset"), titles(out))
        self.assertEqual(json.loads(store.meta[selfguard.STATE_META])["rule_floor"], 8)


class Audit(Base):
    def test_end_to_end_learns_then_reports_and_survives_a_corrupt_state(self):
        store = FakeStore()
        kw = dict(root=str(self.root), release_root=str(self.root), state_root=str(self.state_root),
                  rules={"status": "builtin"}, suspended={})
        with mock.patch.object(selfguard, "_writable_by_others", return_value=False):
            first = selfguard.audit(store, **kw)
            self.assertEqual([f["title"] for f in first], ["Argus self-protection not fully observed"])
            (self.site / "sitecustomize.py").write_text("x = 1\n")
            second = selfguard.audit(store, **kw)
            self.assertIn(("high", "Python startup hook added: sitecustomize.py"), titles(second))
            store.meta[selfguard.STATE_META] = "not json"
            third = selfguard.audit(store, **kw)
        self.assertIn("could not be read", third[-1]["detail"])
        self.assertIn(("low", "1 Python startup hook(s) present at first observation"), titles(third))

    def test_rule_state_failure_is_a_visibility_problem_not_a_crash(self):
        store = FakeStore()
        with mock.patch("jarvis.core.rulepack.current", side_effect=RuntimeError("x")):
            out = selfguard.audit(store, root=str(self.root), release_root=str(self.root),
                                  state_root=str(self.state_root))
        self.assertIn("rule-pack state unreadable", out[-1]["detail"])


class Registered(unittest.TestCase):
    def test_declared_in_the_registry_and_conformant(self):
        c = mechanisms.BY_NAME["selfguard"]
        self.assertEqual((c.domain, c.area), ("linux", None))
        self.assertTrue(c.unscored)
        self.assertEqual([p for p in mechanisms.conformance() if "selfguard" in p], [])

    def test_assurance_claims_nothing_measured(self):
        report = assurance.report({"selfguard": {"status": "complete"}})
        for name in ("signed_detection_content", "self_tamper_evidence"):
            entry = report["capabilities"][name]
            self.assertEqual(entry["implementation"], "unverified")
            self.assertFalse(entry["validated_containment"])
            self.assertIsNone(entry["last_validation"])
            self.assertEqual(entry["live_telemetry"], "current")


if __name__ == "__main__":
    unittest.main()
