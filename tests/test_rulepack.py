"""Signed rule packs (jarvis/core/rulepack.py, docs/architecture/DETECTION-CONTENT.md).

Every key here is a throwaway ed25519 key made at test time in a temporary
directory; no real signing key is created or read.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from jarvis.collectors.telemetry import techniques
from jarvis.core import rulepack, sshsig
from jarvis.response import defense
from jarvis.response.actions import base

NOW = 1_800_000_000
HAVE_SSH = shutil.which("ssh-keygen") is not None


def fast_timer(patterns):
    return {p: 0.1 for p in patterns}


def rule(**over):
    r = {"id": "AR-0001", "tids": ["T1105"], "platform": "linux", "images": ["curl"],
         "pattern": r"\s-o\s+/dev/shm/", "severity": "medium",
         "title": "download written to shared memory",
         "sample": ["/usr/bin/curl", "curl -s https://x.test/a -o /dev/shm/a"],
         "benign": [["/usr/bin/curl", "curl -s https://x.test/a -o /tmp/a"]]}
    r.update(over)
    return r


def pack(version=1, rules=None, issued=NOW - 3600, expires=NOW + 7 * 86400, **over):
    p = {"schema": rulepack.SCHEMA, "version": version, "issued_at": issued,
         "expires_at": expires, "rules": [rule()] if rules is None else rules}
    p.update(over)
    return json.dumps(p).encode()


class Keys:
    """Throwaway signing keys and a signer for one test."""

    def __init__(self, tmp, name="tester"):
        self.dir = Path(tmp)
        self.key = self.dir / name
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(self.key)],
                       check=True, capture_output=True)
        t, k = (self.dir / f"{name}.pub").read_text().split()[:2]
        self.line = f"{name} {t} {k}"

    def sign(self, data, namespace=rulepack.NAMESPACE):
        f = self.dir / "payload"
        f.write_bytes(data)
        sig = self.dir / "payload.sig"
        if sig.exists():
            sig.unlink()
        subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(self.key), "-n", namespace, str(f)],
                       check=True, capture_output=True)
        return sig.read_text()


@unittest.skipUnless(HAVE_SSH, "ssh-keygen is not installed")
class SignatureChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.keys = Keys(self.tmp.name)
        self.other = Keys(self.tmp.name, "intruder")

    def tearDown(self):
        self.tmp.cleanup()

    def test_pinned_key_verifies(self):
        data = pack()
        who, fp = sshsig.verify(data, self.keys.sign(data), (self.keys.line,), rulepack.NAMESPACE)
        self.assertEqual(who, "tester")
        self.assertTrue(fp.startswith("SHA256:"))

    def test_release_namespace_signature_is_not_a_rules_signature(self):
        data = pack()
        with self.assertRaises(sshsig.SignatureError):
            sshsig.verify(data, self.keys.sign(data, "argus-release"), (self.keys.line,), rulepack.NAMESPACE)

    def test_unpinned_key_refused(self):
        data = pack()
        with self.assertRaises(sshsig.SignatureError):
            sshsig.verify(data, self.other.sign(data), (self.keys.line,), rulepack.NAMESPACE)

    def test_changed_bytes_refused(self):
        data = pack()
        sig = self.keys.sign(data)
        with self.assertRaises(sshsig.SignatureError):
            sshsig.verify(data.replace(b"medium", b"high  "), sig, (self.keys.line,), rulepack.NAMESPACE)

    def test_no_pins_malformed_signature_and_missing_tool_refused(self):
        data = pack()
        sig = self.keys.sign(data)
        with self.assertRaises(sshsig.SignatureError):
            sshsig.verify(data, sig, (), rulepack.NAMESPACE)
        with self.assertRaises(sshsig.SignatureError):
            sshsig.verify(data, "not a signature", (self.keys.line,), rulepack.NAMESPACE)
        with self.assertRaises(sshsig.SignatureError):
            sshsig.verify(data, sig, ("tester ssh-rsa AAAA",), rulepack.NAMESPACE)
        with mock.patch.object(sshsig.shutil, "which", return_value=None):
            with self.assertRaises(sshsig.SignatureError):
                sshsig.verify(data, sig, (self.keys.line,), rulepack.NAMESPACE)

    def test_the_shipped_program_pins_no_key_so_packs_cannot_load(self):
        # Owner decision pending (design doc, "Keys"): until then only built-in rules run.
        self.assertEqual(rulepack.PINNED_SIGNERS, ())
        data = pack()
        with self.assertRaises(rulepack.PackError):
            rulepack.verify(data, self.keys.sign(data), now=NOW, timer=fast_timer)


class Schema(unittest.TestCase):
    def test_valid_pack_parses(self):
        p = rulepack.parse(pack())
        self.assertEqual(p["version"], 1)
        self.assertEqual(p["rules"][0]["images"], ("curl",))

    def test_refusals(self):
        cases = {
            "unknown top key": pack(extra=1),
            "unknown rule key": pack(rules=[rule(run="rm -rf /")]),
            "duplicate key": pack()[:-1] + b', "version": 2}',
            "float": pack().replace(b'"version": 1', b'"version": 1.5'),
            "nan": pack().replace(b'"version": 1', b'"version": NaN'),
            "critical": pack(rules=[rule(severity="critical")]),
            "image-less": pack(rules=[rule(images=[])]),
            "bad tid": pack(rules=[rule(tids=["X1"])]),
            "bad image": pack(rules=[rule(images=["Curl.EXE"])]),
            "control char": pack(rules=[rule(title="a\x1b[2Jb")]),
            "schema": pack(schema="argus-rules/2"),
            "lifetime": pack(expires=NOW + 400 * 86400),
            "expires before issued": pack(expires=NOW - 7200),
            "version 0": pack(version=0),
            "repeat ids": pack(rules=[rule(), rule()]),
            "not utf-8": b"\xff\xfe",
            "oversize": b" " * (rulepack.MAX_PACK_BYTES + 1),
            "too many rules": pack(rules=[rule(id=f"AR-{i:04d}") for i in range(rulepack.MAX_RULES + 1)]),
        }
        for name, data in cases.items():
            with self.subTest(name), self.assertRaises(rulepack.PackError):
                rulepack.parse(data)


class SafeRegexSubset(unittest.TestCase):
    def test_accepts_the_shapes_rules_use(self):
        for p in (r"\s-o\s+/dev/shm/", r"(?<![\w.-])/etc/g?shadow(?![\w.-])",
                  r"\b(save|export)\s+hklm\\(sam|system)\b", r"-e\S*\s.*x", r"a{0,16}b"):
            with self.subTest(p):
                rulepack.check_pattern(p)

    def test_refuses_what_can_backtrack_without_bound(self):
        for p in (r"(a+)+$", r"(\w*)*x", r"(ab|cd)*e", r"(a)\1", r"(?(1)a|b)", r"(?>a+)b",
                  r".*.*.*x", r"(?<=a+)b", r"(?=.*x)y", "a" * (rulepack.MAX_PATTERN + 1), r"(unclosed"):
            with self.subTest(p), self.assertRaises(rulepack.PackError):
                rulepack.check_pattern(p)

    def test_timing_child_measures_a_safe_pattern(self):
        worst = rulepack.probe([r"\s-o\s+/dev/shm/"])
        self.assertLess(worst[r"\s-o\s+/dev/shm/"], rulepack.PROBE_LIMIT_MS)

    def test_a_pattern_inside_the_subset_that_still_backtracks_is_stopped_by_the_deadline(self):
        # Two unbounded repeats pass the static subset; measured 2026-10-30,
        # `.*.*x` takes over 10 s on a 4 KiB subject. The child is killed and
        # the pack refused; this process never runs the search.
        started = time.monotonic()
        with self.assertRaises(rulepack.PackError) as caught:
            rulepack.probe([r".*.*x"], deadline=3)
        self.assertIn("deadline", str(caught.exception))
        self.assertLess(time.monotonic() - started, 10)

    def test_the_child_refuses_patterns_outside_the_subset(self):
        with self.assertRaises(rulepack.PackError):
            rulepack.probe([r"(a+)+$"])

    def test_slow_rule_refused_by_timing(self):
        p = rulepack.parse(pack())
        with self.assertRaises(rulepack.PackError):
            rulepack.check_timing(p, lambda ps: {x: rulepack.PROBE_LIMIT_MS + 1 for x in ps})


@unittest.skipUnless(HAVE_SSH, "ssh-keygen is not installed")
class AcceptanceAndInstall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.keys = Keys(self.tmp.name)
        self.root = Path(self.tmp.name) / "rules"
        self.signers = (self.keys.line,)
        rulepack._CACHE.clear()

    def tearDown(self):
        rulepack._CACHE.clear()
        self.tmp.cleanup()

    def install(self, data, now=NOW):
        return rulepack.install(data, self.keys.sign(data), root=self.root, signers=self.signers,
                                now=now, timer=fast_timer)

    def load(self, now=NOW):
        return rulepack.load(self.root, signers=self.signers, now=now, timer=fast_timer)

    def test_nothing_installed_is_builtin(self):
        self.assertEqual(self.load()["status"], "builtin")

    def test_install_then_load_with_the_real_timing_child(self):
        data = pack()
        rulepack.install(data, self.keys.sign(data), root=self.root, signers=self.signers, now=NOW)
        got = rulepack.load(self.root, signers=self.signers, now=NOW)
        self.assertEqual(got["status"], "active")
        self.assertEqual(got["pack"]["signer"], "tester")
        self.assertEqual(oct(os.stat(self.root / rulepack.BUNDLE).st_mode & 0o777), "0o600")

    def test_freshness(self):
        with self.assertRaisesRegex(rulepack.PackError, "expired"):
            self.install(pack(), now=NOW + 8 * 86400)
        with self.assertRaisesRegex(rulepack.PackError, "future"):
            self.install(pack(issued=NOW + 3 * 86400, expires=NOW + 9 * 86400))

    def test_rollback_and_equivocation_refused_and_the_newer_pack_stays(self):
        self.install(pack(version=5))
        with self.assertRaisesRegex(rulepack.PackError, "rollback"):
            self.install(pack(version=4))
        with self.assertRaisesRegex(rulepack.PackError, "equivocation"):
            self.install(pack(version=5, rules=[rule(severity="high")]))
        got = self.load()
        self.assertEqual((got["status"], got["version"]), ("active", 5))
        self.install(pack(version=6))
        self.assertEqual(self.load()["version"], 6)

    def test_sample_and_benign_checks(self):
        with self.assertRaisesRegex(rulepack.PackError, "sample does not fire"):
            self.install(pack(rules=[rule(sample=["/usr/bin/curl", "curl -s https://x.test"])]))
        with self.assertRaisesRegex(rulepack.PackError, "benign sample fires"):
            self.install(pack(rules=[rule(benign=[["/usr/bin/curl", "curl -o /dev/shm/x"]])]))

    def test_a_refused_pack_changes_nothing(self):
        self.install(pack(version=2))
        before = (self.root / rulepack.BUNDLE).read_bytes()
        with self.assertRaises(rulepack.PackError):
            self.install(pack(version=3, rules=[rule(pattern=r"(a+)+")]))
        self.assertEqual((self.root / rulepack.BUNDLE).read_bytes(), before)

    def test_interrupted_install_leaves_the_old_bundle_whole(self):
        self.install(pack(version=2))
        before = (self.root / rulepack.BUNDLE).read_bytes()
        with mock.patch.object(rulepack.os, "replace", side_effect=OSError("power cut")):
            with self.assertRaises(OSError):
                self.install(pack(version=3))
        self.assertEqual((self.root / rulepack.BUNDLE).read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), [rulepack.BUNDLE, rulepack.STATE])
        self.assertEqual(self.load()["version"], 2)

    def test_tamper_states_are_named(self):
        self.install(pack(version=3))
        bundle = self.root / rulepack.BUNDLE
        good = bundle.read_text()
        # bytes changed on disk after acceptance
        b = json.loads(good)
        b["pack"] = rulepack.base64.b64encode(pack(version=3, rules=[rule(severity="high")])).decode()
        bundle.write_text(json.dumps(b))
        self.assertEqual(self.load()["status"], "rejected")
        # an older, validly signed pack put back
        old = pack(version=2)
        bundle.write_text(json.dumps({"format": rulepack.BUNDLE_FORMAT,
                                      "pack": rulepack.base64.b64encode(old).decode(),
                                      "sig": self.keys.sign(old)}))
        self.assertEqual(self.load()["status"], "rollback")
        # removed
        bundle.unlink()
        self.assertEqual(self.load()["status"], "missing")
        # garbage
        bundle.write_text("{")
        self.assertEqual(self.load()["status"], "rejected")
        # a program that pins no key
        bundle.write_text(good)
        self.assertEqual(rulepack.load(self.root, signers=(), now=NOW)["status"], "no-signers")
        # time passes
        self.assertEqual(self.load(now=NOW + 30 * 86400)["status"], "expired")

    def test_cache_rechecks_expiry_and_reverifies_on_change(self):
        self.install(pack(version=1))
        with mock.patch.object(rulepack, "load", wraps=rulepack.load) as spy:
            first = rulepack.current(self.root, signers=self.signers, now=NOW)
            rulepack.current(self.root, signers=self.signers, now=NOW + 1)
            self.assertEqual(spy.call_count, 1)
            later = rulepack.current(self.root, signers=self.signers, now=NOW + 8 * 86400)
        self.assertEqual(first["status"], "active")
        self.assertEqual(later["status"], "expired")
        self.assertIsNone(later["pack"])

    def test_hot_consumers_never_wait_for_verification(self):
        import threading
        t = int(time.time())          # the background refresh reads the real clock
        self.install(pack(version=1, issued=t - 3600, expires=t + 7 * 86400), now=t)
        gate = threading.Event()
        real = rulepack.load

        def slow_load(*a, **kw):
            gate.wait(10)
            return real(*a, **{**kw, "timer": fast_timer})

        with mock.patch.object(rulepack, "load", side_effect=slow_load):
            started = time.monotonic()
            got = rulepack.current(self.root, signers=self.signers, block=False)
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertEqual(got["status"], "builtin")          # pending: built-ins only
            self.assertIn("pending", got["problem"])
            gate.set()
            for _ in range(100):
                if not rulepack._PENDING:
                    break
                time.sleep(0.05)
        got = rulepack.current(self.root, signers=self.signers, block=False)
        self.assertEqual((got["status"], got["version"]), ("active", 1))
        # a changed bundle is re-verified in the background while the verified pack keeps serving
        self.install(pack(version=2, issued=t - 3600, expires=t + 7 * 86400), now=t)
        rulepack._CACHE[(str(self.root), self.signers)] = {
            "checked": 0, "stamp": None, "result": got}
        gate.clear()
        with mock.patch.object(rulepack, "load", side_effect=slow_load):
            during = rulepack.current(self.root, signers=self.signers, block=False)
            self.assertEqual(during["version"], 1)
            gate.set()
            for _ in range(100):
                if not rulepack._PENDING:
                    break
                time.sleep(0.05)
        self.assertEqual(rulepack.current(self.root, signers=self.signers, block=False)["version"], 2)


class ConsumerTechniques(unittest.TestCase):
    def setUp(self):
        techniques.PACK_SUSPENDED.clear()

    def tearDown(self):
        techniques.PACK_SUSPENDED.clear()

    def pack_rule(self, **over):
        r = rulepack.parse(pack(rules=[rule(**over)]))["rules"][0]
        return techniques.Rule(r["tids"], r["platform"], r["images"], r["pattern"], r["severity"],
                               r["title"], r["sample"], r["benign"], origin="rulepack:7:AR-0001")

    def test_pack_rules_add_to_builtins_never_replace_them(self):
        extra = (self.pack_rule(),)
        hits = techniques.match("/usr/bin/cat", "cat /etc/shadow", techniques.LINUX, extra=extra)
        self.assertTrue(hits and not hits[0][0].origin)
        hits = techniques.match("/usr/bin/curl", "curl -s https://x.test/a -o /dev/shm/a",
                                techniques.LINUX, extra=extra)
        self.assertEqual([h[0].origin for h in hits], ["rulepack:7:AR-0001"])
        self.assertIn("[rule pack AR-0001]", techniques.finding_title(hits[0][0]))
        self.assertEqual(techniques.match("/usr/bin/wget", "wget -O /dev/shm/a x", techniques.LINUX,
                                          extra=extra), [])

    def test_slow_pack_rule_is_suspended_and_reported_not_silently_kept(self):
        extra = (self.pack_rule(),)
        cmd = "curl -s https://x.test/a -o /dev/shm/a"
        with mock.patch.object(techniques, "PACK_SLOW_MS", -1.0):
            self.assertTrue(techniques.match("/usr/bin/curl", cmd, techniques.LINUX, extra=extra))
            self.assertIn("rulepack:7:AR-0001", techniques.PACK_SUSPENDED)
            self.assertEqual(techniques.match("/usr/bin/curl", cmd, techniques.LINUX, extra=extra), [])
        from jarvis.collectors.host import selfguard
        found = selfguard.rule_findings({"status": "active"}, dict(techniques.PACK_SUSPENDED))
        self.assertEqual(found[0]["title"], "rule-pack rules suspended for slow matching")

    def test_active_pack_is_read_through_the_cache_and_a_broken_one_yields_builtins(self):
        p = rulepack.parse(pack(version=9))
        with mock.patch.object(rulepack, "current", return_value={"status": "active", "pack": p}):
            rules = techniques.pack_rules()
        self.assertEqual(rules[0].origin, "rulepack:9:AR-0001")
        with mock.patch.object(rulepack, "current", side_effect=RuntimeError("boom")):
            self.assertEqual(techniques.pack_rules(), ())
            self.assertTrue(techniques.match("/usr/bin/cat", "cat /etc/shadow", techniques.LINUX))

    def test_default_install_has_no_pack_rules(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(rulepack, "DEFAULT_ROOT", Path(tmp)):
            rulepack._CACHE.clear()
            self.assertEqual(rulepack.current(Path(tmp))["status"], "builtin")
        rulepack._CACHE.clear()


class ContentIsNotAuthority(unittest.TestCase):
    def test_pack_findings_are_never_acted_on_unasked(self):
        action = mock.Mock(autonomy=base.AUTO, enable_flag="auto_x")
        action.match.return_value = {"pid": 4242}
        action.auto_eligible.return_value = True
        action.permitted.return_value = (True, "")   # Action.permitted: no owner rule forbids it
        conf = {"autonomous_defense": True, "auto_x": True}
        f = {"severity": "high", "title": "t", "category": "technique"}
        with mock.patch.object(base, "registry", return_value={"x": action}):
            self.assertEqual(defense.decide(f, "sysmon", conf, {})[0], defense.AUTO)
            self.assertEqual(defense.decide({**f, "origin": "rulepack"}, "sysmon", conf, {})[0],
                             defense.PROPOSE)


class Fetch(unittest.TestCase):
    def test_only_plain_https(self):
        for url in ("http://x.test/r", "https://u:p@x.test/r", "https://x.test/r?host=me", "file:///etc"):
            with self.subTest(url), self.assertRaises(rulepack.PackError):
                rulepack.fetch(url, opener=mock.Mock())

    def test_same_request_for_every_host_and_size_caps(self):
        seen = []

        class Resp:
            def __init__(self, body):
                self.body = body

            def read(self, n):
                return self.body[:n]

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def open_(req, timeout):
            seen.append((req.full_url, dict(req.header_items())))
            return Resp(b"{}" if req.full_url.endswith(".json") else b"sig")

        opener = mock.Mock(open=open_)
        data, sig = rulepack.fetch("https://rules.example.test/argus/", opener=opener)
        self.assertEqual((data, sig), (b"{}", "sig"))
        self.assertEqual([u for u, _ in seen], ["https://rules.example.test/argus/rules.json",
                                                 "https://rules.example.test/argus/rules.json.sig"])
        self.assertEqual(seen[0][1], {"User-agent": "argus-rules", "Accept": "*/*"})
        opener = mock.Mock(open=lambda req, timeout: Resp(b"x" * (rulepack.MAX_PACK_BYTES + 5)))
        with self.assertRaises(rulepack.PackError):
            rulepack.fetch("https://rules.example.test/", opener=opener)

    def test_redirect_to_http_refused(self):
        import urllib.request
        rulepack_fetch_handler = None
        captured = {}
        real = urllib.request.build_opener

        def spy(*handlers):
            captured["h"] = handlers[0]
            return mock.Mock(open=mock.Mock(side_effect=OSError("offline")))

        with mock.patch.object(urllib.request, "build_opener", spy):
            with self.assertRaises(rulepack.PackError):
                rulepack.fetch("https://rules.example.test/")
        rulepack_fetch_handler = captured["h"]
        with self.assertRaises(rulepack.PackError):
            rulepack_fetch_handler.redirect_request(None, None, 302, "", {}, "http://evil.test/rules.json")
        self.assertIs(urllib.request.build_opener, real)


if __name__ == "__main__":
    unittest.main()
