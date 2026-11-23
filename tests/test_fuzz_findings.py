"""Regression tests for the findings of the first fuzz pass (docs/security/FUZZ-FINDINGS-2026-11-04.md).

Each test names its finding id. Fixed findings must stay fixed; open findings are
expectedFailure (or skip) until their fix is reviewed, so the suite records the
gap without hiding it. Every input here is synthetic; nothing reads the user's
data, starts the daemon or runs a system tool other than in a temp directory.
"""

import io
import json
import lzma
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "release"))
import gate  # noqa: E402
import versioning  # noqa: E402

from jarvis.collectors.host import updates  # noqa: E402
from jarvis.collectors.identity import logins, sshwatch  # noqa: E402
from jarvis.collectors.telemetry.sysmon_linux import journal as sysmon_journal  # noqa: E402
from jarvis.platform import sysmon_records  # noqa: E402
from jarvis.web import clients  # noqa: E402
from tests.fuzz.targets import release_gate as rg  # noqa: E402
from tests.fuzz.targets.collectors import WINGET_HEAD, WINGET_ROWS, _row  # noqa: E402

POLICY = gate.load_policy()


class _Deadline:
    """Fail (not hang) when the body runs past `seconds`."""

    def __init__(self, seconds):
        self.seconds = seconds

    def _fire(self, *_a):
        raise AssertionError(f"did not finish within {self.seconds} s")

    def __enter__(self):
        self.old = signal.signal(signal.SIGALRM, self._fire)
        signal.setitimer(signal.ITIMER_REAL, self.seconds)

    def __exit__(self, *exc):
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self.old)
        return False


def _deb_rule():
    return next(r for r in POLICY["artifacts"] if r["name"] == "argus-server_*_amd64.deb")


def _check(name, data, rule):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / name
        p.write_bytes(data)
        return gate.check_artifact(p, rule, POLICY)


class ReleaseGateFindings(unittest.TestCase):
    def test_fz01_negative_ar_size_is_refused_not_a_hang(self):
        data = b"!<arch>\n" + b"d" + b"-60       " * 6
        with _Deadline(5):
            with self.assertRaises(ValueError):
                gate._ar_members(data)
            problems, _n = _check("argus-server_1_amd64.deb", data, _deb_rule())
        self.assertTrue(problems and "cannot be opened" in problems[0])

    def test_fz01_truncated_member_is_refused(self):
        data = rg.ar_bytes([("debian-binary", b"2.0\n")])[:-3]
        with self.assertRaises(ValueError):
            gate._ar_members(data)

    def test_fz02_second_data_tar_cannot_hide_the_first(self):
        """dpkg-deb unpacks the first data.tar; the gate kept only the last one."""
        allowed = "./usr/share/argus-server/bin/argus-server"
        hidden = lzma.compress(rg.tar_bytes({"./usr/share/argus-server/src/secret.py": b"x"}))
        clean = lzma.compress(rg.tar_bytes({allowed: rg.ELF}))
        control = lzma.compress(rg.tar_bytes({"./control": b"Package: argus\n"}))
        deb = rg.ar_bytes([("debian-binary", b"2.0\n"), ("control.tar.xz", control),
                           ("data.tar.xz", hidden), ("data.tar.xz", clean)])
        problems, _n = _check("argus-server_1_amd64.deb", deb, _deb_rule())
        self.assertTrue(problems, "a .deb with two data.tar members passed the gate")

    def test_fz01_a_normal_deb_still_opens(self):
        deb = rg.deb_bytes({"./usr/share/argus-server/bin/argus-server": rg.ELF})
        names = sorted(m.path for m in gate._deb_members(deb))
        self.assertIn("usr/share/argus-server/bin/argus-server", names)

    def test_fz11_denied_member_inside_a_nested_zip_is_refused(self):
        inner = rg.zip_bytes({"src/secret.py": b"print('x')  # /home/builder/project\n"})
        rule = {"name": "f.zip", "kind": "zip", "allow": ["app/**/*"], "executables": []}
        problems, _n = _check("f.zip", rg.zip_bytes({"app/lib/bundle.zip": inner}), rule)
        self.assertTrue(any("src/secret.py" in p for p in problems), problems)

    def test_fz12_binary_artifact_that_is_a_zip_is_refused(self):
        data = rg.zip_bytes({"src/secret.py": b"x"})
        problems, _n = _check("argus-desktop-windows-x64.exe", data, {"name": "x", "kind": "binary"})
        self.assertTrue(problems)

    def test_fz13_denied_names_follow_windows_name_equivalence(self):
        for path in ("app/Docs/readme.txt", "app/SRC/x.dll", "app/x.PY.", "app/Tests/a.dll"):
            self.assertTrue(gate.denied_path(path, POLICY), path)

    def _budget(self, limit):
        old = gate.MAX_TOTAL
        gate.MAX_TOTAL = limit
        self.addCleanup(setattr, gate, "MAX_TOTAL", old)

    def test_fz14_archive_members_have_an_aggregate_memory_budget(self):
        # The measured reproducer shape (zero-filled members of a small .tar.gz),
        # scaled so the budget is 3 MiB instead of 512 MiB.
        self._budget(3 * 1024 * 1024)
        member = bytes(1024 * 1024)
        names = {f"app/m{i}.bin": member for i in range(8)}
        tgz = io.BytesIO()
        import gzip
        with gzip.GzipFile(fileobj=tgz, mode="wb", mtime=0) as gz:
            gz.write(rg.tar_bytes(names))
        self.assertLess(len(tgz.getvalue()), 64 * 1024)
        for members in (gate._tar_members(tgz.getvalue()), gate._zip_members(rg.zip_bytes(names))):
            held = sum(len(m.data) for m in members)
            self.assertLessEqual(held, gate.MAX_TOTAL)
            self.assertEqual([m.kind for m in members].count("over-budget"), 5)
            self.assertEqual(len(members), 8, "every member is still listed")
        rule = {"name": "f.zip", "kind": "zip", "allow": ["app/**/*"], "executables": []}
        problems, _n = _check("f.zip", rg.zip_bytes(names), rule)
        self.assertTrue(any("over-budget" in p for p in problems), problems)

    def test_fz14_archive_within_budget_is_unchanged(self):
        self._budget(3 * 1024 * 1024)
        names = {f"app/m{i}.bin": bytes(1024 * 1024) for i in range(3)}
        members = gate._zip_members(rg.zip_bytes(names))
        self.assertEqual([m.kind for m in members], ["file"] * 3)
        self.assertEqual(sum(len(m.data) for m in members), 3 * 1024 * 1024)
        rule = {"name": "f.zip", "kind": "zip", "allow": ["app/**/*"], "executables": []}
        self.assertEqual(_check("f.zip", rg.zip_bytes(names), rule)[0], [])

    def test_fz14_nested_zip_budget_is_checked_before_reading(self):
        old = gate._NESTED_ZIP_BYTES
        gate._NESTED_ZIP_BYTES = 1024 * 1024
        self.addCleanup(setattr, gate, "_NESTED_ZIP_BYTES", old)
        inner = rg.zip_bytes({"a.bin": bytes(2 * 1024 * 1024)})
        read = []
        real = gate.zipfile.ZipFile.read
        def spy(zf, info, *a, **k):
            read.append(getattr(info, "file_size", None))
            return real(zf, info, *a, **k)
        from unittest import mock
        with mock.patch.object(gate.zipfile.ZipFile, "read", spy):
            problems = gate._check_nested_zips(inner, "outer", POLICY)
        self.assertIn("outer: nested archive exceeds read budget", problems)
        self.assertEqual(read, [], "an over-budget member was decompressed")


class VersioningFindings(unittest.TestCase):
    def test_fz05_tag_grammar_is_ascii_and_has_no_trailing_newline(self):
        for bad in ("v2026.11.04\n", "v2026.11.0\u0664", "v\uff12026.11.04", "v2026.11.04-1\n"):
            with self.assertRaises(versioning.VersionError, msg=repr(bad)):
                versioning.candidate_key(bad)
        with self.assertRaises(versioning.VersionError):
            versioning.live_key("2026.10.30\n")
        self.assertEqual(versioning.candidate_key("v2026.11.04-2"), (2026, 11, 4, 2))
        self.assertEqual(versioning.live_key("2026.10.29.1"), (2026, 10, 29, 1))


class LoginFindings(unittest.TestCase):
    IP = "198.51.100.7"

    def _failures(self, lines):
        return logins.evaluate([(1000.0, ln) for ln in lines], {}, {}, 1000.0)[2]

    def test_fz03_user_name_cannot_choose_the_failure_address(self):
        for user in ("bob from 203.0.113.9", "x from 10.0.0.1 port 22", "a from 10.0.0.1 port 1 ssh2"):
            fails = self._failures([f"Invalid user {user} from {self.IP} port 4242",
                                    f"Failed password for invalid user {user} from {self.IP} port 4242 ssh2"])
            self.assertEqual(sorted(fails), [self.IP], user)

    def test_fz03_real_sshd_failure_shapes_still_count(self):
        lines = [f"Failed password for root from {self.IP} port 22 ssh2",
                 f"Failed publickey for chris from {self.IP} port 22 ssh2: ED25519 SHA256:abc",
                 f"Invalid user admin from {self.IP} port 4242",
                 f"Invalid user  from {self.IP} port 4242 [preauth]",
                 f"Failed none for invalid user x from {self.IP} port 4242 ssh2"]
        self.assertEqual(self._failures(lines), {self.IP: [1000.0] * 5})

    def test_fz15_odd_journal_lines_do_not_lose_the_read(self):
        text = "\n".join(["0", "null", json.dumps({"MESSAGE": [70, 900, "x"], "_UID": "0"}),
                          json.dumps({"__REALTIME_TIMESTAMP": "1" * 400, "MESSAGE": "ok", "__CURSOR": "c",
                                      "_UID": "0"})])

        class P:
            stdout, returncode = io.StringIO(text), 0

            def communicate(self, timeout=None):
                return "", ""

            def kill(self):
                pass

        records, cursor, _problem = logins.read_journal(None, run=lambda *a, **k: P())
        self.assertEqual([m for _t, m in records], ["F", "ok"])
        self.assertEqual(cursor, "c")

    @staticmethod
    def _journal(*recs):
        text = "".join(json.dumps(r) + "\n" for r in recs)

        class P:
            stdout, returncode = io.StringIO(text), 0

            def communicate(self, timeout=None):
                return "", ""

            def kill(self):
                pass
        return lambda *a, **k: P()

    FORGED = {"__CURSOR": "s=1", "__REALTIME_TIMESTAMP": "1730000000000000", "_UID": "1000",
              "MESSAGE": "Accepted publickey for chris from 203.0.113.50 port 1 ssh2: ED25519 SHA256:evil"}
    REAL = {"__CURSOR": "s=2", "__REALTIME_TIMESTAMP": "1730000001000000", "_UID": "0",
            "MESSAGE": "Accepted publickey for chris from 192.0.2.7 port 2 ssh2: ED25519 SHA256:good"}

    def test_fz04_lines_written_by_a_non_root_process_are_not_evidence(self):
        records, cursor, _p = logins.read_journal(None, run=self._journal(self.FORGED))
        self.assertEqual(list(records), [])
        self.assertEqual(records.untrusted, 1)          # counted, not silently dropped
        self.assertEqual(cursor, "s=1")                 # the cursor still moves past it

    def test_fz04_a_record_with_no_uid_is_not_evidence(self):
        rec = {k: v for k, v in self.FORGED.items() if k != "_UID"}
        records, _c, _p = logins.read_journal(None, run=self._journal(rec))
        self.assertEqual((list(records), records.untrusted), ([], 1))

    def test_fz04_negative_control_root_records_still_count(self):
        records, cursor, _p = logins.read_journal(None, run=self._journal(self.FORGED, self.REAL))
        self.assertEqual([m for _t, m in records], [self.REAL["MESSAGE"]])
        self.assertEqual((records.untrusted, cursor), (1, "s=2"))

    def test_fz04_a_flood_of_forged_lines_is_bounded_and_still_reported(self):
        # Forgeries count toward the read bound: a flood is truncated (reported as
        # not fully observed), never read without limit, and the count survives.
        flood = [{**self.FORGED, "__CURSOR": f"s={n}"} for n in range(5)] + [self.REAL]
        records, cursor, problem = logins.read_journal(None, run=self._journal(*flood), max_lines=3)
        self.assertEqual((list(records), records.untrusted, cursor), ([], 3, "s=2"))
        self.assertIn("more than 3", problem)

    def test_fz04_forged_lines_cannot_pre_train_the_baseline_and_are_reported(self):
        from tests.test_argus_server_net import MetaStore
        store, now = MetaStore(), 1730000100.0
        reader = lambda c: logins.read_journal(c, run=self._journal(self.FORGED))  # noqa: E731
        out = logins.audit(store, now=now, reader=reader)
        state = json.loads(store.get_meta(logins.STATE_META))
        self.assertEqual(state.get("accounts"), {})     # nothing learned from the forgery
        titles = [f["title"] for f in out]
        self.assertIn("sshd journal records written by a non-root process", titles)
        self.assertFalse(any("chris" in t for t in titles))
        # Kept for a day like other login events: the next empty run still shows it.
        out = logins.audit(store, now=now + 60, reader=lambda c: (logins.Records(), c, ""))
        self.assertIn("sshd journal records written by a non-root process", [f["title"] for f in out])

    def test_fz04_negative_control_a_real_root_login_is_learned_and_nothing_is_flagged(self):
        from tests.test_argus_server_net import MetaStore
        store = MetaStore()
        out = logins.audit(store, now=1730000100.0,
                           reader=lambda c: logins.read_journal(c, run=self._journal(self.REAL)))
        state = json.loads(store.get_meta(logins.STATE_META))
        self.assertIn("SHA256:good", state["accounts"]["chris"]["keys"])
        self.assertEqual(out, [])


class SysmonLinuxFindings(unittest.TestCase):
    GOOD = ("<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name=\"Image\">/tmp/real</Data></EventData></Event>")

    def test_fz06_non_numeric_event_id_skips_that_record_only(self):
        bad = "<Event><System><EventID>1x</EventID></System></Event>"
        events = sysmon_journal._parse(bad + "\n" + self.GOOD)
        self.assertEqual([e.get("Image") for e in events], ["/tmp/real"])

    def test_fz16_huge_numeric_event_id_skips_that_record_only(self):
        # Found by the 2026-11-06 fuzz run: 5121 digits passed isdigit() and int() raised.
        bad = "<Event><System><EventID>" + "9" * 5121 + "</EventID></System></Event>"
        events = sysmon_journal._parse(bad + "\n" + self.GOOD)
        self.assertEqual([e.get("Image") for e in events], ["/tmp/real"])

    def test_fz06_unclosed_event_tags_are_linear(self):
        with _Deadline(5):
            t0 = time.perf_counter()
            self.assertEqual(sysmon_journal._parse("<Event " * 200_000 + self.GOOD), [])
            self.assertLess(time.perf_counter() - t0, 2.0)

    def test_fz06_same_spans_as_the_old_pattern(self):
        import re
        samples = [self.GOOD * 3, "<EventData>x</Event>" + self.GOOD, "<Event><Event>" + self.GOOD,
                   "a<Event>b</Event>c<Event x='1'>d</Event><Event", "<Events></Event>" + self.GOOD]
        for s in samples:
            self.assertEqual(list(sysmon_records._event_blobs(s)),
                             [m.group(0) for m in re.finditer(r"<Event\b.*?</Event>", s, re.S)], s)


class SshwatchFindings(unittest.TestCase):
    def _parse(self, text):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "etc/ssh").mkdir(parents=True)
            main = Path(root) / "etc/ssh/sshd_config"
            main.write_text(text)
            cfg, matches, _files, problems = sshwatch.parse_sshd_config(str(main), root=root)
            return cfg, matches, problems, sshwatch.policy_findings(cfg, matches, str(main))

    def test_fz07_subsystem_without_command_does_not_crash_the_audit(self):
        cfg, _m, problems, findings = self._parse(
            "Subsystem sftp\nSubsystem backdoor /tmp/x\nPasswordAuthentication yes\n")
        self.assertTrue(any("Subsystem without a command" in p for p in problems))
        titles = [f["title"] for f in findings]
        self.assertIn("SSH accepts passwords", titles)
        self.assertTrue(any("subsystem backdoor" in t for t in titles), titles)

    def test_fz07_nul_in_include_is_a_problem_not_a_crash(self):
        _cfg, _m, problems, _f = self._parse("Include /etc/ssh/a\x00b.d/*.conf\nPort 22\n")
        self.assertTrue(any("not a usable path" in p for p in problems))


class UpdatesFindings(unittest.TestCase):
    def test_fz08_display_name_cannot_hide_later_rows(self):
        for name in ("The following game", "Price cannot be determined", "require explicit targeting"):
            table = WINGET_HEAD + "\n".join([_row(name, "Odd.App", "1.0", "2.0")] +
                                            [_row(*r) for r in WINGET_ROWS]) + "\n4 upgrades available.\n"
            ids = {i["id"] for i in updates.parse_winget(table)}
            self.assertTrue({"Odd.App", "Git.Git", "Studio.PlainGame"} <= ids, (name, ids))

    def test_fz08_real_footers_still_end_the_table(self):
        table = (WINGET_HEAD + _row(*WINGET_ROWS[1]) + "\n1 upgrades available.\n\n"
                 "The following packages have an upgrade available, but require explicit targeting for upgrade:\n"
                 + WINGET_HEAD + _row(*WINGET_ROWS[2]) + "\n")
        self.assertEqual([i["id"] for i in updates.parse_winget(table)], ["Git.Git"])

    def test_fz10_brew_json_that_is_not_an_object_is_unreadable(self):
        for text in ("1", "[]", "null", '"x"'):
            self.assertIsNone(updates.parse_brew(text), text)
        rows = updates.parse_brew(json.dumps({"formulae": [{"name": "x", "installed_versions": 3}], "casks": 7}))
        self.assertEqual([(r["id"], r["installed"]) for r in rows], [("x", "3")])


class ClientTokenFindings(unittest.TestCase):
    def test_fz09_damaged_digest_is_a_mismatch_not_an_exception(self):
        class Store(dict):
            def get_meta(self, k, d=None):
                return self.get(k, d)

            def set_meta(self, k, v):
                self[k] = v

        store = Store()
        cid, token = clients.pair(store, "x", now=0)
        recs = json.loads(store[clients.META_KEY])
        recs[0]["sha256"] = "\u0236"
        store[clients.META_KEY] = json.dumps(recs)
        self.assertIsNone(clients.verify(store, token))


class HarnessSmoke(unittest.TestCase):
    def test_every_target_runs_its_seeds(self):
        """The harness itself: each target loads and its seeds run (findings may exist;
        crashes of the harness may not)."""
        from tests.fuzz import engine
        from tests.fuzz.targets import all_targets
        names = set()
        for t in all_targets():
            self.assertNotIn(t.name, names)
            names.add(t.name)
            res = engine.fuzz(t, budget_s=5, max_execs=len(t.seeds) + 3)
            self.assertGreater(res.executions, 0, t.name)
        self.assertGreaterEqual(len(names), 15)


if __name__ == "__main__":
    unittest.main()
