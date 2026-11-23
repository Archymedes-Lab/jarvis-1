"""Positive control of the Linux process sensor and the trusted journal origin."""

import json
import os
import sqlite3
import stat
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

from jarvis.collectors.telemetry import sensorprobe
from jarvis.collectors.telemetry.sysmon_linux import history, journal
from jarvis.platform import proclinux

PROG = "/opt/probe-test/true"  # does not exist: realpath is itself


class Store:
    def __init__(self):
        self.meta = {}
        self.db = sqlite3.connect(":memory:")
        history.ensure(self.db)

    def ingest(self, image, at, cursor):
        """What a sysmon_linux pass leaves behind: a start row and its cursor."""
        self.db.execute("INSERT INTO start_images(host, image, sha256, name, first_seen, last_seen) "
                        "VALUES('wsl', ?, '', 'true', ?, ?) ON CONFLICT(host, image, sha256) DO "
                        "UPDATE SET last_seen=max(last_seen, excluded.last_seen)", (image, at, at))
        self.meta[sensorprobe.CURSOR_KEY] = cursor

    def get_meta(self, key, default=None):
        return self.meta.get(key, default)

    def set_meta(self, key, value):
        self.meta[key] = value

    def state(self):
        return json.loads(self.meta[sensorprobe.META])


def event(label, image=PROG, eid=1, cmd=None):
    cmd = f"{image} {label}" if cmd is None else cmd
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<EventID>{eid}</EventID><TimeCreated SystemTime="2026-11-01T10:00:00.000Z"/>'
            f'</System><EventData><Data Name="Image">{image}</Data>'
            f'<Data Name="CommandLine">{cmd}</Data></EventData></Event>\n')


class Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


class Harness:
    """Drives run() with a fake sensor that answers (or not) per probe."""

    def __init__(self, answer=True, active=True, program=PROG, spawn_error="", forge=None):
        self.store, self.clock = Store(), Clock()
        self.answer, self.is_active, self.prog = answer, active, program
        self.spawn_error, self.forge = spawn_error, forge
        self.labels, self.reads, self.journal = [], [], ""

    def start(self, path, label):
        self.labels.append(label)
        if not self.spawn_error and self.answer:
            self.journal += event(label)
        return self.spawn_error

    def reader(self, since, until=None):
        self.reads.append((since, until))
        text = self.journal
        if self.forge:
            text += self.forge(self.labels[-1]) if self.labels else ""
        return text

    def run(self, now=1_000_000):
        return sensorprobe.run(self.store, now=now, active=lambda: self.is_active,
                               find_program=lambda: self.prog, start=self.start,
                               reader=self.reader, clock=self.clock, sleep=self.clock.sleep)


def titles(findings):
    return [(f["severity"], f["title"]) for f in findings]


class SeenPath(unittest.TestCase):
    def test_a_probe_that_arrives_is_ok_with_its_latency_kept(self):
        h = Harness()
        out = h.run()
        self.assertEqual([f["severity"] for f in out], ["ok"])
        self.assertIn("answered its positive control", out[0]["title"])
        st = h.store.state()
        self.assertEqual(st["history"][-1]["outcome"], "seen")
        self.assertIsInstance(st["history"][-1]["latency_ms"], int)
        self.assertNotIn("pending", st)

    def test_label_is_random_prefixed_and_never_given_to_the_reader(self):
        h = Harness()
        h.run()
        h.run()
        self.assertEqual(len(set(h.labels)), 2)
        self.assertTrue(all(lb.startswith(sensorprobe.PREFIX) and len(lb) == len(sensorprobe.PREFIX) + 16
                            for lb in h.labels))
        for args in h.reads:
            self.assertTrue(all(a is None or isinstance(a, int) for a in args), args)


class NoFalseSighting(unittest.TestCase):
    def assertNotSeen(self, forge):
        h = Harness(answer=False, forge=forge)
        out = h.run()
        self.assertNotIn("ok", [f["severity"] for f in out], forge)
        self.assertIn("pending", h.store.state())

    def test_the_checker_or_another_program_carrying_the_label(self):
        self.assertNotSeen(lambda lb: event(lb, image="/usr/bin/journalctl"))

    def test_label_only_as_part_of_another_argument(self):
        self.assertNotSeen(lambda lb: event(lb, cmd=f"{PROG} x{lb}y"))

    def test_other_event_types(self):
        self.assertNotSeen(lambda lb: event(lb, eid=5))

    def test_a_plain_text_line_with_the_label(self):
        self.assertNotSeen(lambda lb: f"{lb}\n")

    def test_an_old_label_does_not_answer_a_new_probe(self):
        h = Harness()
        h.run()
        old = h.labels[-1]
        h.answer = False
        h.forge = lambda _lb: event(old)
        self.assertNotIn("ok", [f["severity"] for f in h.run()])


class MissLateBlind(unittest.TestCase):
    def test_wait_is_bounded_by_the_monotonic_clock(self):
        h = Harness(answer=False)
        out = h.run()
        self.assertEqual(titles(out)[0][0], "low")
        self.assertLessEqual(len(h.reads), sensorprobe.WAIT_S / sensorprobe.POLL_S + 2)

    def test_a_probe_seen_on_the_next_run_is_late_not_missed(self):
        h = Harness(answer=False)
        h.run(now=1_000_000)
        late_label = h.labels[-1]
        h.answer = True
        h.journal += event(late_label)          # arrived after the wait
        out = h.run(now=1_000_900)
        self.assertIn(("low", "Sysmon for Linux answered its positive control late"), titles(out))
        self.assertIn("ok", [f["severity"] for f in out])
        st = h.store.state()
        self.assertEqual([x["outcome"] for x in st["history"]], ["late", "seen"])
        self.assertEqual(st["misses"], 0)
        # the late check reads a bounded window around the probe
        self.assertIn((1_000_000 - sensorprobe.SKEW_S, 1_000_000 + sensorprobe.LATE_S), h.reads)

    def test_misses_escalate_to_blind_and_recovery_clears_it(self):
        h = Harness(answer=False)
        sev = [max((f["severity"] for f in h.run(now=1_000_000 + 900 * i)),
                   key=lambda s: -["critical", "high", "medium", "low", "ok"].index(s))
               for i in range(3)]
        self.assertEqual(sev, ["low", "medium", "high"])
        self.assertEqual(h.store.state()["misses"], 2)
        h.answer = True
        out = h.run(now=1_000_000 + 2700)
        got = titles(out)
        self.assertFalse([t for s, t in got if s == "high"], got)
        self.assertIn("medium", [s for s, _ in got])
        self.assertIn("ok", [s for s, _ in got])
        self.assertEqual(h.store.state()["misses"], 0)

    def test_history_is_bounded(self):
        h = Harness()
        for i in range(sensorprobe.HISTORY + 10):
            h.run(now=1_000_000 + i)
        self.assertEqual(len(h.store.state()["history"]), sensorprobe.HISTORY)

    def test_corrupt_state_starts_fresh(self):
        h = Harness()
        h.store.meta[sensorprobe.META] = "[1, 2"
        self.assertEqual(h.run()[0]["severity"], "ok")


class CollectorPipeline(unittest.TestCase):
    def test_collector_that_ingested_the_probe_raises_nothing(self):
        h = Harness()
        h.run(now=1_000_000)
        h.store.ingest(PROG, 1_000_000, cursor=1_000_600)
        out = h.run(now=1_000_900)
        self.assertEqual([f["severity"] for f in out], ["ok"])
        self.assertEqual(h.store.state()["pipeline_last"], "ingested")

    def test_cursor_past_the_probe_without_its_start_is_a_lost_event(self):
        h = Harness()
        h.run(now=1_000_000)
        h.store.ingest(PROG, 999_000, cursor=1_000_600)   # only an older start recorded
        out = h.run(now=1_000_900)
        self.assertIn("high", [f["severity"] for f in out])
        self.assertIn("never ingested", " ".join(f["title"] for f in out))

    def test_a_cursor_that_never_moves_is_reported_after_the_waits(self):
        h = Harness()
        h.store.meta[sensorprobe.CURSOR_KEY] = 999_999      # behind every probe
        runs = [[f["title"] for f in h.run(now=1_000_000 + 900 * i)]
                for i in range(sensorprobe.PIPELINE_MAX_WAITS + 1)]
        said = ["has not read past" in " ".join(r) for r in runs]
        self.assertEqual(said, [False] * sensorprobe.PIPELINE_MAX_WAITS + [True], runs)

    def test_a_newer_probe_does_not_replace_the_unverified_one(self):
        h = Harness()
        h.store.meta[sensorprobe.CURSOR_KEY] = 999_999
        h.run(now=1_000_000)
        h.run(now=1_000_900)
        self.assertEqual(h.store.state()["pipeline"]["t"], 1_000_000)

    def test_no_cursor_or_no_history_is_unknown_not_lost(self):
        st = Store()
        self.assertEqual(sensorprobe.pipeline(st, PROG, 10), "unknown")
        st.meta[sensorprobe.CURSOR_KEY] = 20
        st.db = None
        self.assertEqual(sensorprobe.pipeline(st, PROG, 10), "unknown")


class NothingProvedIsNeverOk(unittest.TestCase):
    def test_stopped_sensor_is_skipped_without_a_probe(self):
        h = Harness(active=False)
        out = h.run()
        self.assertEqual([f["severity"] for f in out], ["low"])
        self.assertIn("skipped", out[0]["title"])
        self.assertEqual(h.labels, [])

    def test_no_safe_program(self):
        h = Harness(program=None)
        out = h.run()
        self.assertEqual(out[0]["severity"], "low")
        self.assertEqual(h.labels, [])

    def test_spawn_failure(self):
        h = Harness(spawn_error="PermissionError")
        out = h.run()
        self.assertEqual(out[0]["severity"], "low")
        self.assertNotIn("pending", h.store.state())


class ProbeProgram(unittest.TestCase):
    @staticmethod
    def st(mode, uid=0):
        return SimpleNamespace(st_mode=mode, st_uid=uid)

    def test_only_a_root_owned_regular_file_nobody_else_can_write(self):
        cases = {"/a": self.st(stat.S_IFREG | 0o755),
                 "/w": self.st(stat.S_IFREG | 0o777),
                 "/g": self.st(stat.S_IFREG | 0o775),
                 "/u": self.st(stat.S_IFREG | 0o755, uid=1000),
                 "/d": self.st(stat.S_IFDIR | 0o755)}

        def fake(path):
            if path not in cases:
                raise FileNotFoundError(path)
            return cases[path]
        self.assertEqual(sensorprobe.program(("/missing", "/w", "/g", "/u", "/d", "/a"), fake), "/a")
        self.assertIsNone(sensorprobe.program(("/w", "/u", "/d"), fake))

    def test_spawn_has_no_shell_and_an_empty_environment(self):
        with mock.patch.object(sensorprobe.subprocess, "run") as run:
            self.assertEqual(sensorprobe.spawn("/usr/bin/true", "argus-probe-x"), "")
        args, kw = run.call_args
        self.assertEqual(args[0], ["/usr/bin/true", "argus-probe-x"])
        self.assertEqual(kw["env"], {})
        self.assertFalse(kw.get("shell", False))
        self.assertEqual(kw["timeout"], sensorprobe.SPAWN_TIMEOUT_S)

    def test_spawn_reports_errors_by_type(self):
        with mock.patch.object(sensorprobe.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("x", 5)):
            self.assertEqual(sensorprobe.spawn("/usr/bin/true", "l"), "TimeoutExpired")


class TrustedJournalOrigin(unittest.TestCase):
    def test_reader_and_live_feed_use_the_same_trusted_match(self):
        self.assertEqual(journal.TRUSTED_MATCH, proclinux.SYSMON_TRUSTED_MATCH)
        self.assertIn("_UID=0", journal.TRUSTED_MATCH)
        self.assertIn("_SYSTEMD_UNIT=sysmon.service", journal.TRUSTED_MATCH)

    # The collector reads through journal.read_since (cursor moves only after a
    # good read); `run` and `syslog` are its injection points.
    @staticmethod
    def _run(stdout, rc, seen=None):
        def run(cmd, **kw):
            if seen is not None:
                seen.append(cmd)
            return subprocess.CompletedProcess(cmd, rc, stdout, "")
        return run

    def test_collector_reader_queries_trusted_records(self):
        seen = []
        text, ok, _ = journal.read_since(5, run=self._run("x", 0, seen),
                                         syslog=lambda: self.fail("syslog read"))
        self.assertEqual((text, ok), ("x", True))
        cmd = seen[0]
        self.assertEqual(cmd[1:1 + len(journal.TRUSTED_MATCH)], list(journal.TRUSTED_MATCH))

    def test_quiet_journal_does_not_fall_back_to_untrusted_syslog(self):
        text, ok, _ = journal.read_since(5, run=self._run("", 0),
                                         syslog=lambda: self.fail("syslog read"))
        self.assertEqual((text, ok), ("", True))

    def test_syslog_only_when_journalctl_cannot_run(self):
        text, ok, _ = journal.read_since(5, run=self._run("", 1),
                                         syslog=lambda: ("a sysmon line", False))
        self.assertEqual((text, ok), ("a sysmon line", True))

    def test_failed_journal_without_syslog_keeps_the_cursor(self):
        text, ok, why = journal.read_since(5, run=self._run("", 1),
                                           syslog=lambda: (None, False))
        self.assertIsNone(text)
        self.assertFalse(ok)
        self.assertIn("exit 1", why)

    def test_trusted_text_bounds_and_failure(self):
        with mock.patch.object(journal, "_run", return_value=("t", 0)) as run:
            self.assertEqual(journal.trusted_text(10, 20), "t")
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[-4:], ["--since", "@10", "--until", "@20"])
        with mock.patch.object(journal, "_run", return_value=("partial", 1)):
            self.assertEqual(journal.trusted_text(10), "")

    def test_live_feed_follows_trusted_records_only(self):
        with mock.patch.object(proclinux.subprocess, "Popen") as popen:
            proclinux.StartFollower._journalctl()
        cmd = popen.call_args[0][0]
        self.assertTrue(all(m in cmd for m in proclinux.SYSMON_TRUSTED_MATCH), cmd)


@unittest.skipUnless(os.environ.get("ARGUS_LIVE_PROBE") == "1" and journal.active(),
                     "live round trip runs only with ARGUS_LIVE_PROBE=1 on a host running Sysmon")
class LiveRoundTrip(unittest.TestCase):
    def test_real_sensor_answers_the_real_probe(self):
        store = Store()
        out = sensorprobe.run(store)
        self.assertEqual([f["severity"] for f in out], ["ok"], out)


if __name__ == "__main__":
    unittest.main()
