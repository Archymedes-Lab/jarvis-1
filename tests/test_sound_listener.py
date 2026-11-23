"""Continuous sound listener: hook script invariants, ingest, health, findings."""
import importlib
import json
import os
import re
import tempfile
import time
import unittest
from unittest import mock

from jarvis.collectors.host import audiowatch
from jarvis.collectors.host.inputwatch import common
from jarvis.core.paths import win_script
from jarvis.core.store import Store
from tests.test_audiowatch import sample

try:
    from jarvis.collectors.process import assemblies
except ImportError:     # a release that predates the own-assembly register
    assemblies = None

ingest = importlib.import_module("jarvis.collectors.host.inputwatch.ingest")
NOW = 1_792_760_000


def line(**over):
    rec = {"ts": NOW - 60, "kind": "sound", "sound": "beep", "source": "session",
           "ms": (NOW - 60) * 1000, "dur_ms": 160, "pulses": 1, "peak": 0.5,
           "endpoint": "{0.0.0.00000000}.{d9e9}", "pid": 0, "app": "system sounds",
           "proc_start": "", "known": 0, "sys": 1, "quiet_ms": 2902, "idle_s": 28,
           "open": 0, "fg": "WindowsTerminal"}
    rec.update(over)
    return rec


def beat(ts=NOW - 30, **over):
    sound = {"state": "running", "samples": 3227, "endpoints": 2, "sessions": 5,
             "episodes": 3, "beeps": 3, "dropped": 0, "errors": 0,
             "enumerations": 2, "last_sample": ts}
    sound.update(over)
    return {"ts": ts, "kind": "heartbeat", "pid": 42, "session": 1, "desktop": 1,
            "counters": {}, "window": {}, "sound": sound}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "test.db"))
        self.addCleanup(self.store.close)
        self.out = os.path.join(self.tmp.name, "input.jsonl")

    def feed(self, *records, raw=()):
        with open(self.out, "w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
            for text in raw:
                fh.write(text + "\n")
        with mock.patch.object(ingest, "_paths", return_value=("C:\\x", self.out)):
            ingest.ingest(self.store)

    def rows(self):
        return self.store.db.execute("SELECT * FROM sound_events ORDER BY id").fetchall()


class HookScriptInvariants(unittest.TestCase):
    """The listener is metadata-only and bounded; checked on the shipped script."""

    @classmethod
    def setUpClass(cls):
        with open(win_script("inputhook.ps1"), encoding="utf-8") as fh:
            text = fh.read()
        cls.script = text
        cls.src = text.split("$soundSrc = @'\n", 1)[1].split("\n'@", 1)[0]

    def test_meters_output_devices_only_and_never_opens_a_stream(self):
        # flow 0 = render, state mask 1 = active; capture (flow 1) or all (2) never.
        self.assertEqual(re.findall(r"EnumAudioEndpoints\((\d+),", self.src), ["0"])
        for forbidden in ("IAudioClient", "IAudioCaptureClient", "IAudioRenderClient",
                          "GetBuffer", "Initialize(", "GetDefaultAudioEndpoint(1"):
            self.assertNotIn(forbidden, self.src)

    def test_bounded_poll_queue_and_rate(self):
        consts = dict(re.findall(r"(\w+) = (\d+)", self.src))
        self.assertGreaterEqual(int(consts["StepMs"]), 20)
        self.assertLessEqual(int(consts["MaxEndpoints"]), 16)
        self.assertLessEqual(int(consts["MaxSessions"]), 64)
        self.assertLessEqual(int(consts["LinesPerMinute"]), 60)
        self.assertLessEqual(int(consts["QueueCap"]), 1024)
        self.assertEqual(int(consts["MaxBeepMs"]), 1500)
        # The host's worker drains a bounded number per tick into the hook's
        # single output queue (2026-10-31; a WinForms timer did it before).
        drain = self.script.split("static void DrainSound()", 1)[1].split("\n    }\n", 1)[0]
        self.assertIn("for (int i = 0; i < 64; i++)", drain)
        self.assertIn("JarvisInputHook.WriteState(line)", drain)

    def test_beep_lookup_is_bounded_and_names_only_the_beep_device(self):
        lookup = self.src.split("static class BeepCallers {", 1)[1].split("public static class Listener", 1)[0]
        consts = dict(re.findall(r"(\w+) = (-?\d+)", lookup))
        self.assertGreaterEqual(int(consts["MinGapMs"]), 1000)
        self.assertLessEqual(int(consts["MaxBufferBytes"].split()[0]), 64)
        self.assertIn("const uint BeepAccess = 0x3", lookup)
        self.assertIn('const string BeepDevice = @"\\Device\\Beep"', lookup)
        # Names are compared and dropped: the only thing kept is the match.
        self.assertIn("if (name == BeepDevice) holders.Add(key); else notBeep.Add(key);", lookup)
        # Duplicate-handle only; never terminate, read memory or write.
        for forbidden in ("TerminateProcess", "ReadProcessMemory", "WriteProcessMemory",
                          "CreateRemoteThread", "PROCESS_ALL_ACCESS", "0x1F0FFF"):
            self.assertNotIn(forbidden, lookup)
        self.assertIn("const uint BeepAccess = 0x3, DupHandle = 0x40, QueryLimited = 0x1000", lookup)
        # It runs off the metering thread and reports a stuck lookup.
        self.assertIn('worker.Name = "jarvis-beep-callers"', lookup)
        self.assertIn('"wedged"', lookup)

    def test_heartbeat_always_carries_listener_state(self):
        hb = self.script.split("static void Heartbeat()", 1)[1].split("\n    }\n", 1)[0]
        self.assertIn('",\\"sound\\":" + snd', hb)
        self.assertIn("_soundState ?? _soundCounters()", hb)
        # The state is never empty: "unavailable" until the listener is bound and started.
        self.assertIn("listener did not compile", self.script.split("static string _soundState", 1)[1][:120])

    def test_compile_failure_does_not_stop_the_hook(self):
        self.assertIn("try { Add-Type -TypeDefinition $soundSrc -ErrorAction Stop } catch { }",
                      self.script)
        # The host binds it by reflection and runs without it.
        self.assertIn('Bind<Action>("JarvisSound.Listener", "Start")', self.script)

    @unittest.skipIf(assemblies is None, "no own-assembly register in this tree")
    def test_own_assembly_register_counts_the_listener(self):
        # memscan recognises the hook's Add-Type assemblies by count and by the
        # script's identifiers; the listener must be inside both.
        assemblies._CACHE.pop("inputhook.ps1", None)
        idents, compiles, _hashes = assemblies._script_facts("inputhook.ps1")
        # core + host, audio, sound (brightness moved into the host 2026-10-31)
        self.assertEqual(compiles, 3)
        for name in ("JarvisSound", "Listener", "IPeakMeter", "GetPeakValue",
                     "GetSessionInstanceIdentifier", "FreeCoTaskMem"):
            self.assertIn(name, idents)
        # Constructs whose compiler-generated names are not in the source.
        self.assertNotIn("=>", self.src)
        self.assertNotIn(".Values", self.src)


class IngestTests(Base):
    def test_episode_and_heartbeat_are_stored(self):
        self.feed(line(), line(sound="sound", dur_ms=90000, sys=0, pid=9768,
                               app="firefox", known=1, proc_start="2026-10-23T11:23:07Z",
                               open=1), beat())
        rows = self.rows()
        self.assertEqual([r["sound"] for r in rows], ["beep", "sound"])
        self.assertEqual(rows[1]["app"], "firefox")
        meta = json.loads(self.store.get_meta(common.SOUND_META))
        self.assertEqual(meta["state"], "running")
        self.assertEqual(meta["sessions"], 5)
        self.assertEqual(meta["ts"], NOW - 30)

    def test_malformed_lines_are_dropped_not_half_stored(self):
        bad = [line(peak=True), line(peak=1.5), line(pid="12"), line(source="mic"),
               line(sound="tone"), line(dur_ms=1600), line(open=1), line(known=2),
               line(ts=None)]
        self.feed(*bad, line(), raw=["{not json", ""])
        self.assertEqual(len(self.rows()), 1)

    def test_text_fields_are_capped(self):
        self.feed(line(app="x" * 500, fg="y" * 500, endpoint="z" * 900))
        row = self.rows()[0]
        self.assertEqual((len(row["app"]), len(row["fg"]), len(row["endpoint"])),
                         (64, 64, 160))

    def test_newest_heartbeat_wins_and_bad_counters_are_ignored(self):
        self.feed(beat(ts=NOW - 90), beat(ts=NOW - 30, samples="many", sessions=7))
        meta = json.loads(self.store.get_meta(common.SOUND_META))
        self.assertEqual(meta["ts"], NOW - 30)
        self.assertNotIn("samples", meta)
        self.assertEqual(meta["sessions"], 7)

    def test_old_hook_heartbeat_without_listener_leaves_no_state(self):
        old = beat()
        del old["sound"]
        self.feed(old)
        self.assertEqual(self.store.get_meta(common.SOUND_META, ""), "")

    def test_retention_is_bounded(self):
        stale = int(time.time()) - 31 * 86400
        self.feed(line(ts=stale, ms=stale * 1000), line(ts=int(time.time())))
        self.assertEqual(len(self.rows()), 1)


class ListenerHealthTests(Base):
    def state(self, record, now=NOW):
        self.feed(record)
        return audiowatch.listener_state(self.store, now=now)

    def test_no_heartbeat_is_not_live(self):
        live, _beat, why = audiowatch.listener_state(self.store, now=NOW)
        self.assertFalse(live)
        self.assertIn("predates it or is not running", why)

    def test_fresh_running_listener_is_live(self):
        self.assertTrue(self.state(beat())[0])

    def test_stale_heartbeat_is_not_live(self):
        live, _b, why = self.state(beat(ts=NOW - 400))
        self.assertFalse(live)
        self.assertIn("400 s old", why)

    def test_stopped_thread_is_not_live(self):
        live, _b, why = self.state(beat(state="stopped: COMException"))
        self.assertFalse(live)
        self.assertIn("stopped: COMException", why)

    def test_beating_hook_with_a_wedged_listener_is_not_live(self):
        live, _b, why = self.state(beat(last_sample=NOW - 600))
        self.assertFalse(live)
        self.assertIn("stopped sampling", why)

    def test_did_not_compile_is_not_live(self):
        record = beat()
        record["sound"] = {"state": "unavailable: listener did not compile"}
        self.assertFalse(self.state(record)[0])


class CallerTests(Base):
    """Beep() callers and console bells are named only from measured evidence."""

    def titles(self, *records, beat_record=None):
        self.feed(*records, *( [beat_record] if beat_record else []))
        return {f["title"]: f for f in audiowatch.sound_findings(self.store, now=NOW)}

    def test_beep_caller_is_named_with_its_start_time(self):
        found = self.titles(line(caller="found", caller_pid=8316, caller_app="powershell",
                                 caller_start="2026-10-23T13:07:35Z", caller_blocked_new=8))
        detail = found["beep-like sound from powershell (Beep() call)"]["detail"]
        self.assertIn("Process 8316 started 2026-10-23T13:07:35Z had the Beep device open", detail)

    def test_no_caller_means_an_event_sound_not_beep(self):
        found = self.titles(line(caller="none", caller_blocked_new=0))
        detail = found["beep-like sound from the system sounds session"]["detail"]
        self.assertIn("not Beep()", detail)
        self.assertIn("1 none", detail)

    def test_uninspectable_new_handles_do_not_rule_out_an_elevated_caller(self):
        found = self.titles(line(caller="none visible", caller_blocked_new=12))
        detail = found["beep-like sound from the system sounds session"]["detail"]
        self.assertIn("12 handle(s) opened since the last look", detail)
        self.assertIn("elevated Beep() caller is not ruled out", detail)

    def test_console_bell_names_the_console_owner(self):
        found = self.titles(line(sys=0, pid=2440, app="conhost", known=1, console_pid=25332,
                                 console_app="powershell",
                                 console_start="2026-10-23T13:07:40Z"))
        detail = found["beep-like sound from powershell (console bell)"]["detail"]
        self.assertIn("console host (process 2440) played its bell for process 25332", detail)

    def test_found_without_a_pid_or_unknown_state_is_rejected(self):
        self.feed(line(caller="found"), line(caller="maybe"), line(caller_pid=-1),
                  line(caller="none", caller_blocked_new="many"), line(caller="none"))
        self.assertEqual([r["caller"] for r in self.rows()], ["none"])

    def test_lookup_health_and_unexpected_holders_from_the_heartbeat(self):
        now = int(time.time())
        self.feed(beat(ts=now - 5, last_sample=now - 5, beep_state="wedged",
                       beep_holders="taskhostw:9876 evil:4242"))
        titles = {f["title"]: f for f in audiowatch.listener_findings(self.store)[0]}
        self.assertEqual(titles["Beep() caller lookup not working"]["severity"], "medium")
        self.assertIn("evil:4242", titles["a process keeps the Beep device open"]["detail"])
        self.assertNotIn("taskhostw:9876,", titles["a process keeps the Beep device open"]["detail"])

    def test_healthy_lookup_with_only_the_sound_service_is_quiet(self):
        now = int(time.time())
        self.feed(beat(ts=now - 5, last_sample=now - 5, beep_state="running",
                       beep_holders="taskhostw:9876"))
        titles = [f["title"] for f in audiowatch.listener_findings(self.store)[0]]
        self.assertEqual(titles, [])

    def test_a_table_from_before_the_caller_columns_is_migrated(self):
        import sqlite3
        path = os.path.join(self.tmp.name, "old.db")
        db = sqlite3.connect(path)
        db.execute("CREATE TABLE sound_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER "
                   "NOT NULL, ms INTEGER NOT NULL, sound TEXT NOT NULL, source TEXT NOT NULL, "
                   "dur_ms INTEGER NOT NULL, pulses INTEGER NOT NULL DEFAULT 1, peak REAL NOT "
                   "NULL, endpoint TEXT NOT NULL DEFAULT '', pid INTEGER NOT NULL DEFAULT 0, app "
                   "TEXT NOT NULL DEFAULT '', proc_start TEXT NOT NULL DEFAULT '', known INTEGER "
                   "NOT NULL DEFAULT 0, sys INTEGER NOT NULL DEFAULT 0, quiet_ms INTEGER NOT NULL "
                   "DEFAULT -1, idle_s INTEGER NOT NULL DEFAULT -1, open INTEGER NOT NULL DEFAULT "
                   "0, fg TEXT NOT NULL DEFAULT '')")
        db.commit()
        db.close()
        old = Store(path)
        self.addCleanup(old.close)
        cols = {r[1] for r in old.db.execute("PRAGMA table_info(sound_events)")}
        self.assertTrue({"caller", "caller_pid", "console_pid", "caller_blocked_new"} <= cols)


class FindingTests(Base):
    def test_beeps_grouped_by_source_with_honest_attribution(self):
        self.feed(line(), line(ts=NOW - 30, ms=(NOW - 30) * 1000),
                  line(sys=0, pid=9768, app="firefox", known=1,
                       proc_start="2026-10-23T11:23:07Z"),
                  line(source="device", sys=0, app=""),
                  line(sys=0, pid=777, app="", known=0, idle_s=900))
        findings = {f["title"]: f for f in audiowatch.sound_findings(self.store, now=NOW)}
        self.assertEqual(sorted(findings), [
            "beep-like sound from firefox",
            "beep-like sound from process 777 (exited or not inspectable)",
            "beep-like sound from sound with no app session",
            "beep-like sound from the system sounds session"])
        system = findings["beep-like sound from the system sounds session"]["detail"]
        self.assertIn("2 beep(s) in 24 h", system)
        self.assertIn("not looked up (older hook)", system)
        self.assertIn("Process 9768 started 2026-10-23T11:23:07Z",
                      findings["beep-like sound from firefox"]["detail"])
        self.assertIn("1 while nobody had used the machine",
                      findings["beep-like sound from process 777 (exited or not inspectable)"]["detail"])
        self.assertTrue(all(f["severity"] == "low" for f in findings.values()))

    def test_sustained_sound_and_old_beeps_are_not_reported(self):
        self.feed(line(sound="sound", dur_ms=60000),
                  line(ts=NOW - 2 * 86400, ms=(NOW - 2 * 86400) * 1000))
        self.assertEqual(audiowatch.sound_findings(self.store, now=NOW), [])

    def _audit(self):
        with mock.patch.object(audiowatch, "ps_json", return_value=sample()):
            return audiowatch.audit(self.store)

    def test_audit_with_listener_down_says_coverage_is_the_burst(self):
        findings = {f["title"]: f for f in self._audit()}
        self.assertEqual(findings["continuous sound listener not reporting"]["severity"],
                         "medium")
        self.assertIn("jarvis inputwatch --stop && jarvis inputwatch --start",
                      findings["continuous sound listener not reporting"]["detail"])
        inventory = findings["audio route and session inventory"]["detail"]
        self.assertIn("only the burst sampler", inventory)
        self.assertIn("firmware and embedded-controller beeps", inventory)

    def test_audit_with_listener_live_reports_continuous_coverage(self):
        now = int(time.time())
        self.feed(beat(ts=now - 10, last_sample=now - 10),
                  line(ts=now - 50, ms=(now - 50) * 1000))
        findings = {f["title"]: f for f in self._audit()}
        self.assertNotIn("continuous sound listener not reporting", findings)
        self.assertIn("beep-like sound from the system sounds session", findings)
        inventory = findings["audio route and session inventory"]["detail"]
        self.assertIn("continuous listener is live", inventory)
        self.assertNotIn("only the burst sampler", inventory)

    def test_listener_findings_survive_a_failed_core_audio_probe(self):
        now = int(time.time())
        self.feed(line(ts=now - 50, ms=(now - 50) * 1000))
        with mock.patch.object(audiowatch, "ps_json", return_value=None):
            titles = [f["title"] for f in audiowatch.audit(self.store)]
        self.assertIn("audio route visibility unavailable", titles)
        self.assertIn("beep-like sound from the system sounds session", titles)


if __name__ == "__main__":
    unittest.main()
