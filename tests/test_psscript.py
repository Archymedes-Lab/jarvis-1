"""PowerShell script blocks: cursor, continuity, privacy, own scripts, bounds.

Invariants (collectors/telemetry/psscript.py)
  1. The cursor moves only after a pass that read and validated its records.
  2. Lost records and logging switched off are reported, never read as quiet.
  3. Script text is never stored and never appears in a finding.
  4. The monitor's own scripts are named to the reader by hash; never by name.
  5. Reads are bounded and what a bound cut is reported.
  6. Matches are community findings: capped, attributed, per-install judged.
"""
import hashlib
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.telemetry import community, psscript
from jarvis.core import sigma
from jarvis.core.paths import load_win_script
from jarvis.core.store import Store
from jarvis.platform import windows

SECRET = "Invoke-Evil -Password Hunter2!"
RULE = {"schema": sigma.SCHEMA, "source": {"repo": "r", "commit": "0" * 40, "license": "DRL"},
        "rules": [{"id": "ps-1", "title": "Evil cmdlet", "level": "critical", "author": "Ann Author",
                   "tids": ["T1059.001"], "cat": sigma.WIN_PS,
                   "sels": {"s": [[["text", "contains", False, [["invoke-evil"]]]]]}, "cond": ["sel", "s"]}]}
PS_RULE = sigma.parse(json.dumps(RULE).encode())["rules"][sigma.WIN_PS][0]


def block(rec, text="Get-Date", path="", level=5, **over):
    b = {"rec": rec, "time": "2026-11-10T12:00:00.0000000Z", "pid": 1, "level": level, "path": path,
         "sha": hashlib.sha256(text.encode()).hexdigest(), "len": len(text), "complete": True,
         "truncated": False, "text": text}
    b.update(over)
    return b


def answer(blocks=(), first=10, last=20, read=5, oldest=1, enabled=True, **over):
    a = {"enabled": enabled, "log": {"enabled": True, "records": 900, "max_bytes": 15 * 1024 * 1024, "oldest": oldest},
         "first": first, "last": last, "read": read, "own": 3, "more": False, "errors": [], "blocks": list(blocks)}
    a.update(over)
    return a


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.addCleanup(self.store.close)
        patch = mock.patch.object(sigma, "index", side_effect=lambda category, path=None: (
            sigma.Index([PS_RULE] if category == sigma.WIN_PS else []), ""))
        patch.start()
        self.addCleanup(patch.stop)
        self.cursors = []

    def run_pass(self, raw):
        def reader(cursor):
            self.cursors.append(cursor)
            if raw is None:
                return None, "Windows did not answer"
            valid = psscript._valid(raw)
            return (valid, "") if valid is not None else (None, "the reader's answer was malformed")
        return psscript.audit(self.store, reader=reader)

    def cursor(self):
        return psscript._state(self.store)["cursor"]


class Cursor(Base):
    def test_a_good_pass_moves_the_cursor_to_the_last_record_read(self):
        self.run_pass(answer(last=20))
        self.assertEqual(self.cursor(), 20)
        self.run_pass(answer(first=21, last=35))
        self.assertEqual((self.cursors, self.cursor()), ([0, 20], 35))

    def test_no_answer_a_malformed_answer_or_reader_errors_keep_the_cursor(self):
        self.run_pass(answer(last=20))
        for raw in (None, {"enabled": True}, answer(last=5, first=9), answer(blocks=[{"rec": "x"}]),
                    answer(blocks=[block(1, text="a" * 70000)]), answer(last=99, errors=["read failed: X"])):
            out = self.run_pass(raw)
            self.assertEqual(self.cursor(), 20, raw)
            self.assertTrue(any(f["category"] == "visibility" and "not read" in f["title"] for f in out), raw)

    def test_an_empty_pass_keeps_the_cursor(self):
        self.run_pass(answer(last=20))
        self.run_pass(answer(first=0, last=0, read=0))
        self.assertEqual(self.cursor(), 20)

    def test_the_cursor_never_goes_backwards(self):
        self.run_pass(answer(last=20))
        self.run_pass(answer(first=3, last=7))
        self.assertEqual(self.cursor(), 20)


class Continuity(Base):
    def test_records_overwritten_between_passes_are_counted_and_reported(self):
        self.run_pass(answer(last=100))
        out = self.run_pass(answer(first=5001, last=5100, oldest=5001))
        gap = [f for f in out if "overwritten" in f["title"]]
        self.assertEqual(len(gap), 1)
        self.assertIn("About 4900 records", gap[0]["detail"])
        self.assertIn("wevtutil sl", gap[0]["detail"])

    def test_no_gap_is_claimed_on_the_first_pass_or_when_records_are_contiguous(self):
        self.assertFalse([f for f in self.run_pass(answer(last=100, oldest=50)) if "overwritten" in f["title"]])
        self.assertFalse([f for f in self.run_pass(answer(first=101, last=120, oldest=60)) if "overwritten" in f["title"]])

    def test_logging_off_is_said_and_is_not_a_clean_result(self):
        out = self.run_pass(answer(enabled=False, read=0, first=0, last=0))
        self.assertEqual([f["title"] for f in out], ["PowerShell script-block logging is off"])
        self.assertIn("does not turn it on", out[0]["detail"])

    def test_what_a_bound_cut_is_reported(self):
        out = self.run_pass(answer(blocks=[block(11, truncated=True), block(12, complete=False)], more=True))
        titles = [f["title"] for f in out]
        self.assertIn("Some PowerShell scripts were only partly checked", titles)
        self.assertIn("PowerShell script blocks: more than one pass could read", titles)


class Matching(Base):
    def later(self):
        """Past the learning week, so a new shape alerts."""
        self.store.set_meta(community.META, json.dumps({"since": 0, "shapes": {}}))

    def test_a_matching_block_is_a_community_finding_without_its_text(self):
        self.later()
        out = self.run_pass(answer(blocks=[block(11, text=SECRET, path="C:\\Users\\u\\evil.ps1")]))
        hits = [f for f in out if "(community rule)" in f["title"]]
        self.assertEqual(len(hits), 1)
        f = hits[0]
        self.assertEqual((f["severity"], f["techniques"], f["origin"]), ("high", ["T1059.001"], "sigma"))
        self.assertIn("Ann Author", f["detail"])
        self.assertIn("evil.ps1", f["detail"])
        for text in (f["title"], f["detail"], self.store.get_meta(psscript.META, ""),
                     self.store.get_meta(community.META, "")):
            self.assertNotIn("Hunter2", text)
            self.assertNotIn("Invoke-Evil", text)

    def test_a_block_with_no_script_file_does_not_put_its_text_anywhere(self):
        for burn_in in (False, True):                       # as an alert, and as a learned shape
            self.store.set_meta(community.META, "" if burn_in else json.dumps({"since": 0, "shapes": {}}))
            self.store.set_meta(psscript.META, "")
            out = self.run_pass(answer(blocks=[block(11, text=SECRET)]))
            self.assertTrue(out)
            everything = json.dumps(out) + (self.store.get_meta(psscript.META, "") or "") \
                + (self.store.get_meta(community.META, "") or "")
            self.assertNotIn("hunter2", everything.lower(), burn_in)
            self.assertNotIn("invoke-evil", everything.lower(), burn_in)

    def test_a_hit_stays_listed_for_a_day_then_ages_out(self):
        self.later()
        self.run_pass(answer(blocks=[block(11, text=SECRET)]))
        again = self.run_pass(answer(first=21, last=30))
        self.assertEqual(len([f for f in again if "(community rule)" in f["title"]]), 1)
        with mock.patch.object(psscript, "now", return_value=psscript.now() + psscript.KEEP_FOR_S + 60):
            aged = self.run_pass(answer(first=31, last=40))
        self.assertEqual([f for f in aged if "(community rule)" in f["title"]], [])

    def test_a_hit_is_still_listed_when_a_later_pass_fails(self):
        self.later()
        self.run_pass(answer(blocks=[block(11, text=SECRET)]))
        out = self.run_pass(None)
        self.assertEqual(len([f for f in out if "(community rule)" in f["title"]]), 1)

    def test_an_ordinary_block_raises_nothing(self):
        self.later()
        self.assertEqual(self.run_pass(answer(blocks=[block(11, text="Get-ChildItem C:\\")])), [])

    def test_in_the_learning_week_a_match_is_inventory_not_an_alert(self):
        out = self.run_pass(answer(blocks=[block(11, text=SECRET)]))
        self.assertEqual([f["severity"] for f in out], ["low"])
        self.assertIn("has not been reviewed", out[0]["title"])


class OwnScripts(unittest.TestCase):
    def test_the_request_names_own_scripts_by_hash_and_includes_the_reader(self):
        seen = {}

        def fake_ps_json(script, timeout=120, payload=None):
            seen["script"], seen["req"] = script, json.loads(payload)
            return answer()
        launched = windows.note_own_script("Get-Process | Out-Null")
        with mock.patch.object(windows, "ps_json", fake_ps_json):
            got, why = psscript.read(42)
        self.assertEqual(why, "")
        req = seen["req"]
        self.assertEqual(req["after"], 42)
        self.assertIn(launched, req["own"])
        self.assertIn(hashlib.sha256(seen["script"].encode()).hexdigest(), req["own"])
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", h) for h in req["own"]))
        self.assertNotIn("Get-Process", json.dumps(req))            # hashes only, never script text
        self.assertLessEqual((req["max_events"], req["max_blocks"], req["max_text"]),
                             (psscript.MAX_EVENTS, psscript.MAX_BLOCKS, psscript.MAX_TEXT))

    def test_the_ledger_is_exact_and_bounded(self):
        a = windows.note_own_script("x = 1")
        self.assertEqual(a, hashlib.sha256(b"x = 1").hexdigest())
        self.assertNotEqual(a, windows.note_own_script("x = 1 "))  # one character differs: not the same script
        with mock.patch.object(windows, "OWN_SCRIPTS_MAX", 5):
            for i in range(20):
                windows.note_own_script(f"script {i}")
            self.assertLessEqual(len(windows.own_scripts()), 5)
            self.assertIn(hashlib.sha256(b"script 19").hexdigest(), windows.own_scripts())

    def test_every_launch_through_the_runner_is_recorded(self):
        with mock.patch.object(windows.host, "has_windows", return_value=True), \
                mock.patch.object(windows, "available", return_value=True), \
                mock.patch.object(windows, "spawn", side_effect=OSError("no interop here")):
            windows.ps_json("Get-Service | Select-Object -First 1")
        self.assertIn(hashlib.sha256(b"Get-Service | Select-Object -First 1").hexdigest(), windows.own_scripts())


class Payload(unittest.TestCase):
    TEXT = load_win_script("psscript.ps1")

    def test_the_reader_only_reads(self):
        code = "\n".join(line for line in self.TEXT.splitlines() if not line.lstrip().startswith("#"))
        for verb in ("Set-", "New-Item", "Remove-", "Clear-", "Out-File", "Add-Content", "wevtutil", "Limit-EventLog",
                     "Start-Process", "Invoke-Expression", "iex ", "Invoke-WebRequest", "Net.WebClient"):
            self.assertNotIn(verb.lower(), code.lower(), verb)

    def test_own_matching_is_by_hash_and_caps_are_enforced_in_the_reader(self):
        self.assertIn("$ownSet.Contains($h)", self.TEXT)
        self.assertIn("'^[0-9a-f]{64}$'", self.TEXT)
        for cap in ("5000", "500", "65536", "4194304"):
            self.assertIn(cap, self.TEXT)
        self.assertTrue(self.TEXT.startswith("# jarvis: psscript reader"))


if __name__ == "__main__":
    unittest.main()

class PartialEvidence(Base):
    def test_partial_or_truncated_scripts_cannot_trigger_absence_conditions(self):
        self.store.set_meta(community.META, json.dumps({'since': 0, 'shapes': {}}))
        for flags in ({'complete': False}, {'truncated': True}):
            out = self.run_pass(answer(blocks=[block(11, text=SECRET, **flags)]))
            self.assertFalse(any('(community rule)' in f['title'] for f in out))
            self.assertTrue(any('partly checked' in f['title'] for f in out))

    def test_reader_does_not_trust_process_id_for_following_blocks(self):
        self.assertNotIn('$ownPid', load_win_script('psscript.ps1'))

class LogReset(Base):
    def test_record_sequence_reset_rereads_from_zero_and_records_gap(self):
        self.run_pass(answer(last=100))
        raw = answer(first=0, last=0, read=0)
        raw['log']['newest'] = 5
        reread = answer(first=1, last=5, read=2)
        reread['log']['newest'] = 5
        values = iter([psscript._valid(raw), psscript._valid(reread)])
        cursors = []
        def reader(cursor):
            cursors.append(cursor)
            return next(values), ''
        out = psscript.audit(self.store, reader=reader)
        self.assertEqual(cursors, [100, 0])
        self.assertEqual(self.cursor(), 5)
        self.assertTrue(any('sequence reset' in f['title'] for f in out))

    def test_failed_reread_after_reset_keeps_previous_cursor(self):
        self.run_pass(answer(last=100))
        raw = answer(first=0, last=0, read=0)
        raw['log']['newest'] = 5
        values = iter([(psscript._valid(raw), ''), (None, 'failed')])
        out = psscript.audit(self.store, reader=lambda cursor: next(values))
        self.assertEqual(self.cursor(), 100)
        self.assertTrue(any('reset could not be read' in f['title'] for f in out))

    def test_logging_off_is_reported_even_with_old_records(self):
        out = self.run_pass(answer(enabled=False, blocks=[block(11)]))
        self.assertTrue(any('logging is off' in f['title'] for f in out))
