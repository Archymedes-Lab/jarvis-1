import json
import os
import tempfile
import unittest
from unittest import mock

from jarvis.core.store import Store
from jarvis.response import defense, questions
from jarvis.response.actions import base, block_network, disable_autostart, quarantine, suspend
from jarvis.response.evidence import paths as evidence_paths


def dropped(path, sev="high", category="dropped file"):
    detail = ("SHA-256 " + "a" * 64 + " — known sample"
              if category == "sample match" else "listed as an attacker-created path")
    return {"category": category, "severity": sev, "host": "wsl",
            "title": "a file named in threat intelligence exists here", "where": path,
            "detail": detail}


class QuarantineActionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.qroot = tempfile.TemporaryDirectory()
        self.patch = mock.patch.object(quarantine, "QUARANTINE_DIR",
                                       os.path.join(self.qroot.name, "q"))
        self.patch.start()
        self.action = quarantine.QuarantineFile()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()
        self.qroot.cleanup()

    def _file(self, name="payload.sh", body="#!/bin/sh\necho evil\n"):
        p = os.path.join(self.tmp.name, name)
        with open(p, "w") as fh:
            fh.write(body)
        return p

    def test_matches_only_a_real_non_system_file(self):
        p = self._file()
        self.assertEqual(self.action.match(dropped(p), "hunt"), {"path": p})
        self.assertIsNone(self.action.match(dropped("/usr/bin/python3"), "hunt"))
        self.assertIsNone(self.action.match(dropped(p + ".gone"), "hunt"))
        self.assertIsNone(self.action.match({**dropped(p), "host": "win"}, "hunt"))
        self.assertIsNone(self.action.match(dropped(p), "scan"))
        self.assertIsNone(self.action.match({**dropped(p), "category": "process"}, "hunt"))

    def test_apply_moves_and_undo_restores_the_bytes(self):
        p = self._file(body="payload-body")
        ok, record, detail = self.action.apply({"path": p}, None)
        self.assertTrue(ok, detail)
        self.assertFalse(os.path.exists(p))
        self.assertTrue(os.path.isfile(record["stored"]))
        self.assertTrue(os.path.exists(p + ".jarvis-quarantined"))
        ok, detail = self.action.undo({"path": p}, record)
        self.assertTrue(ok, detail)
        with open(p) as fh:
            self.assertEqual(fh.read(), "payload-body")
        self.assertFalse(os.path.exists(p + ".jarvis-quarantined"))

    def test_undo_never_overwrites_a_file_that_returned(self):
        p = self._file()
        ok, record, _ = self.action.apply({"path": p}, None)
        self.assertTrue(ok)
        with open(p, "w") as fh:
            fh.write("something new")
        ok, detail = self.action.undo({"path": p}, record)
        self.assertFalse(ok)
        self.assertIn("exists again", detail)


class SuspendActionTests(unittest.TestCase):
    def _state(self, pid, want, tries=50):
        import time
        for _ in range(tries):
            with open(f"/proc/{pid}/stat") as fh:
                st = fh.read().rsplit(")", 1)[1].split()[0]
            if st == want:
                return st
            time.sleep(0.01)
        return st

    def test_never_matches_a_protected_process(self):
        action = suspend.SuspendProcess()
        with mock.patch.object(suspend, "_alive", return_value=True), \
             mock.patch.object(suspend, "_name", return_value="systemd"):
            self.assertIsNone(action.match({"host": "wsl", "pid": 1234}, "sysmon_linux"))

    def test_apply_and_undo_pause_resume_a_real_process(self):
        import signal
        import subprocess
        import time
        proc = subprocess.Popen(["sleep", "30"])
        try:
            action = suspend.SuspendProcess()
            # Popen returns just before the child completes execve; during that
            # small window /proc still reports the protected parent name.
            for _ in range(50):
                if suspend._name(proc.pid) == "sleep":
                    break
                time.sleep(0.01)
            target = action.match({"host": "wsl", "pid": proc.pid,
                                   "category": "sysmon-linux"}, "sysmon_linux")
            self.assertIsNotNone(target)
            ok, record, _ = action.apply(target, None)
            self.assertTrue(ok)
            self.assertEqual(self._state(proc.pid, want="T"), "T")  # stopped
            ok, _ = action.undo(target, record)
            self.assertTrue(ok)
            self.assertIn(self._state(proc.pid, want="S"), ("S", "R"))
        finally:
            proc.send_signal(signal.SIGCONT)
            proc.kill()
            proc.wait()


class LadderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.qroot = tempfile.TemporaryDirectory()
        self.qpatch = mock.patch.object(quarantine, "QUARANTINE_DIR",
                                        os.path.join(self.qroot.name, "q"))
        self.qpatch.start()
        self.epatch = mock.patch.object(evidence_paths, "EVIDENCE_ROOT",
                                       os.path.join(self.tmp.name, "evidence"))
        self.epatch.start()
        self.file = os.path.join(self.tmp.name, "drop.sh")
        with open(self.file, "w") as fh:
            fh.write("evil")

    def tearDown(self):
        self.epatch.stop()
        self.qpatch.stop()
        self.store.close()
        self.tmp.cleanup()
        self.qroot.cleanup()

    def test_interrupted_action_is_durable_and_never_retried(self):
        finding = dropped(self.file, "critical", "sample match")
        conf = {"autonomous_defense": True, "auto_quarantine": True}
        def interrupted(target, case):
            other = Store(self.store.path)
            try:
                entries = defense.load(other)
                self.assertEqual(next(iter(entries.values()))["status"], "attempting")
            finally:
                other.close()
            raise RuntimeError("interrupted")
        with mock.patch.object(quarantine.QuarantineFile, "apply", side_effect=interrupted) as apply:
            first = defense.process(self.store, conf, "hunt", [finding])[0]
            eid = first["defense"]["id"]
            self.assertEqual(first["defense"]["status"], "uncertain")
            defense.process(self.store, conf, "hunt", [dropped(self.file, "critical", "sample match")])
            self.assertFalse(defense.approve(self.store, eid)[0])
            apply.assert_called_once()

    def test_reconcile_recovers_quarantine_only_with_marker_and_undo_record(self):
        finding = dropped(self.file, "critical", "sample match")
        conf = {"autonomous_defense": True, "auto_quarantine": True}
        with mock.patch.object(quarantine.QuarantineFile, "apply", side_effect=RuntimeError("crash")):
            eid = defense.process(self.store, conf, "hunt", [finding])[0]["defense"]["id"]
        marker = self.file + ".jarvis-quarantined"
        stored = os.path.join(self.qroot.name, "q", "recovered")
        os.makedirs(os.path.dirname(stored), exist_ok=True)
        os.rename(self.file, stored)
        with open(marker, "w") as fh:
            json.dump({"stored": stored, "quarantined": 1}, fh)
        rows = defense.reconcile(self.store)
        self.assertEqual(rows[0][1], "applied")
        entry = defense.load(self.store)[eid]
        self.assertEqual(entry["status"], "applied")
        self.assertTrue(defense.undo(self.store, eid)[0])

    def test_reconcile_never_guesses_after_markerless_move(self):
        finding = dropped(self.file, "critical", "sample match")
        conf = {"autonomous_defense": True, "auto_quarantine": True}
        with mock.patch.object(quarantine.QuarantineFile, "apply", side_effect=RuntimeError("crash")):
            eid = defense.process(self.store, conf, "hunt", [finding])[0]["defense"]["id"]
        os.remove(self.file)
        rows = defense.reconcile(self.store)
        self.assertEqual(rows[0][1], "unknown")
        self.assertEqual(defense.load(self.store)[eid]["status"], "uncertain")

    def test_reconcile_not_applied_still_requires_human_decision(self):
        finding = dropped(self.file, "critical", "sample match")
        conf = {"autonomous_defense": True, "auto_quarantine": True}
        with mock.patch.object(quarantine.QuarantineFile, "apply", side_effect=RuntimeError("crash")):
            eid = defense.process(self.store, conf, "hunt", [finding])[0]["defense"]["id"]
        rows = defense.reconcile(self.store)
        self.assertEqual(rows[0][1], "not_applied")
        self.assertEqual(defense.load(self.store)[eid]["status"], "not_applied")
        with mock.patch.object(quarantine.QuarantineFile, "apply") as apply:
            defense.process(self.store, conf, "hunt", [finding])
        apply.assert_not_called()

    def test_failed_intent_write_prevents_mutation(self):
        finding = dropped(self.file, "critical", "sample match")
        with mock.patch.object(self.store, "set_meta", side_effect=OSError("disk full")), \
                mock.patch.object(quarantine.QuarantineFile, "apply") as apply:
            with self.assertRaises(OSError):
                defense.process(self.store, {"autonomous_defense": True, "auto_quarantine": True},
                                "hunt", [finding])
            apply.assert_not_called()

    def test_corrupt_history_never_reauthorizes_action(self):
        for corrupt in ('', 'null', '{', '[]', '{"entry": null}'):
            self.store.set_meta(defense.LEDGER_META, corrupt)
            with mock.patch.object(quarantine.QuarantineFile, "apply") as apply:
                with self.assertRaises(ValueError):
                    defense.process(self.store, {"autonomous_defense": True, "auto_quarantine": True},
                                    "hunt", [dropped(self.file, "critical", "sample match")])
                apply.assert_not_called()

    def test_off_by_default_proposes_never_acts(self):
        rung, action, _ = defense.decide(dropped(self.file), "hunt", {}, {})
        self.assertEqual(rung, defense.PROPOSE)
        self.assertEqual(action.id, "quarantine_file")
        defense.process(self.store, {}, "hunt", [dropped(self.file)])
        self.assertTrue(os.path.exists(self.file))            # untouched
        self.assertEqual(len(defense.pending(self.store)), 1)

    def test_enabled_and_high_severity_acts_and_is_undoable(self):
        conf = {"autonomous_defense": True, "auto_quarantine": True}
        finding = dropped(self.file, "critical", "sample match")
        rung, action, _ = defense.decide(finding, "hunt", conf, {})
        self.assertEqual(rung, defense.AUTO)
        out = defense.process(self.store, conf, "hunt", [finding])
        self.assertFalse(os.path.exists(self.file))           # quarantined
        eid = out[0]["defense"]["id"]
        self.assertEqual(out[0]["defense"]["status"], "applied")
        ok, _ = defense.undo(self.store, eid)
        self.assertTrue(ok)
        self.assertTrue(os.path.exists(self.file))            # restored

    def test_enabling_does_not_lower_the_bar_for_a_medium(self):
        conf = {"autonomous_defense": True, "auto_quarantine": True}
        rung, _, _ = defense.decide(dropped(self.file, "medium"), "hunt", conf, {})
        self.assertEqual(rung, defense.PROPOSE)

    def test_high_severity_filename_indicator_still_needs_approval(self):
        conf = {"autonomous_defense": True, "auto_quarantine": True}
        rung, _, _ = defense.decide(dropped(self.file), "hunt", conf, {})
        self.assertEqual(rung, defense.PROPOSE)

    def test_failed_evidence_capture_prevents_automatic_action(self):
        conf = {"autonomous_defense": True, "auto_quarantine": True}
        finding = dropped(self.file, "critical", "sample match")
        with mock.patch.object(defense, "Case", side_effect=OSError("disk full")):
            out = defense.process(self.store, conf, "hunt", [finding])
        self.assertTrue(os.path.exists(self.file))
        self.assertEqual(out[0]["defense"]["status"], "failed")

    def test_incomplete_coverage_can_only_propose_even_with_auto_enabled(self):
        conf = {"autonomous_defense": True, "auto_quarantine": True}
        for coverage in ("partial", "unavailable", "unknown"):
            with self.subTest(coverage=coverage):
                result = defense.process(self.store, conf, "hunt", [
                    dropped(self.file, "critical", "sample match")], coverage=coverage)
                self.assertTrue(os.path.exists(self.file))
                self.assertEqual(result[0]["defense"]["rung"], defense.PROPOSE)
                self.assertIn("incomplete collection", result[0]["defense"]["reason"])

    def test_repeated_finding_does_not_repeat_an_applied_action(self):
        conf = {"autonomous_defense": True, "auto_quarantine": True}
        finding = dropped(self.file, "critical", "sample match")
        first = defense.process(self.store, conf, "hunt", [finding])[0]
        with mock.patch.object(quarantine.QuarantineFile, "apply") as apply:
            second = defense.process(self.store, conf, "hunt", [
                dropped(self.file, "critical", "sample match")])[0]
        apply.assert_not_called()
        # The quarantined path no longer matches on the next scan. Its original
        # action remains the sole ledger entry and no second mutation occurs.
        self.assertNotIn("defense", second)
        self.assertEqual(list(defense.load(self.store)), [first["defense"]["id"]])

    def test_undo_prevents_automatic_reapplication(self):
        conf = {"autonomous_defense": True, "auto_quarantine": True}
        finding = dropped(self.file, "critical", "sample match")
        first = defense.process(self.store, conf, "hunt", [finding])[0]
        self.assertTrue(defense.undo(self.store, first["defense"]["id"])[0])
        second = defense.process(self.store, conf, "hunt", [
            dropped(self.file, "critical", "sample match")])[0]
        self.assertEqual(second["defense"]["rung"], defense.PROPOSE)
        self.assertTrue(os.path.exists(self.file))

    def test_undo_is_never_fought_on_any_later_recurrence(self):
        # Found by the V13 model (jarvis/verify/models/response_ladder.py): the
        # first recurrence became a proposal, and the second applied it again.
        conf = {"autonomous_defense": True, "auto_quarantine": True}
        first = defense.process(self.store, conf, "hunt", [dropped(self.file, "critical", "sample match")])[0]
        eid = first["defense"]["id"]
        self.assertTrue(defense.undo(self.store, eid)[0])
        for _ in range(3):
            again = defense.process(self.store, conf, "hunt", [dropped(self.file, "critical", "sample match")])[0]
            self.assertEqual(again["defense"]["rung"], defense.PROPOSE)
            self.assertEqual(defense.load(self.store)[eid]["status"], "proposed")
            self.assertTrue(os.path.exists(self.file))
        # Only a new human decision applies it again.
        self.assertTrue(defense.approve(self.store, eid, conf=conf)[0])
        self.assertEqual(defense.load(self.store)[eid]["status"], "applied")
        self.assertFalse(os.path.exists(self.file))

    def test_failed_action_waits_before_retrying(self):
        conf = {"autonomous_defense": True, "auto_quarantine": True}
        finding = dropped(self.file, "critical", "sample match")
        with mock.patch.object(defense, "Case", side_effect=OSError("disk full")):
            defense.process(self.store, conf, "hunt", [finding])
        with mock.patch.object(defense, "_apply") as apply:
            defense.process(self.store, conf, "hunt", [finding])
        apply.assert_not_called()

    def test_approve_runs_a_proposal_and_records_it(self):
        defense.process(self.store, {}, "hunt", [dropped(self.file)])
        eid = next(iter(defense.pending(self.store)))
        ok, detail = defense.approve(self.store, eid)
        self.assertTrue(ok, detail)
        self.assertFalse(os.path.exists(self.file))
        self.assertIn(eid, defense.applied(self.store))

    def test_an_acknowledged_finding_is_left_alone(self):
        from jarvis.response import acknowledge
        f = dropped(self.file)
        acknowledge.acknowledge(self.store, f, "hunt", "mine")
        rung, _, _ = defense.decide(f, "hunt", {"autonomous_defense": True,
                                                "auto_quarantine": True},
                                    acknowledge.load(self.store))
        self.assertEqual(rung, defense.WATCH)


class QuestionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _account(self):
        return {"category": "accounts", "severity": "high", "host": "win",
                "title": "account hidden from the sign-in screen: Weird",
                "where": "Winlogon", "detail": "hidden"}

    def test_a_confirm_finding_becomes_a_specific_question(self):
        self.store.save_snapshot("backdoor", [self._account()])
        qs = questions.build(self.store, self.store.get_snapshots(), {})
        self.assertEqual(len(qs), 1)
        self.assertIn("Weird", qs[0]["prompt"])
        self.assertIn("Did you", qs[0]["prompt"])

    def test_yes_acknowledges_and_no_longer_asks(self):
        self.store.save_snapshot("backdoor", [self._account()])
        qid = questions.build(self.store, self.store.get_snapshots(), {})[0]["id"]
        ok, msg = questions.answer(self.store, qid, "yes")
        self.assertTrue(ok)
        self.assertIn("expected", msg)
        self.assertEqual(questions.build(self.store, self.store.get_snapshots(), {}), [])

    def test_no_flags_and_records_the_answer(self):
        self.store.save_snapshot("backdoor", [self._account()])
        qid = questions.build(self.store, self.store.get_snapshots(), {})[0]["id"]
        with mock.patch.object(defense, "approve", return_value=(True, "blocked")):
            ok, msg = questions.answer(self.store, qid, "no")
        self.assertTrue(ok)

    def test_an_unknown_answer_is_rejected(self):
        self.store.save_snapshot("backdoor", [self._account()])
        qid = questions.build(self.store, self.store.get_snapshots(), {})[0]["id"]
        ok, _ = questions.answer(self.store, qid, "maybe")
        self.assertFalse(ok)


class TriageIntegrationTests(unittest.TestCase):
    def test_an_applied_action_reads_as_jarvis_handled_with_undo(self):
        from jarvis.response.reporting import triage
        f = {**dropped("/tmp/x"), "defense": {"rung": "auto", "status": "applied",
             "detail": "quarantined", "undo": "jarvis defend undo ab12"}}
        r = triage.classify(f, "hunt")
        self.assertEqual(r["owner"], triage.JARVIS)
        self.assertEqual(r["command"], "jarvis defend undo ab12")

    def test_a_proposal_reads_as_your_approval_with_the_command(self):
        from jarvis.response.reporting import triage
        f = {**dropped("/tmp/x"), "defense": {"rung": "propose", "preview": "Move it.",
             "approve": "jarvis defend approve ab12"}}
        r = triage.classify(f, "hunt")
        self.assertEqual(r["owner"], triage.YOU_DO)
        self.assertEqual(r["command"], "jarvis defend approve ab12")

    def test_uncertain_containment_never_reads_as_handled(self):
        from jarvis.response.reporting import triage
        f = {**dropped("/tmp/x"), "defense": {"rung": "auto", "status": "uncertain",
             "detail": "interrupted"}}
        r = triage.classify(f, "hunt")
        self.assertEqual(r["owner"], triage.YOU_DO)
        self.assertEqual(r["command"], "jarvis defend reconcile")


class RegistryTests(unittest.TestCase):
    def test_every_auto_action_is_reversible(self):
        for a in base.registry().values():
            if a.autonomy == base.AUTO:
                self.assertTrue(a.reversible, a.id)

    def test_windows_recovery_probes_only_report_state(self):
        block = block_network.BlockAddress()
        with mock.patch.object(block, "_run", return_value={"available": True, "blocked": True}) as run:
            state, record, _ = block.recover({"ip": "8.8.8.8"}, {})
        self.assertEqual(state, "applied")
        self.assertEqual(record["ip"], "8.8.8.8")
        self.assertEqual(run.call_count, 1)

        autostart = disable_autostart.DisableAutostart()
        target = {"kind": "task", "path": "\\\\", "name": "Example"}
        with mock.patch.object(autostart, "_run", return_value={"available": True, "disabled": True}):
            state, record, _ = autostart.recover(target, {})
        self.assertEqual(state, "unknown")
        self.assertEqual(record, {})


if __name__ == "__main__":
    unittest.main()
