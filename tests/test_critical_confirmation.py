"""A critical finding cannot be silenced through the local API.

Invariants (PRODUCTION-READINESS-2026-11-02 blocker 1):

  1. `acknowledge` refuses a critical finding unless the caller names a
     confirmation made outside the API; the default is refusal.
  2. An acknowledgement of a critical finding without that record does not
     apply: the finding keeps its severity for scoring, alerting and questions.
  3. A "yes" on a critical finding through `questions.answer` (the API path)
     changes no state at all: no acknowledgement, no answer, no egress decision.
  4. The terminal confirmation never reads input unless both streams are
     terminals, and accepts only the exact id.
  5. Lower severities behave as before, and "no" on a critical still works.
"""
import argparse
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from jarvis.cli import output
from jarvis.cli.commands import ack as ack_cli
from jarvis.cli.commands import defend as defend_cli
from jarvis.core.store import Store
from jarvis.response import acknowledge as ack
from jarvis.response import questions

NOW = 2_000_000_000


def finding(sev="critical", title="account hidden from the sign-in screen: Weird"):
    return {"category": "accounts", "severity": sev, "host": "win", "title": title,
            "where": "Winlogon", "detail": "hidden"}


class Tty(io.StringIO):
    def __init__(self, text="", tty=True):
        super().__init__(text)
        self._tty = tty

    def isatty(self):
        return self._tty


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.store.close)

    def state(self):
        """Everything an answer or acknowledgement may write."""
        return (self.store.get_meta(ack.META, ""), self.store.get_meta(questions.META, ""))


class Gate(Base):
    def test_a_critical_is_refused_by_default(self):
        with self.assertRaises(ack.ConfirmationRequired):
            ack.acknowledge(self.store, finding(), "backdoor", "mine", now=NOW)
        self.assertEqual(ack.load(self.store), {})

    def test_an_unknown_confirmation_is_refused(self):
        for bad in ("api", "", "phone", True):
            with self.assertRaises(ValueError):
                ack.acknowledge(self.store, finding(), "backdoor", "mine", now=NOW, confirmed_by=bad)
        self.assertEqual(ack.load(self.store), {})

    def test_a_confirmed_critical_is_recorded_and_applies(self):
        fid, entry = ack.acknowledge(self.store, finding(), "backdoor", "mine", now=NOW,
                                     confirmed_by=ack.TERMINAL)
        self.assertEqual(entry["confirmed_by"], "terminal")
        self.assertTrue(ack.is_acknowledged(ack.load(self.store), finding(), "backdoor", now=NOW + 1))

    def test_a_critical_record_without_confirmation_does_not_apply(self):
        # What an older release, or a writer that skipped the gate, would have stored.
        fid, _ = ack.acknowledge(self.store, finding(), "backdoor", "mine", now=NOW,
                                 confirmed_by=ack.TERMINAL)
        acks = ack.load(self.store)
        del acks[fid]["confirmed_by"]
        self.assertFalse(ack.is_acknowledged(acks, finding(), "backdoor", now=NOW + 1))
        acks[fid]["confirmed_by"] = "api"
        self.assertFalse(ack.is_acknowledged(acks, finding(), "backdoor", now=NOW + 1))

    def test_a_high_acknowledged_before_it_became_critical_does_not_cover_the_critical(self):
        ack.acknowledge(self.store, finding("high"), "backdoor", "mine", now=NOW)
        self.assertFalse(ack.is_acknowledged(ack.load(self.store), finding("critical"), "backdoor",
                                             now=NOW + 1))

    def test_lower_severities_need_no_confirmation(self):
        for sev in ("high", "medium", "low"):
            ack.acknowledge(self.store, finding(sev, title=f"t {sev}"), "backdoor", "mine", now=NOW)
            self.assertTrue(ack.is_acknowledged(ack.load(self.store), finding(sev, title=f"t {sev}"),
                                                "backdoor", now=NOW + 1))


class ApiPath(Base):
    def _qid(self, f):
        self.store.save_snapshot("backdoor", [f])
        return ack.finding_id(f, "backdoor")

    def test_yes_on_a_critical_changes_nothing(self):
        qid = self._qid(finding())
        before = self.state()
        ok, message = questions.answer(self.store, qid, "yes", now=NOW)
        self.assertFalse(ok)
        self.assertIn("terminal", message)
        self.assertIn(qid, message)
        self.assertEqual(self.state(), before)
        self.assertFalse(ack.is_acknowledged(ack.load(self.store), finding(), "backdoor", now=NOW))

    def test_yes_on_a_critical_egress_finding_does_not_mark_the_program_expected(self):
        f = finding(title="new program reaching the internet: evil.exe")
        qid = self._qid(f)
        with mock.patch.object(questions.egress, "program_of", return_value="evil.exe"), \
                mock.patch.object(questions.egress, "decide") as decide:
            ok, _ = questions.answer(self.store, qid, "yes", now=NOW)
        self.assertFalse(ok)
        decide.assert_not_called()

    def test_no_on_a_critical_is_still_recorded(self):
        qid = self._qid(finding())
        ok, _ = questions.answer(self.store, qid, "no", now=NOW)
        self.assertTrue(ok)
        self.assertEqual(json.loads(self.store.get_meta(questions.META))[qid]["answer"], questions.NO)

    def test_yes_on_a_high_still_acknowledges(self):
        qid = self._qid(finding("high"))
        ok, _ = questions.answer(self.store, qid, "yes", now=NOW)
        self.assertTrue(ok)
        self.assertTrue(ack.is_acknowledged(ack.load(self.store), finding("high"), "backdoor", now=NOW))

    def test_a_confirmed_yes_acknowledges_the_critical(self):
        qid = self._qid(finding())
        ok, _ = questions.answer(self.store, qid, "yes", now=NOW, confirmed_by=ack.TERMINAL)
        self.assertTrue(ok)
        self.assertEqual(ack.load(self.store)[qid]["confirmed_by"], "terminal")


class TypedConfirmation(unittest.TestCase):
    def test_exact_id_at_a_terminal(self):
        self.assertTrue(output.typed_confirmation("ab12cd34", "x", Tty("ab12cd34\n"), Tty()))

    def test_anything_else_cancels(self):
        for typed in ("\n", "yes\n", "y\n", "ab12cd3\n", "AB12CD34\n", ""):
            self.assertFalse(output.typed_confirmation("ab12cd34", "x", Tty(typed), Tty()), typed)

    def test_a_pipe_is_refused_without_reading(self):
        piped = Tty("ab12cd34\n", tty=False)
        self.assertFalse(output.typed_confirmation("ab12cd34", "x", piped, Tty()))
        self.assertEqual(piped.tell(), 0)
        self.assertFalse(output.typed_confirmation("ab12cd34", "x", Tty("ab12cd34\n"), Tty(tty=False)))

    def test_a_closed_stream_is_refused(self):
        closed = Tty("ab12cd34\n")
        closed.close()
        self.assertFalse(output.typed_confirmation("ab12cd34", "x", closed, Tty()))


class Cli(Base):
    def _ack(self, fid, typed, tty=True, reason="mine"):
        args = argparse.Namespace(revoke=None, target=fid, reason=reason, days=90)
        out = Tty()
        with mock.patch.object(output.sys, "stdin", Tty(typed, tty=tty)), \
                mock.patch.object(output.sys, "stdout", out), contextlib.redirect_stdout(out):
            return ack_cli.cmd_ack(args, self.store), out.getvalue()

    def test_ack_of_a_critical_needs_the_typed_id(self):
        self.store.save_snapshot("backdoor", [finding()])
        fid = ack.finding_id(finding(), "backdoor")
        for typed, tty in (("yes\n", True), (fid + "\n", False), ("", True)):
            code, text = self._ack(fid, typed, tty)
            self.assertEqual(code, 2, text)
            self.assertEqual(ack.load(self.store), {})
        code, _ = self._ack(fid, fid + "\n")
        self.assertEqual(code, 0)
        self.assertEqual(ack.load(self.store)[fid]["confirmed_by"], "terminal")

    def test_the_list_says_which_earlier_confirmations_stopped_applying(self):
        self.store.save_snapshot("backdoor", [finding()])
        fid, _ = ack.acknowledge(self.store, finding(), "backdoor", "mine", confirmed_by=ack.TERMINAL)
        args = argparse.Namespace(revoke=None, target="list", reason="", days=90)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ack_cli.cmd_ack(args, self.store)
        self.assertNotIn("NOT APPLYING", out.getvalue())
        acks = ack.load(self.store)
        del acks[fid]["confirmed_by"]                      # as stored by an earlier release
        self.store.set_meta(ack.META, json.dumps(acks))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ack_cli.cmd_ack(args, self.store)
        self.assertIn("NOT APPLYING", out.getvalue())
        self.assertIn(fid, out.getvalue())

    def test_ack_of_a_high_asks_nothing(self):
        self.store.save_snapshot("backdoor", [finding("high")])
        fid = ack.finding_id(finding("high"), "backdoor")
        code, text = self._ack(fid, "", tty=False)
        self.assertEqual(code, 0, text)
        self.assertNotIn("confirmed_by", ack.load(self.store)[fid])

    def test_answer_yes_on_a_critical_needs_the_typed_id(self):
        self.store.save_snapshot("backdoor", [finding()])
        fid = ack.finding_id(finding(), "backdoor")
        args = argparse.Namespace(qid=fid, choice="yes")
        out = Tty()
        with mock.patch.object(output.sys, "stdin", Tty(fid + "\n", tty=False)), \
                mock.patch.object(output.sys, "stdout", out), contextlib.redirect_stdout(out):
            self.assertEqual(defend_cli.cmd_answer(self.store, args), 2)
        self.assertEqual(ack.load(self.store), {})
        out = Tty()
        with mock.patch.object(output.sys, "stdin", Tty(fid + "\n")), \
                mock.patch.object(output.sys, "stdout", out), contextlib.redirect_stdout(out):
            self.assertEqual(defend_cli.cmd_answer(self.store, args), 0)
        self.assertEqual(ack.load(self.store)[fid]["confirmed_by"], "terminal")


if __name__ == "__main__":
    unittest.main()
