"""The assistant's approvals and beginner answers: lifecycle, honesty and safety.

Uses an in-memory store and an injected runner. Nothing here changes the machine.
"""

import json
import os
import tempfile
import time
import unittest
import urllib.error
from unittest import mock

from jarvis.core.store import Store
from jarvis.response import advisor, assistant, llm
from jarvis.service.schedule import JOBS

FINDING = {"category": "persistence", "severity": "high", "host": "win", "title": "scheduled task",
           "detail": "runs a program automatically", "where": "C:/Windows/System32/Tasks/x"}
JOB = next(iter(JOBS))


def offline(*_a, **_k):
    raise urllib.error.URLError("refused")


class Base(unittest.TestCase):
    def setUp(self):
        llm.reset_backoff()
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.now = int(time.time())
        self.queued = []
        for job in JOBS:
            self.snap(job, self.now - 1)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def snap(self, job, ts, findings=(), error=""):
        self.store.db.execute(
            "INSERT INTO snapshots(kind,ts,duration,error,payload) VALUES(?,?,?,?,?) "
            "ON CONFLICT(kind) DO UPDATE SET ts=excluded.ts, error=excluded.error, payload=excluded.payload",
            (job, ts, 1.0, error, json.dumps(list(findings))))
        self.store.db.commit()

    def runner(self, job):
        self.queued.append(job)
        return True

    def act(self, op, **kw):
        kw.setdefault("now", self.now)
        kw.setdefault("runner", self.runner)
        return advisor.handle_action(self.store, JOBS, op, **kw)

    def propose(self, now=None):
        return self.act("propose", action="rerun_monitor", target={"job": JOB}, now=now or self.now)

    def ask(self, q, **kw):
        with mock.patch.object(llm, "_open", side_effect=offline), mock.patch.object(llm, "ps_json", return_value=None):
            return assistant.answer(self.store, q, conf={}, jobs=JOBS, **kw)


class ProposalDetailsTests(Base):
    TEN = ("proposes", "why", "target", "expected", "risks", "reversible", "if_nothing", "elevated", "exact", "evidence")

    def test_a_proposal_carries_everything_needed_to_decide_and_does_nothing_yet(self):
        self.snap(JOB, self.now - 10 * 86400, error="Access is denied")
        r = self.propose()
        d = r["details"]
        for key in self.TEN:
            self.assertTrue(d[key], key)
        self.assertEqual(d["target"]["id"], JOB)
        self.assertIn("Access is denied", d["why"])
        self.assertIn("Nothing to undo", d["reversible"])
        self.assertIn("expires in 10 minutes", d["if_nothing"])
        self.assertIn("No elevated permissions", d["elevated"])
        self.assertTrue(d["confirm_label"].startswith("Approve:"))
        self.assertEqual((r["state"], r["lifecycle"], d["lifecycle"]), ("proposed", "awaiting_approval", "awaiting_approval"))
        self.assertEqual(self.queued, [])

    def test_a_never_run_check_is_described_as_never_run_not_as_failing(self):
        self.store.db.execute("DELETE FROM snapshots WHERE kind=?", (JOB,))
        self.store.db.commit()
        d = self.propose()["details"]
        self.assertIn("has never stored a result", d["why"])

    def test_pending_proposals_are_listed_with_their_token_and_drop_out_when_expired(self):
        token = self.propose()["token"]
        listed = advisor.pending_proposals(self.store, JOBS, self.now + 5)
        self.assertEqual([d["token"] for d in listed], [token])
        self.assertEqual(listed[0]["expires_at"], self.now + advisor.PROPOSAL_TTL_S)
        self.assertEqual(advisor.pending_proposals(self.store, JOBS, self.now + advisor.PROPOSAL_TTL_S + 1), [])


class LifecycleTests(Base):
    def test_cancel_expire_reuse_and_unknown_are_told_apart_and_audited(self):
        t1 = self.propose()["token"]
        cancelled = self.act("cancel", token=t1)
        self.assertEqual((cancelled["lifecycle"], cancelled["ok"]), ("cancelled", True))
        again = self.act("approve", token=t1)
        self.assertEqual((again["ok"], again["lifecycle"]), (False, "cancelled"))
        self.assertIn("already cancelled", again["answer"])

        t2 = self.propose()["token"]
        late = self.act("approve", token=t2, now=self.now + advisor.PROPOSAL_TTL_S + 1)
        self.assertEqual((late["ok"], late["lifecycle"]), (False, "expired"))
        self.assertIn("expired", late["answer"])
        self.assertIn("Nothing was changed", late["answer"].replace("nothing was changed", "Nothing was changed"))
        self.assertIn("expired", self.act("approve", token=t2, now=self.now + advisor.PROPOSAL_TTL_S + 2)["answer"])

        unknown = self.act("approve", token="forged")
        self.assertEqual(unknown["lifecycle"], "denied")
        outcomes = [e["outcome"] for e in advisor.audit_log(self.store)]
        for expected in ("cancelled", "already_used", "expired", "unknown_token"):
            self.assertIn(expected, outcomes)
        self.assertEqual(self.queued, [])

    def test_approval_is_single_use_and_a_second_attempt_never_queues_again(self):
        token = self.propose()["token"]
        ok = self.act("approve", token=token)
        self.assertEqual((ok["ok"], ok["state"], ok["lifecycle"]), (True, "queued", "approved_queued"))
        second = self.act("approve", token=token)
        self.assertEqual((second["ok"], second["lifecycle"]), (False, "approved"))
        self.assertIn("already approved", second["answer"])
        self.assertEqual(self.queued, [JOB])

    def test_approval_after_expiry_does_not_execute_even_at_the_boundary(self):
        token = self.propose()["token"]
        r = self.act("approve", token=token, now=self.now + advisor.PROPOSAL_TTL_S)
        self.assertFalse(r["ok"])
        self.assertEqual(self.queued, [])

    def test_a_runner_failure_is_reported_as_failed_and_consumes_the_token(self):
        token = self.propose()["token"]
        r = self.act("approve", token=token, runner=lambda j: False)
        self.assertEqual((r["ok"], r["lifecycle"]), (False, "failed"))
        self.assertIn("nothing happened", r["answer"])
        self.assertFalse(self.act("approve", token=token)["ok"])

    def test_a_runner_that_raises_is_a_failure_not_a_success(self):
        def boom(job):
            raise RuntimeError("scheduler gone")
        r = self.act("approve", token=self.propose()["token"], runner=boom)
        self.assertEqual((r["ok"], r["lifecycle"]), (False, "failed"))

    def test_queued_is_never_completed_until_a_newer_valid_result_exists(self):
        self.snap(JOB, self.now - 10 * 86400, error="boom")
        token = self.propose()["token"]
        queued = self.act("approve", token=token)
        for word in ("Recovered", "Verified", "fixed", "resolved"):
            self.assertNotIn(word, queued["answer"])
        target = {"job": JOB, "since": self.now}
        waiting = self.act("run", action="verify_monitor", target=target)
        self.assertEqual(waiting["lifecycle"], "approved_queued")
        self.snap(JOB, self.now + 5, error="still failing")
        failed = self.act("run", action="verify_monitor", target=target)
        self.assertEqual(failed["lifecycle"], "failed")
        self.snap(JOB, self.now + 9)
        done = self.act("run", action="verify_monitor", target=target)
        self.assertEqual(done["lifecycle"], "completed")
        self.assertIn("Recovered", done["answer"])

    def test_a_finding_that_is_still_present_is_reported_as_not_fixed(self):
        from jarvis.response.reporting import triage
        self.snap("secrets", self.now - 1, [FINDING])
        fid = triage.classify(FINDING, "secrets")["id"]
        target = {"id": fid, "job": "secrets", "since": self.now}
        self.snap("secrets", self.now + 5, [FINDING])
        r = self.act("run", action="verify_finding", target=target)
        self.assertEqual(r["lifecycle"], "failed")
        self.assertIn("not fixed yet", r["answer"])
        self.snap("secrets", self.now + 9, [])
        self.assertEqual(self.act("run", action="verify_finding", target=target)["lifecycle"], "completed")

    def test_every_lifecycle_state_the_backend_can_emit_is_a_documented_one(self):
        emitted = set()
        t1 = self.propose()
        emitted.add(t1["lifecycle"])
        emitted.add(self.act("cancel", token=t1["token"])["lifecycle"])
        t2 = self.propose()
        emitted.add(self.act("approve", token=t2["token"])["lifecycle"])
        emitted.add(self.act("approve", token=t2["token"])["lifecycle"])
        emitted.add(self.act("approve", token="x")["lifecycle"])
        emitted.add(self.act("approve", token=self.propose()["token"], now=self.now + 9999)["lifecycle"])
        allowed = set(advisor.LIFECYCLE) | {"denied", "approved"}
        self.assertTrue(emitted <= allowed, emitted - allowed)

    def test_dismissing_without_calling_the_backend_leaves_the_proposal_open_and_unexecuted(self):
        # The UI's "Return without making changes" sends nothing; the proposal simply waits and later expires.
        self.propose()
        self.assertEqual(self.queued, [])
        self.assertEqual(len(advisor.pending_proposals(self.store, JOBS, self.now + 60)), 1)
        self.assertEqual(advisor.pending_proposals(self.store, JOBS, self.now + advisor.PROPOSAL_TTL_S + 1), [])
        self.assertEqual(self.queued, [])


class ReportOutputTests(Base):
    def test_a_monitor_check_returns_a_read_only_report_that_says_it_did_not_rerun(self):
        self.snap(JOB, self.now - 10 * 86400, error="Access is denied")
        r = self.act("run", action="check_monitor", target={"job": JOB})
        rep = r["report"]
        self.assertTrue(rep["read_only"])
        self.assertIn("Nothing on this computer was changed.", rep["not_done"])
        self.assertTrue(any("was not re-run" in x for x in rep["not_done"]))
        self.assertIn("Access is denied", " ".join(rep["found"]))
        self.assertIn("permission", " ".join(rep["meaning"]).lower())
        self.assertIn("I did not run it again", r["answer"])
        self.assertEqual(rep["status"], "complete")

    def test_explaining_a_finding_says_what_it_did_not_check_and_never_claims_a_verdict(self):
        from jarvis.response.reporting import triage
        self.snap("secrets", self.now - 1, [FINDING])
        fid = triage.classify(FINDING, "secrets")["id"]
        rep = self.act("run", action="explain_finding", target={"id": fid})["report"]
        text = json.dumps(rep).lower()
        self.assertIn("not scored", rep["certainty"].lower())
        self.assertIn("was not opened or run", text)
        self.assertNotIn("is malware", text)
        self.assertIn("legitimate explanation", text)


class BeginnerQuestionTests(Base):
    def setUp(self):
        super().setUp()
        for i in range(4):
            self.snap(list(JOBS)[i + 3], self.now - 1,
                      [dict(FINDING, title=f"serious {i}", where=f"w{i}")])
        self.snap(list(JOBS)[9], self.now - 1, [dict(FINDING, severity="medium", title="medium one", category="rules")])
        self.snap(list(JOBS)[10], self.now - 1, [dict(FINDING, severity="medium", title="medium two", category="rules")])

    def test_what_did_argus_find_separates_serious_from_total_and_states_no_changes(self):
        r = self.ask("What did ARGUS find?")
        text = r["answer"]
        self.assertIn("found 6 items to review, including 4 marked as serious", text)
        self.assertIn("Some items may have legitimate explanations", text)
        self.assertIn("No changes have been made to your computer by ARGUS-INSTINCT.", text)
        kinds = [s["kind"] for s in r["sections"]]
        self.assertEqual(kinds[0], "simple")
        self.assertIn("why", kinds)
        self.assertIn("next", kinds)
        self.assertEqual(r["source"], "builtin")

    def test_the_no_changes_sentence_is_not_said_after_an_approved_action(self):
        self.act("approve", token=self.propose()["token"])
        text = self.ask("What did ARGUS find?")["answer"]
        self.assertNotIn("No changes have been made", text)
        self.assertIn("read-only re-run", text)

    def test_changes_summary_counts_audit_and_automatic_responses_truthfully(self):
        self.assertEqual(advisor.changes_summary(self.store)["assistant_executed"], 0)
        self.assertIn("No changes have been made", advisor.changes_summary(self.store)["text"])
        with mock.patch("jarvis.response.defense.applied", return_value={"e1": {}, "e2": {}}):
            s = advisor.changes_summary(self.store)
            self.assertEqual(s["automatic_applied"], 2)
            self.assertIn("applied 2 automatic response actions", s["text"])
            self.assertNotIn("No changes", s["text"])
        with mock.patch("jarvis.response.defense.applied", side_effect=RuntimeError("unreadable")):
            s = advisor.changes_summary(self.store)
            self.assertIsNone(s["automatic_applied"])
            self.assertNotIn("No changes have been made", s["text"])

    def test_should_i_be_worried_is_calm_and_not_a_verdict(self):
        text = self.ask("Should I be worried about this?")["answer"]
        self.assertIn("calmly", text)
        self.assertIn("not that your computer is compromised", text)
        self.assertNotRegex(text.lower(), r"you are (hacked|infected)|is malware")

    def test_why_serious_explains_impact_versus_likelihood(self):
        text = self.ask("Why is this item marked serious?")["answer"]
        self.assertIn("could do if it is real", text)
        self.assertIn("does not score how likely", text)

    def test_can_this_damage_my_computer_states_what_the_page_can_and_cannot_do(self):
        text = self.ask("Can this damage my computer?")["answer"]
        self.assertIn("Looking at findings cannot damage your computer", text)
        self.assertIn("only queue a read-only re-run", text)
        self.assertIn("not available from this page", text)

    def test_how_to_investigate_safely_is_read_only_and_warns_against_deleting(self):
        text = self.ask("How do I investigate this safely?")["answer"]
        self.assertIn("Everything below is read-only", text)
        self.assertIn("Do not run unknown files", text)
        self.assertIn("destroy evidence", text)

    def test_what_has_argus_not_checked_names_the_checks_that_are_not_reporting(self):
        self.snap(JOB, self.now - 10 * 86400)
        r = self.ask("What has ARGUS not checked?")
        self.assertIn("not reporting", r["answer"])
        self.assertIn("having no alerts from an area that was not checked says nothing about it".lower(), r["answer"].lower())
        self.assertIn(JOBS[JOB][1], r["answer"])

    def test_what_happens_if_i_approve_describes_the_open_proposal_and_the_option_to_do_nothing(self):
        self.propose()
        r = self.ask("What happens if I approve this?")
        self.assertIn("Nothing has happened yet", r["answer"])
        self.assertIn("Nothing runs", r["answer"])
        self.assertEqual(r["details"]["lifecycle"], "awaiting_approval")
        self.assertEqual(self.queued, [])                                  # asking never approves

    def test_what_happens_if_i_approve_with_nothing_open_says_so(self):
        self.assertIn("Nothing is waiting for your approval", self.ask("What happens if I approve this?")["answer"])

    def test_the_monitoring_warning_question_is_answered_without_calling_it_an_attack(self):
        self.snap(JOB, self.now - 10 * 86400)
        text = self.ask("Why is my computer showing a monitoring warning?")["answer"]
        self.assertIn("does not mean your computer has been attacked", text)

    def test_every_beginner_question_works_with_the_model_offline_and_leaks_no_technical_errors(self):
        for q in ("What did ARGUS find?", "Should I be worried about this?", "Why is this item marked serious?",
                  "What happens if I approve this?", "Can this damage my computer?", "How do I investigate this safely?",
                  "What has ARGUS not checked?", "Why is my computer showing a monitoring warning?"):
            r = self.ask(q)
            self.assertEqual(r["source"], "builtin", q)
            for banned in ("Ollama", "llama", "Traceback", "Unable to connect", "not sure I understood"):
                self.assertNotIn(banned, r["answer"], q)
            self.assertEqual(self.queued, [], q)

    def test_answers_use_the_real_finding_data_not_a_generic_template(self):
        text = self.ask("Why is this item marked serious?")["answer"]
        self.assertRegex(text, r"serious \d")
        self.assertIn("persistence", text)

    def test_secrets_in_findings_never_reach_an_answer(self):
        secret = "sk-" + "Hj5Kl6Mn" * 4
        self.snap(list(JOBS)[3], self.now - 1, [dict(FINDING, title="OpenAI key", detail=f"token={secret}", where=f"C:/x/.env?k={secret}")])
        for q in ("What did ARGUS find?", "Why is this item marked serious?", "Should I be worried about this?"):
            self.assertNotIn(secret, json.dumps(self.ask(q)))


if __name__ == "__main__":
    unittest.main()
