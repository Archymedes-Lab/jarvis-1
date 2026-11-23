"""The guided assistant must stay useful with no local model, and must never
claim a check, a fix or an understanding it does not have."""

import os
import tempfile
import time
import unittest
import urllib.error
from unittest import mock

from jarvis.core.store import Store
from jarvis.response import advisor, assistant, llm
from jarvis.response.reporting import triage
from jarvis.service.schedule import JOBS

SECRET = "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"
FINDING = {"category": "data at rest", "severity": "critical", "host": "win",
           "title": "OpenAI API key in plaintext", "detail": "key found in a file", "where": "f"}


def offline(*_a, **_k):
    raise urllib.error.URLError("connection refused")


class Base(unittest.TestCase):
    def setUp(self):
        advisor.llm.reset_backoff()
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.now = int(time.time())
        for job in JOBS:
            self.snap(job, self.now - 1)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def snap(self, job, ts, findings=(), error=""):
        self.store.db.execute(
            "INSERT INTO snapshots(kind,ts,duration,error,payload) VALUES(?,?,?,?,?) "
            "ON CONFLICT(kind) DO UPDATE SET ts=excluded.ts, error=excluded.error, "
            "payload=excluded.payload", (job, ts, 1.0, error, __import__("json").dumps(list(findings))))
        self.store.db.commit()

    def ask(self, q, **kw):
        # The model is offline in every test unless the test patches it.
        with mock.patch.object(llm, "_open", side_effect=offline), \
             mock.patch.object(llm, "ps_json", return_value=None):
            return assistant.answer(self.store, q, conf={}, jobs=JOBS, **kw)


class OfflineModelIsStillUseful(Base):
    def test_greeting_needs_no_model_and_no_error_text(self):
        r = self.ask("hey")
        self.assertIn("I'm ARGUS", r["answer"])
        self.assertNotIn("Ollama", r["answer"])
        self.assertNotIn("Unable to connect", r["answer"])
        self.assertEqual(r["source"], "builtin")

    def test_natural_variations_are_understood(self):
        for q in ("Hello!", "am I safe?", "is my computer hacked?", "what should I do first?",
                  "how can I improve my score?", "what does this warning mean?", "can you fix it?",
                  "why is this monitor not working?", "what are you able to do?",
                  "explain this like I'm not technical"):
            r = self.ask(q)
            self.assertEqual(r["source"], "builtin", q)
            for banned in ("deterministic assistant", "Ollama", "llama3", "Unable to connect"):
                self.assertNotIn(banned, r["answer"], q)

    def test_unknown_question_asks_one_followup_and_does_not_pretend(self):
        r = self.ask("could these two odd things be linked somehow?")
        self.assertEqual(r["source"], "builtin")
        self.assertIn("not sure I understood", r["answer"])
        self.assertEqual(r["answer"].count("?"), 1)
        self.assertNotIn("Ollama", r["answer"])
        self.assertTrue(r["suggestions"])

    def test_unavailable_model_is_reported_as_status_not_error(self):
        r = self.ask("could these two odd things be linked somehow?")
        self.assertEqual(r["model"]["state"], "stopped")
        self.assertIn("Basic assistance is still working", r["model"]["label"])

    def test_cooldown_stops_every_question_waiting_on_a_dead_model(self):
        self.ask("could these two odd things be linked somehow?")
        with mock.patch.object(llm, "chat") as chat, mock.patch.object(llm, "_open") as opened:
            assistant.answer(self.store, "another odd open question?", conf={}, jobs=JOBS)
        chat.assert_not_called()
        opened.assert_not_called()

    def test_backoff_doubles_and_is_capped_and_reset_by_retry(self):
        llm.reset_backoff()
        llm.note_failure(now=0.0)
        self.assertTrue(llm.cooling_down(now=4.0))
        self.assertFalse(llm.cooling_down(now=5.1))
        for _ in range(10):
            llm.note_failure(now=0.0)
        self.assertFalse(llm.cooling_down(now=121.0))
        llm.reset_backoff()
        self.assertFalse(llm.cooling_down(now=0.0))


class ModelDiagnosis(unittest.TestCase):
    def setUp(self):
        llm.reset_backoff()

    def diag(self, tags=None, **conf):
        fake = mock.MagicMock()
        fake.__enter__.return_value.read.return_value = __import__("json").dumps(tags).encode()
        with mock.patch.object(llm, "_open", return_value=fake):
            return llm.diagnose(conf)

    def test_running_with_model_installed_is_ok(self):
        self.assertEqual(self.diag({"models": [{"name": "llama3.2:1b"}]})["state"], "ok")

    def test_running_without_the_model_is_missing_not_stopped(self):
        d = self.diag({"models": [{"name": "llama3.2:3b"}]})
        self.assertEqual(d["state"], "model_missing")
        self.assertIn("llama3.2:1b", d["label"])

    def test_stopped_service(self):
        with mock.patch.object(llm, "_open", side_effect=offline), \
             mock.patch.object(llm, "ps_json", return_value=None):
            self.assertEqual(llm.diagnose({})["state"], "stopped")

    def test_connection_failure_through_the_bridge_is_stopped_not_refused(self):
        # Found live on Windows: the PowerShell bridge reports "nothing is
        # listening" as an error object, which must not read as a refusal.
        bridge = {"_jarvis_error": "Unable to connect to the remote server"}
        with mock.patch.object(llm, "_open", side_effect=offline), \
             mock.patch.object(llm, "ps_json", return_value=bridge):
            self.assertEqual(llm.diagnose({})["state"], "stopped")

    def test_http_error_through_the_bridge_is_refused(self):
        bridge = {"_jarvis_error": "The remote server returned an error: (403) Forbidden."}
        with mock.patch.object(llm, "_open", side_effect=offline), \
             mock.patch.object(llm, "ps_json", return_value=bridge):
            self.assertEqual(llm.diagnose({})["state"], "refused")

    def test_failure_text_alone_names_the_cause(self):
        cases = {"Unable to connect to the remote server": "stopped",
                 "<urlopen error [WinError 10061] refused>": "stopped",
                 "The remote server returned an error: (404) Not Found.": "model_missing",
                 "model 'llama3.2:1b' not found": "model_missing",
                 "The remote server returned an error: (500) Internal Server Error.": "inference_failed",
                 "The remote server returned an error: (403) Forbidden.": "refused"}
        for text, state in cases.items():
            self.assertEqual(llm.classify_failure(text), state, text)

    def test_a_failed_chat_costs_one_attempt_not_a_second_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "t.db"))
            try:
                with mock.patch.object(llm, "chat",
                                       return_value=("", "Unable to connect to the remote server")), \
                     mock.patch.object(llm, "diagnose") as probe:
                    assistant._ollama(store, "odd question", {}, jobs=JOBS)
                probe.assert_not_called()
                self.assertEqual(llm.last_state(), "stopped")
            finally:
                store.close()

    def test_non_loopback_endpoint_is_refused_without_a_request(self):
        with mock.patch.object(llm, "_open") as opened:
            self.assertEqual(llm.diagnose({"ollama_url": "http://evil.example:11434"})["state"],
                             "misconfigured")
        opened.assert_not_called()

    def test_inference_failure_with_service_up_is_named(self):
        store_tmp = tempfile.TemporaryDirectory()
        store = Store(os.path.join(store_tmp.name, "t.db"))
        try:
            with mock.patch.object(llm, "chat", return_value=("", "HTTP (500) Internal Server Error")):
                assistant._ollama(store, "odd question", {}, jobs=JOBS)
            self.assertEqual(llm.last_state(), "inference_failed")
        finally:
            store.close()
            store_tmp.cleanup()


class FindingsBasedAdvice(Base):
    def setUp(self):
        super().setUp()
        self.snap("secrets", self.now - 1, [FINDING])

    def test_safe_question_reports_real_findings_and_never_says_safe(self):
        r = self.ask("am I safe?")
        self.assertIn("OpenAI API key in plaintext", r["answer"])
        self.assertIn("not proof", r["answer"])
        self.assertNotIn("you are safe", r["answer"].lower())
        self.assertEqual(r["offer"]["action"], "next_priority")

    def test_clean_machine_still_makes_no_absolute_claim(self):
        self.snap("secrets", self.now - 1, [])
        r = self.ask("is my computer hacked?")
        self.assertIn("No tool can prove", r["answer"])
        self.assertIn("no critical or high", r["answer"])

    def test_what_first_walks_through_the_top_finding(self):
        r = self.ask("what should I do first?")
        self.assertIn("OpenAI API key in plaintext", r["answer"])
        self.assertIn("ARGUS rates this critical", r["answer"])
        self.assertTrue(any(s["kind"] == "recommend" for s in r["sections"]))

    def test_score_question_is_plain_english_with_the_exact_projection(self):
        r = self.ask("how do I raise my score?")
        self.assertIn("I can help you improve your security score", r["answer"])
        self.assertIn("OpenAI API key in plaintext", r["answer"])
        self.assertIn("will not hide, downgrade or suppress", r["answer"])
        self.assertEqual(r["source"], "builtin")

    def test_duplicate_titles_are_grouped_in_the_score_plan(self):
        self.snap("secrets", self.now - 1, [FINDING, dict(FINDING, where="g")])
        text = self.ask("how do I raise my score?")["answer"]
        plan = text.split("Confirmed weaknesses, biggest first:")[1].split("\n\n")[0]
        self.assertEqual(plan.count("OpenAI API key in plaintext"), 1)
        self.assertIn("(2 found)", plan)

    def test_blind_monitor_is_coverage_not_compromise(self):
        job = next(iter(JOBS))
        self.snap(job, self.now - 10 * 86400)
        r = self.ask("why is this monitor not working?")
        self.assertIn("does not mean your computer has been attacked", r["answer"])
        self.assertEqual(r["offer"]["action"], "check_monitor")
        self.assertEqual(r["offer"]["target"]["job"], job)

    def test_secrets_in_findings_are_redacted(self):
        self.snap("secrets", self.now - 1, [dict(FINDING, detail=f"token={SECRET}")])
        for q in ("what should I do first?", "what does this warning mean?"):
            self.assertNotIn(SECRET, self.ask(q)["answer"])
        fid = triage.classify(FINDING | {"detail": f"token={SECRET}"}, "secrets")["id"]
        r = advisor.handle_action(self.store, JOBS, "run", "explain_finding", {"id": fid})
        self.assertNotIn(SECRET, r["answer"])

    def test_plain_language_has_no_jargon(self):
        r = self.ask("explain this like I'm not technical")
        for word in ("collector", "ATT&CK", "telemetry", "Ollama"):
            self.assertNotIn(word, r["answer"])


class SuggestedQuestions(Base):
    """The seven questions the Assistant page offers must each get a real,
    plain answer from ARGUS data with the model offline."""
    QUESTIONS = ("Is my computer okay?", "What needs my attention first?",
                 "Explain this finding in simple language.", "Why is ARGUS-INSTINCT showing this warning?",
                 "Which checks are not working?", "What can I safely do next?",
                 "What does my security score mean?")

    def setUp(self):
        super().setUp()
        self.snap("secrets", self.now - 1, [FINDING])
        self.snap(next(iter(JOBS)), self.now - 10 * 86400)

    def test_each_is_answered_deterministically_without_the_model(self):
        for q in self.QUESTIONS:
            r = self.ask(q)
            self.assertEqual(r["source"], "builtin", q)
            self.assertNotIn("not sure I understood", r["answer"], q)
            for banned in ("Ollama", "llama", "Unable to connect", "Traceback", "ATT&CK"):
                self.assertNotIn(banned, r["answer"], q)

    def test_attention_question_names_the_real_top_finding(self):
        self.assertIn("OpenAI API key in plaintext", self.ask("What needs my attention first?")["answer"])
        self.assertIn("OpenAI API key in plaintext",
                      self.ask("Explain this finding in simple language.")["answer"])

    def test_checks_question_is_about_monitoring_not_attacks(self):
        r = self.ask("Which checks are not working?")
        self.assertIn("does not mean your computer has been attacked", r["answer"])

    def test_score_meaning_uses_engine_facts_and_no_overclaim(self):
        r = self.ask("What does my security score mean?")["answer"]
        self.assertIn("not counted as safe", r)
        self.assertIn("not proof", r)
        self.assertNotRegex(r, r"(?i)you are (safe|protected|secure)")

    def test_legacy_phrases_still_reach_their_old_answers(self):
        self.assertIn("Security score:", self.ask("what is my score?")["answer"])
        self.assertIn("need you", self.ask("what needs me")["answer"].lower())


class Capabilities(Base):
    def test_listing_is_honest_when_the_service_is_not_running(self):
        r = self.ask("what are you able to do?")
        self.assertNotIn("re-run this monitor", r["answer"].split("Not available")[0]
                         .split("prepare for your approval:")[1].split(".")[0])
        self.assertIn("Not available: changing firewall rules", r["answer"])

    def test_listing_offers_rerun_when_a_runner_exists(self):
        with mock.patch.object(llm, "_open", side_effect=offline):
            r = assistant.answer(self.store, "what can you do?", conf={}, jobs=JOBS, runner=lambda j: True)
        self.assertIn("re-run this monitor", r["answer"])

    def test_every_offered_button_names_a_registered_available_capability(self):
        self.snap("secrets", self.now - 1, [FINDING])
        self.snap(next(iter(JOBS)), self.now - 10 * 86400)
        for q in ("hey", "am I safe?", "what should I do first?", "how do I raise my score?",
                  "why is a monitor not working?", "can you fix it?"):
            for a in self.ask(q)["actions"]:
                cap = advisor.CAPABILITIES[a["action"]]
                self.assertNotEqual(cap.mode, advisor.UNAVAILABLE)
                self.assertTrue(advisor.availability(cap, False)[0], a)

    def test_unsupported_repair_is_refused_and_audited(self):
        r = advisor.handle_action(self.store, JOBS, "run", "system_repair", {}, runner=lambda j: True)
        self.assertFalse(r["ok"])
        self.assertEqual(advisor.audit_log(self.store)[-1]["outcome"], "denied")

    def test_unknown_action_names_and_bad_targets_are_refused(self):
        for action, target in (("rm -rf", {}), ("check_monitor", {"job": "../etc"}),
                               ("explain_finding", {"id": "zz"}), ("check_monitor", {})):
            r = advisor.handle_action(self.store, JOBS, "run", action, target, runner=lambda j: True)
            self.assertFalse(r["ok"], (action, target))

    def test_fix_request_never_claims_it_will_change_the_system(self):
        self.snap("secrets", self.now - 1, [FINDING])
        r = self.ask("can you fix it?")
        self.assertIn("can't change your system", r["answer"])
        self.assertNotIn("I fixed", r["answer"])


class ApprovalAndVerification(Base):
    JOB = next(iter(JOBS))

    def setUp(self):
        super().setUp()
        self.queued = []
        self.snap(self.JOB, self.now - 10 * 86400, error="Access is denied")

    def runner(self, job):
        self.queued.append(job)
        return True

    def propose(self):
        return advisor.handle_action(self.store, JOBS, "propose", "rerun_monitor",
                                     {"job": self.JOB}, runner=self.runner, now=self.now)

    def test_check_reads_stored_state_and_does_not_claim_a_run(self):
        r = advisor.handle_action(self.store, JOBS, "run", "check_monitor", {"job": self.JOB},
                                  runner=self.runner, now=self.now)
        self.assertIn("did not run it again", r["answer"])
        self.assertIn("permissions problem", r["answer"])
        self.assertEqual(self.queued, [])

    def test_a_change_cannot_run_without_a_proposal(self):
        r = advisor.handle_action(self.store, JOBS, "run", "rerun_monitor", {"job": self.JOB},
                                  runner=self.runner)
        self.assertFalse(r["ok"])
        self.assertEqual(self.queued, [])

    def test_proposal_changes_nothing_until_approved(self):
        r = self.propose()
        self.assertEqual(r["state"], "proposed")
        self.assertIn("Nothing has happened yet", r["answer"])
        self.assertEqual(self.queued, [])

    def test_cancel_discards_the_proposal(self):
        token = self.propose()["token"]
        advisor.handle_action(self.store, JOBS, "cancel", token=token, runner=self.runner, now=self.now)
        r = advisor.handle_action(self.store, JOBS, "approve", token=token, runner=self.runner,
                                  now=self.now)
        self.assertFalse(r["ok"])
        self.assertEqual(self.queued, [])

    def test_approval_is_single_use_and_expires(self):
        token = self.propose()["token"]
        late = advisor.handle_action(self.store, JOBS, "approve", token=token, runner=self.runner,
                                     now=self.now + advisor.PROPOSAL_TTL_S + 1)
        self.assertFalse(late["ok"])
        token = self.propose()["token"]
        ok = advisor.handle_action(self.store, JOBS, "approve", token=token, runner=self.runner,
                                   now=self.now)
        again = advisor.handle_action(self.store, JOBS, "approve", token=token, runner=self.runner,
                                      now=self.now)
        self.assertTrue(ok["ok"])
        self.assertFalse(again["ok"])
        self.assertEqual(self.queued, [self.JOB])

    def test_forged_token_does_nothing(self):
        r = advisor.handle_action(self.store, JOBS, "approve", token="forged", runner=self.runner)
        self.assertFalse(r["ok"])
        self.assertEqual(self.queued, [])

    def test_no_service_means_no_proposal(self):
        r = advisor.handle_action(self.store, JOBS, "propose", "rerun_monitor", {"job": self.JOB},
                                  runner=None)
        self.assertFalse(r["ok"])

    def test_runner_failure_is_not_reported_as_success(self):
        token = self.propose()["token"]
        r = advisor.handle_action(self.store, JOBS, "approve", token=token, runner=lambda j: False,
                                  now=self.now)
        self.assertFalse(r["ok"])
        self.assertIn("nothing happened", r["answer"])

    def test_queued_is_not_success_until_a_fresh_valid_result_exists(self):
        token = self.propose()["token"]
        r = advisor.handle_action(self.store, JOBS, "approve", token=token, runner=self.runner,
                                  now=self.now)
        self.assertIn("can't tell you whether it worked", r["answer"])
        for word in ("Recovered", "fixed", "Verified"):
            self.assertNotIn(word, r["answer"])
        target = {"job": self.JOB, "since": self.now}
        v = advisor.handle_action(self.store, JOBS, "run", "verify_monitor", target)
        self.assertIn("Not confirmed", v["answer"])
        self.snap(self.JOB, self.now + 5, error="Access is denied")
        v = advisor.handle_action(self.store, JOBS, "run", "verify_monitor", target)
        self.assertIn("failed", v["answer"])
        self.assertNotIn("Recovered", v["answer"])
        self.snap(self.JOB, self.now + 9)
        v = advisor.handle_action(self.store, JOBS, "run", "verify_monitor", target)
        self.assertIn("Recovered", v["answer"])

    def test_audit_trail_records_each_step(self):
        token = self.propose()["token"]
        advisor.handle_action(self.store, JOBS, "approve", token=token, runner=self.runner, now=self.now)
        steps = [(e["op"], e["outcome"]) for e in advisor.audit_log(self.store)]
        self.assertEqual(steps, [("propose", "proposed"), ("approve", "queued")])

    def test_polling_verify_does_not_flood_the_audit_trail(self):
        target = {"job": self.JOB, "since": self.now}
        for _ in range(15):
            advisor.handle_action(self.store, JOBS, "run", "verify_monitor", target)
        log = advisor.audit_log(self.store)
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["repeats"], 15)
        self.snap(self.JOB, self.now + 9)                      # a state change is a new entry
        advisor.handle_action(self.store, JOBS, "run", "verify_monitor", target)
        self.assertEqual([e["outcome"] for e in advisor.audit_log(self.store)],
                         ["not_verified", "verified"])

    def test_yes_to_an_offered_change_proposes_instead_of_executing(self):
        r = self.ask("yes", offer={"action": "rerun_monitor", "target": {"job": self.JOB}},
                     runner=self.runner)
        self.assertEqual(r["state"], "proposed")
        self.assertEqual(self.queued, [])

    def test_yes_to_a_read_only_offer_runs_the_check(self):
        r = self.ask("yes", offer={"action": "check_monitor", "target": {"job": self.JOB}})
        self.assertIn("did not run it again", r["answer"])

    def test_no_declines_cleanly(self):
        self.assertIn("No problem", self.ask("no", offer={"action": "check_monitor",
                                                          "target": {"job": self.JOB}})["answer"])

    def test_finding_fix_is_verified_only_after_a_newer_clean_result(self):
        self.snap("secrets", self.now - 1, [FINDING])
        fid = triage.classify(FINDING, "secrets")["id"]
        target = {"id": fid, "job": "secrets", "since": self.now}
        r = advisor.handle_action(self.store, JOBS, "run", "verify_finding", target, now=self.now)
        self.assertIn("can't confirm it yet", r["answer"])
        self.snap("secrets", self.now + 5, [FINDING])
        r = advisor.handle_action(self.store, JOBS, "run", "verify_finding", target, now=self.now)
        self.assertIn("still present", r["answer"])
        self.snap("secrets", self.now + 9, [])
        r = advisor.handle_action(self.store, JOBS, "run", "verify_finding", target, now=self.now)
        self.assertIn("Verified", r["answer"])


class Privacy(Base):
    def test_model_prompt_is_redacted_before_leaving_the_process(self):
        sent = []
        def fake(conf, body, timeout):
            sent.append(body.decode())
            return {"message": {"content": "fine"}}, None
        with mock.patch.object(llm, "_request", side_effect=fake):
            llm.chat({}, "system", f"my key is {SECRET}")
        self.assertNotIn(SECRET, sent[0])

    def test_model_output_cannot_trigger_an_action(self):
        # The model path returns text only; a model "reply" naming an action
        # must not reach handle_action, which only the explicit endpoint calls.
        with mock.patch.object(assistant, "_ollama", return_value=("run system_repair now", "ollama")), \
             mock.patch.object(advisor, "handle_action") as handle:
            assistant.answer(self.store, "odd open question about stuff", conf={}, jobs=JOBS)
        handle.assert_not_called()


if __name__ == "__main__":
    unittest.main()
