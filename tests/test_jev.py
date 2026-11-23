"""Jev integration: advisory judgments with structural guarantees.

Load-bearing invariants under test:
  - Jev can never authorize anything: the module exposes no approval,
    authorization, application or execution capability.
  - Request state is metadata-only: no finding content, command lines,
    patch text or secrets cross the boundary; the allowlist is pinned.
  - Every failure mode (no key, offline, malformed) falls back to the
    deterministic path; drafting/review never break because Jev is down.
  - Validation output can never change proposal status by itself.
"""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.core.store import Store
from jarvis.response import fixdraft, jev, selffix

# Recorded live shape (synthetic metadata-only state, safe to embed):
# interrupt noul 0.52; disposition log @ 0.09 over page 0.23/observe 0.38.
RECORDED = {
    "model": "jev-1.13.0",
    "answers": {
        "interrupt": {"type": "noul", "noul": 0.52},
        "disposition": {"type": "choice", "choice": "log", "confidence": 0.09,
                        "probabilities": {"page": 0.23, "log": 0.39,
                                          "observe": 0.38}},
    },
    "usage": {"input_tokens": 421, "output_tokens": 57},
}


def _payload(answers, model="jev-1.13.0"):
    return {"model": model, "answers": answers, "usage": {}}


class AdvisoryStructureTests(unittest.TestCase):
    def test_module_exposes_no_authority(self):
        for name in ("approve", "authorize", "apply", "execute", "generate",
                     "enforce", "act", "decide_fix"):
            self.assertFalse(hasattr(jev, name), f"jev.{name} must not exist")

    def test_every_judgment_is_marked_advisory(self):
        with mock.patch.object(jev, "_call", return_value=_payload({})):
            for result in (jev.triage_chain({"count": 1}),
                           jev.judge_proposal({"title": "t"}),
                           jev.validate_patch({"patch_draft": ""})):
                self.assertTrue(result["advisory_only"])


class RedactionTests(unittest.TestCase):
    def test_chain_state_is_metadata_only(self):
        seen = {}
        chain = {"count": 3, "worst_severity": "high",
                 "jobs": ["sysmon", "network"], "causal": True,
                 "first": 1000.0, "last": 1100.0,
                 "members": [{"title": "C:\\secret\\evil.exe --password hunter2",
                              "detail": "cmdline /c whoami",
                              "where": "C:\\Users\\u\\doc.txt"}]}
        with mock.patch.object(
                jev, "_call",
                side_effect=lambda s, q: seen.update(state=s) or _payload({})):
            jev.triage_chain(chain)
        blob = json.dumps(seen["state"])
        for token in ("evil.exe", "hunter2", "whoami", "Users", "C:\\"):
            self.assertNotIn(token, blob)
        self.assertEqual(sorted(seen["state"]),
                         ["causal_edge", "jobs", "member_count",
                          "window_s", "worst_severity"])

    def test_patch_state_carries_stats_never_text(self):
        seen = {}
        patch = ("diff --git a/s.py b/s.py\n+api_key = 'SECRET-ABC-123'\n"
                 "-old = 'C:\\temp\\x.exe'\n")
        entry = {"problem": "stale collector",
                 "directive": {"diagnosis": "state not persisted",
                               "files": ["jarvis/service/reliability.py"]},
                 "patch_draft": patch}
        with mock.patch.object(
                jev, "_call",
                side_effect=lambda s, q: seen.update(state=s) or _payload(
                    {"addresses": {"type": "noul", "noul": 0.9}})):
            jev.validate_patch(entry)
        blob = json.dumps(seen["state"])
        self.assertNotIn("SECRET-ABC-123", blob)
        self.assertNotIn("api_key", blob)
        self.assertEqual(seen["state"]["lines_added"], 1)
        self.assertEqual(seen["state"]["lines_removed"], 1)
        self.assertEqual(seen["state"]["files"], ["s.py"])

    def test_key_never_leaves_the_authorization_header(self):
        bodies = []

        class _Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, size=-1): return json.dumps(_payload({})).encode()

        with mock.patch.dict("os.environ", {"TYPESAFE_API_KEY": "k"}), \
             mock.patch.object(
                 jev, "_open",
                 side_effect=lambda req, timeout: (bodies.append(req.data), _Resp())[1]):
            jev._call({"a": 1}, {})
        self.assertNotIn(b"k", bodies[0])


class KeyHomeTests(unittest.TestCase):
    def test_owner_only_file_is_read(self):
        import os as _os
        import tempfile as _tf
        with _tf.TemporaryDirectory() as tmp:
            path = _os.path.join(tmp, "typesafe.env")
            with open(path, "w") as fh:
                fh.write("export TYPESAFE_API_KEY='file-key'\n")
            _os.chmod(path, 0o600)
            with mock.patch.object(jev, "KEY_FILE", path), \
                 mock.patch.dict("os.environ", {}, clear=False):
                _os.environ.pop("TYPESAFE_API_KEY", None)
                self.assertEqual(jev._key(), "file-key")

    def test_group_readable_file_is_refused(self):
        import os as _os
        import tempfile as _tf
        with _tf.TemporaryDirectory() as tmp:
            path = _os.path.join(tmp, "typesafe.env")
            with open(path, "w") as fh:
                fh.write("TYPESAFE_API_KEY=file-key\n")
            _os.chmod(path, 0o640)
            with mock.patch.object(jev, "KEY_FILE", path), \
                 mock.patch.dict("os.environ", {}, clear=False):
                _os.environ.pop("TYPESAFE_API_KEY", None)
                self.assertEqual(jev._key(), "")

    def test_env_beats_file(self):
        with mock.patch.object(jev, "KEY_FILE", "/nonexistent"), \
             mock.patch.dict("os.environ", {"TYPESAFE_API_KEY": "env-key"}):
            self.assertEqual(jev._key(), "env-key")


class FallbackTests(unittest.TestCase):
    def test_no_key_means_unavailable_never_exception(self):
        with mock.patch.object(jev, "_key", return_value=""):
            for result in (jev.triage_chain({}),
                           jev.judge_proposal({}),
                           jev.validate_patch({"patch_draft": "diff"})):
                self.assertIn("unavailable", result["answers"])
                self.assertIn("fallback", result)

    def test_transport_and_shape_failures_fall_back(self):
        with mock.patch.object(jev, "_key", return_value="k"):
            with mock.patch.object(jev, "_open",
                            side_effect=OSError("offline")):
                out = jev.triage_chain({"count": 1})
                self.assertIn("unavailable", out["answers"])
                self.assertEqual(out["fallback"]["disposition"], "observe")
            with mock.patch.object(jev, "_open",
                            side_effect=Exception("weird")):
                with mock.patch("json.load", return_value={"nope": 1}):
                    out = jev.judge_proposal({"title": "t"})
                    self.assertIn("unavailable", out["answers"])


class CompositionTests(unittest.TestCase):
    def test_recorded_uncertain_disposition_escalates_to_observe(self):
        with mock.patch.object(jev, "_call", return_value=RECORDED):
            out = jev.triage_chain({"count": 1, "worst_severity": "high",
                                    "jobs": ["sysmon"], "causal": False,
                                    "first": 0, "last": 10})
        # Choice said "log" at 0.09 confidence: below the bands that may
        # decide, so the composer escalates to observe with it recorded.
        self.assertEqual(out["answers"]["disposition"], "observe")
        self.assertEqual(out["answers"]["band"], "low")

    def test_confident_page_passes_through(self):
        payload = _payload({"interrupt": {"type": "noul", "noul": 0.97},
                            "disposition": {"type": "choice", "choice": "page",
                                            "confidence": 0.92,
                                            "probabilities": {"page": 0.92}}})
        with mock.patch.object(jev, "_call", return_value=payload):
            out = jev.triage_chain({"count": 5, "worst_severity": "critical",
                                    "jobs": ["sysmon"], "causal": True,
                                    "first": 0, "last": 60})
        self.assertEqual(out["answers"]["disposition"], "page")

    def test_proposal_recommendation_follows_the_noul(self):
        with mock.patch.object(jev, "_call", return_value=_payload(
                {"worth": {"type": "noul", "noul": 0.8}})):
            self.assertEqual(
                jev.judge_proposal({"title": "t"})["answers"]["recommendation"],
                "investigate")
        with mock.patch.object(jev, "_call", return_value=_payload(
                {"worth": {"type": "noul", "noul": 0.2}})):
            self.assertEqual(
                jev.judge_proposal({"title": "t"})["answers"]["recommendation"],
                "defer")

    def test_noul_probability_is_not_reported_as_confidence(self):
        with mock.patch.object(jev, "_call", return_value=_payload(
                {"worth": {"type": "noul", "noul": 0.8}})):
            answers = jev.judge_proposal({"title": "t"})["answers"]
        self.assertEqual(answers["worth_probability"], 0.8)
        self.assertNotIn("confidence", answers)
        self.assertNotIn("band", answers)

    def test_page_requires_absolute_interrupt_probability(self):
        payload = _payload({
            "interrupt": {"type": "noul", "noul": 0.2},
            "disposition": {"type": "choice", "choice": "page",
                            "confidence": 0.95,
                            "probabilities": {"page": 0.96,
                                              "observe": 0.03,
                                              "log": 0.01}}})
        with mock.patch.object(jev, "_call", return_value=payload):
            out = jev.triage_chain({"count": 1})
        self.assertEqual(out["answers"]["disposition"], "observe")


class ResponseValidationTests(unittest.TestCase):
    class _Response:
        def __init__(self, data):
            self.data = data

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size=-1):
            return self.data[:size]

    def test_wrong_answer_type_is_rejected(self):
        with self.assertRaises(jev.JevError):
            jev._validate_answer(
                "q", {"type": "noul"},
                {"type": "choice", "choice": "yes", "confidence": 1.0,
                 "probabilities": {"yes": 1.0}})

    def test_invalid_probability_is_rejected(self):
        with self.assertRaises(jev.JevError):
            jev._validate_answer(
                "q", {"type": "noul"},
                {"type": "noul", "noul": "certain"})

    def test_oversized_response_is_rejected(self):
        response = self._Response(b"x" * (jev.MAX_RESPONSE_BYTES + 1))
        with mock.patch.object(jev, "_key", return_value="k"), \
                mock.patch.object(jev, "_open", return_value=response), \
                self.assertRaisesRegex(jev.JevError, "too large"):
            jev._call({}, {})

    def test_redirect_handler_refuses_redirects(self):
        handler = jev._NoRedirect()
        import urllib.error
        with self.assertRaises(urllib.error.URLError):
            handler.redirect_request(None, None, 302, "Found", {},
                                     "https://attacker.example/")

    def test_assess_runs_validation_only_with_a_draft_and_never_mutates(self):
        entry = {"title": "t", "problem": "p", "evidence": [],
                 "key": "k", "patch_draft": "diff --git a/a b/a\n+x\n"}
        before = copy.deepcopy(entry)
        with mock.patch.object(jev, "_call", return_value=_payload(
                {"worth": {"type": "noul", "noul": 0.7},
                 "addresses": {"type": "noul", "noul": 0.6}})):
            out = jev.assess(entry)
        self.assertIn("validation", out)
        self.assertEqual(entry, before)
        plain = copy.deepcopy({k: v for k, v in entry.items()
                               if k != "patch_draft"})
        with mock.patch.object(jev, "_call", return_value=_payload(
                {"worth": {"type": "noul", "noul": 0.7}})):
            self.assertNotIn("validation", jev.assess(plain))


class DraftHookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(str(Path(self.tmp.name) / "jarvis.db"))
        self.addCleanup(self.store.close)
        self.repo = Path(self.tmp.name) / "repo"
        (self.repo / ".git").mkdir(parents=True)
        self.entry, _ = selffix.propose(
            self.store, "test-jev", "Repair reliability", "collector stale")
        selffix.approve(self.store, self.entry["id"])

    def _draft_ok(self):
        from unittest import mock as _mock
        directive = json.dumps({
            "objective": "Repair reliability.", "diagnosis": "State is stale.",
            "files": ["jarvis/service/reliability.py"],
            "invariants": ["Do not hide missing evidence."],
            "acceptance_tests": ["python3 -m unittest tests.test_reliability"],
            "forbidden_actions": [], "uncertainties": ["Live state unknown"]})
        with _mock.patch("jarvis.response.fixdraft._git_status", return_value=""), \
             _mock.patch("jarvis.response.fixdraft.shutil.which",
                         return_value="/usr/bin/opencode"), \
             _mock.patch("jarvis.response.fixdraft.llm.chat",
                         return_value=(directive, "")), \
             _mock.patch("jarvis.response.fixdraft.subprocess.run") as run:
            run.return_value = _mock.Mock(
                returncode=0, stderr="",
                stdout="diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-a\n+b\n")
            return fixdraft.generate(self.store, self.entry["id"], str(self.repo))

    def test_validation_rides_along_without_gating_review(self):
        with mock.patch("jarvis.response.jev.available", return_value=True), \
             mock.patch("jarvis.response.jev.validate_patch",
                        return_value={"judgment": "validation",
                                      "answers": {"recommendation": "rework"},
                                      "advisory_only": True}):
            ok, _ = self._draft_ok()
        self.assertTrue(ok)
        saved = selffix.get(self.store, self.entry["id"])
        self.assertEqual(saved["status"], "review")
        self.assertEqual(saved["jev_validation"]["answers"]["recommendation"],
                         "rework")

    def test_jev_failure_leaves_review_exactly_where_it_was(self):
        with mock.patch("jarvis.response.jev.available",
                        side_effect=RuntimeError("boom")):
            ok, _ = self._draft_ok()
        self.assertTrue(ok)
        saved = selffix.get(self.store, self.entry["id"])
        self.assertEqual(saved["status"], "review")
        self.assertNotIn("jev_validation", saved)

    def test_no_key_means_no_validation_no_change(self):
        with mock.patch("jarvis.response.jev.available", return_value=False):
            ok, _ = self._draft_ok()
        self.assertTrue(ok)
        self.assertNotIn("jev_validation",
                         selffix.get(self.store, self.entry["id"]))


if __name__ == "__main__":
    unittest.main()
