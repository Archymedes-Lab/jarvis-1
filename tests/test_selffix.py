"""Human-in-the-loop self-fix: JARVIS asks, you decide, nothing auto-applies.

Load-bearing invariants under test:

  * the daemon path (scan/maintain/email-compose) never spawns a subprocess,
    never calls the model, and performs no network I/O beyond the configured
    Resend transport;
  * approval records intent only — it never touches the working tree;
  * applying requires an approved proposal, a clean tree, a patch that checks
    out, and passing tests; failures revert and are recorded;
  * email replies cannot approve: no inbound path exists and approve() takes
    only an explicit proposal id.
"""

import json
import os
import subprocess
import tempfile
import time
import unittest
import uuid
from types import SimpleNamespace
from unittest import mock

from jarvis.core.store import Store
from jarvis.response import alert, selffix
from jarvis.service.schedule import JOBS


def _store():
    tmp = tempfile.TemporaryDirectory()
    store = Store(os.path.join(tmp.name, "t.db"))
    return tmp, store


def _snaps(ts=None, error=""):
    now = int(time.time())
    return {name: {"ts": now if ts is None else ts, "error": "",
                   "findings": []}
            for name, (interval, _label) in JOBS.items()}


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp, self.store = _store()
        self.addCleanup(self.store.close)
        self.addCleanup(self.tmp.cleanup)

    def test_propose_approve_reject(self):
        entry, created = selffix.propose(
            self.store, "k1", "title", "problem", evidence=["e1"])
        self.assertTrue(created)
        self.assertEqual(entry["status"], "proposed")
        ok, _ = selffix.approve(self.store, entry["id"])
        self.assertTrue(ok)
        self.assertEqual(selffix.get(self.store, entry["id"])["status"], "approved")
        ok, _ = selffix.reject(self.store, entry["id"], "changed mind")
        self.assertTrue(ok)
        self.assertEqual(selffix.get(self.store, entry["id"])["status"], "rejected")

    def test_approve_is_intent_only_and_unknown_ids_fail(self):
        ok, _ = selffix.approve(self.store, "fx-deadbeef")
        self.assertFalse(ok)
        entry, _ = selffix.propose(self.store, "k2", "t", "p")
        with mock.patch("jarvis.response.selffix.uuid") as _u:
            _u.uuid4.side_effect = AssertionError("must not touch the tree")
            ok, _ = selffix.approve(self.store, entry["id"])
        self.assertTrue(ok)

    def test_duplicates_suppressed_and_cooldown_after_decision(self):
        first, made = selffix.propose(self.store, "k3", "t", "p")
        self.assertTrue(made)
        second, made = selffix.propose(self.store, "k3", "t", "p")
        self.assertFalse(made)
        self.assertEqual(first["id"], second["id"])
        selffix.reject(self.store, first["id"], "no")
        third, made = selffix.propose(self.store, "k3", "t", "p")
        self.assertFalse(made)  # 6h cooldown


class DaemonScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp, self.store = _store()
        self.addCleanup(self.store.close)
        self.addCleanup(self.tmp.cleanup)

    def test_cold_start_proposes_nothing(self):
        self.assertEqual(selffix.scan(self.store, {}, JOBS), [])

    def test_stale_and_failing_grouped_into_two_proposals(self):
        now = int(time.time())
        snaps = _snaps()
        snaps["scan"]["ts"] = now - 10000  # stale on a 60s cadence
        snaps["bridge"]["error"] = "interop down"
        created = selffix.scan(self.store, snaps, JOBS, now=now)
        self.assertEqual(len(created), 2)
        keys = sorted(p["key"] for p in created)
        self.assertEqual(keys, ["failing-collectors", "stale-collectors"])
        # Second scan: same open proposals, no duplicates.
        self.assertEqual(selffix.scan(self.store, snaps, JOBS, now=now), [])

    def test_daemon_path_touches_no_subprocess_no_model(self):
        now = int(time.time())
        snaps = _snaps()
        snaps["scan"]["ts"] = now - 10000
        with mock.patch("subprocess.run",
                        side_effect=AssertionError("daemon must not shell out")), \
             mock.patch("subprocess.Popen",
                        side_effect=AssertionError("daemon must not spawn")), \
             mock.patch("jarvis.response.llm.chat",
                        side_effect=AssertionError("daemon must not call the model")), \
             mock.patch.object(alert, "enabled", return_value=False):
            result = selffix.maintain(self.store.path, snaps, JOBS, now=now)
        self.assertEqual(len(result["created"]), 1)
        self.assertEqual(result["mailed"], [])

    def test_maintain_never_raises(self):
        with mock.patch.object(Store, "get_snapshots", side_effect=OSError("locked")):
            self.assertEqual(
                selffix.maintain(self.store.path)["created"], [])


class EmailTests(unittest.TestCase):
    def setUp(self):
        self.tmp, self.store = _store()
        self.addCleanup(self.store.close)
        self.addCleanup(self.tmp.cleanup)

    def test_email_body_names_terminal_commands_and_says_replies_do_nothing(self):
        entry, _ = selffix.propose(self.store, "k", "Fix the bridge", "bridge is down")
        text = selffix.email_text(entry)
        self.assertIn(f"jarvis fix approve {entry['id']}", text)
        self.assertIn(f"jarvis fix authorize {entry['id']}", text)
        self.assertIn(f"jarvis fix apply {entry['id']}", text)
        self.assertIn("Replying to this email does nothing", text)
        self.assertIn("Nothing has been changed", text)

    def test_one_email_per_proposal_and_daily_budget(self):
        entry, _ = selffix.propose(self.store, "k", "t", "p")
        conf = {"resend_api_key": "x", "alert_from": "a@b.c", "alert_to": "c@d.e"}
        with mock.patch.object(alert, "send_email", return_value="") as send:
            self.assertEqual(selffix.send_email_for(self.store, conf, entry["id"]), "")
            self.assertEqual(send.call_count, 1)
            # Second attempt: already mailed.
            self.assertIn("already mailed",
                          selffix.send_email_for(self.store, conf, entry["id"]))
        # Daily budget: pre-fill the log, new proposal must wait.
        entry2, _ = selffix.propose(self.store, "k2", "t", "p")
        self.store.set_meta(selffix.MAIL_LOG_META,
                            json.dumps([int(time.time())] * selffix.EMAILS_PER_DAY))
        with mock.patch.object(alert, "send_email", return_value="") as send:
            self.assertIn("budget",
                          selffix.send_email_for(self.store, conf, entry2["id"]))
            send.assert_not_called()

    def test_no_approval_path_from_email_content(self):
        # approve() requires an explicit id; there is no function that takes
        # raw email text and returns an approval.
        names = [name for name in dir(selffix) if "mail" in name.lower() or "inbox" in name.lower()]
        self.assertNotIn("approve_from_email", names)
        self.assertNotIn("handle_reply", names)
        import inspect
        sig = inspect.signature(selffix.approve)
        self.assertIn("pid", sig.parameters)


class ApplyGateTests(unittest.TestCase):
    """Apply runs against throwaway git repos, never this checkout."""

    def _repo(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        subprocess.run(["git", "init", "-q"], cwd=tmp.name, check=True)
        subprocess.run(["git", "config", "user.email", "t@t"], cwd=tmp.name, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=tmp.name, check=True)
        with open(os.path.join(tmp.name, "note.txt"), "w") as fh:
            fh.write("hello\n")
        subprocess.run(["git", "add", "."], cwd=tmp.name, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=tmp.name, check=True)
        return tmp

    def _proposal(self, store, patch, key=None):
        entry, _ = selffix.propose(store, key or f"k-apply-{uuid.uuid4().hex[:6]}",
                                   "t", "p")
        proposals = selffix._load(store)
        proposals[entry["id"]]["patch_draft"] = patch
        proposals[entry["id"]]["status"] = "review"
        selffix._save(store, proposals)
        selffix.authorize_apply(store, entry["id"])
        return entry["id"]

    def _run_apply(self, store, pid, repo, test_cmd):
        from jarvis.cli.commands import fix as fix_cli
        cwd = os.getcwd()
        os.chdir(repo.name)
        try:
            args = SimpleNamespace(id=pid, test_cmd="")
            with mock.patch.object(fix_cli, "DEFAULT_TEST_CMD", test_cmd):
                return fix_cli._apply(args, store)
        finally:
            os.chdir(cwd)

    def _run_rollback(self, store, pid, repo, test_cmd):
        from jarvis.cli.commands import fix as fix_cli
        cwd = os.getcwd()
        os.chdir(repo.name)
        try:
            args = SimpleNamespace(id=pid, test_cmd="")
            with mock.patch.object(fix_cli, "DEFAULT_TEST_CMD", test_cmd):
                return fix_cli._rollback(args, store)
        finally:
            os.chdir(cwd)

    def test_unapproved_or_patchless_proposals_cannot_apply(self):
        from jarvis.cli.commands import fix as fix_cli
        tmp, store = _store()
        self.addCleanup(store.close)
        self.addCleanup(tmp.cleanup)
        entry, _ = selffix.propose(store, "k", "t", "p")
        args = SimpleNamespace(id=entry["id"], test_cmd="")
        self.assertEqual(fix_cli._apply(args, store), 1)  # not approved
        selffix.approve(store, entry["id"])
        self.assertEqual(fix_cli._apply(args, store), 1)  # no patch

    def test_dirty_tree_refuses(self):
        tmp, store = _store()
        self.addCleanup(store.close)
        self.addCleanup(tmp.cleanup)
        repo = self._repo()
        pid = self._proposal(store, "diff --git a/note.txt b/note.txt\n")
        with open(os.path.join(repo.name, "dirty.txt"), "w") as fh:
            fh.write("uncommitted\n")
        self.assertEqual(
            self._run_apply(store, pid, repo, ["python3", "-c", "pass"]), 1)
        self.assertEqual(selffix.get(store, pid)["status"], "apply_approved")

    def test_passing_tests_apply_and_failing_tests_revert(self):
        tmp, store = _store()
        self.addCleanup(store.close)
        self.addCleanup(tmp.cleanup)
        patch = ("diff --git a/note.txt b/note.txt\n"
                 "--- a/note.txt\n+++ b/note.txt\n"
                 "@@ -1 +1 @@\n-hello\n+goodbye\n")
        repo = self._repo()
        pid = self._proposal(store, patch)
        rc = self._run_apply(store, pid, repo,
                             ["python3", "-c", "import sys; sys.exit(0)"])
        self.assertEqual(rc, 0)
        self.assertEqual(selffix.get(store, pid)["status"], "applied")
        with open(os.path.join(repo.name, "note.txt")) as fh:
            self.assertEqual(fh.read(), "goodbye\n")

        repo2 = self._repo()
        pid2 = self._proposal(store, patch)
        rc = self._run_apply(store, pid2, repo2,
                             ["python3", "-c", "import sys; sys.exit(1)"])
        self.assertEqual(rc, 1)
        self.assertEqual(selffix.get(store, pid2)["status"], "failed")
        with open(os.path.join(repo2.name, "note.txt")) as fh:
            self.assertEqual(fh.read(), "hello\n")
        status = subprocess.run(["git", "status", "--porcelain"],
                                cwd=repo2.name, capture_output=True,
                                text=True).stdout
        self.assertEqual(status.strip(), "")

    def test_patch_changed_after_authorization_is_refused(self):
        tmp, store = _store()
        self.addCleanup(store.close)
        self.addCleanup(tmp.cleanup)
        repo = self._repo()
        patch = ("diff --git a/note.txt b/note.txt\n"
                 "--- a/note.txt\n+++ b/note.txt\n@@ -1 +1 @@\n-hello\n+goodbye\n")
        pid = self._proposal(store, patch)
        proposals = selffix._load(store)
        proposals[pid]["patch_draft"] = patch.replace("goodbye", "tampered")
        selffix._save(store, proposals)
        self.assertEqual(
            self._run_apply(store, pid, repo, ["python3", "-c", "pass"]), 1)
        self.assertEqual(selffix.get(store, pid)["status"], "apply_approved")

    def test_successful_rollback_reverses_exact_applied_patch(self):
        tmp, store = _store()
        self.addCleanup(store.close)
        self.addCleanup(tmp.cleanup)
        repo = self._repo()
        patch = ("diff --git a/note.txt b/note.txt\n"
                 "--- a/note.txt\n+++ b/note.txt\n@@ -1 +1 @@\n-hello\n+goodbye\n")
        pid = self._proposal(store, patch)
        self.assertEqual(self._run_apply(
            store, pid, repo, ["python3", "-c", "pass"]), 0)
        self.assertEqual(self._run_rollback(
            store, pid, repo, ["python3", "-c", "pass"]), 0)
        with open(os.path.join(repo.name, "note.txt")) as fh:
            self.assertEqual(fh.read(), "hello\n")
        self.assertEqual(selffix.get(store, pid)["status"], "rolled_back")


class AssuranceTests(unittest.TestCase):
    def test_self_improvement_claims_no_validation(self):
        from jarvis.core import assurance
        entry = assurance.report()["capabilities"]["self_improvement"]
        self.assertEqual(entry["implementation"], "partial")
        self.assertFalse(entry["validated_containment"])
        self.assertIsNone(entry["last_validation"])


if __name__ == "__main__":
    unittest.main()
