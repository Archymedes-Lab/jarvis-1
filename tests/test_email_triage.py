import re
import unittest

from jarvis.response.reporting import email_ui as ui
from jarvis.response.reporting import emails, triage


def f(category, severity="high", title="t", where="", detail="d", **extra):
    return {"category": category, "severity": severity, "title": title,
            "where": where, "detail": detail, "host": "wsl", **extra}


class TriageTests(unittest.TestCase):
    def owner(self, finding, job):
        return triage.classify(finding, job)["owner"]

    def test_automatic_repair_is_jarvis(self):
        orphan = f("rules", title="permissive inbound rule", host="win",
                   detail="Edge — program no longer installed — orphaned rule")
        orphan["host"] = "win"
        self.assertEqual(self.owner(orphan, "firewall"), triage.JARVIS)

    def test_a_failed_automatic_repair_falls_to_you(self):
        g = f("rules", remediation={"status": "blocked", "reason": "retry limit reached"})
        t = triage.classify(g, "firewall")
        self.assertEqual(t["owner"], triage.YOU_DO)
        self.assertIn("retry limit reached", t["action"])

    def test_outages_and_monitoring_limits_are_jarvis(self):
        self.assertEqual(self.owner(f("daemon", title="the Windows monitor's email path is failing"),
                                    "watchdogs"), triage.JARVIS)
        self.assertEqual(self.owner(f("visibility", "medium", "running unprivileged"), "coverage"),
                         triage.JARVIS)

    def secret_file(self, rel, mode):
        import os
        import tempfile
        self._tmp = getattr(self, "_tmp", None) or tempfile.TemporaryDirectory()
        path = os.path.join(self._tmp.name, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            handle.write("x")
        os.chmod(path, mode)
        return path

    def tearDown(self):
        if getattr(self, "_tmp", None):
            self._tmp.cleanup()

    def test_plaintext_secrets_are_your_task(self):
        path = self.secret_file("app/.env", 0o644)
        t = triage.classify(f("present", "critical", "OpenAI API key in plaintext",
                              where=f"{path}:3"), "secrets")
        self.assertEqual((t["owner"], t["command"]), (triage.YOU_DO, f"chmod 600 {path}"))
        self.assertIn("Rotate", t["action"])

    def test_no_chmod_advice_for_a_file_that_is_already_private(self):
        path = self.secret_file("app/.env", 0o600)
        t = triage.classify(f("present", "critical", "OpenAI API key in plaintext",
                              where=f"{path}:3"), "secrets")
        self.assertEqual((t["owner"], t["command"]), (triage.YOU_DO, ""))
        self.assertIn("already readable only by you", t["action"])

    def test_private_project_env_is_advisory_not_a_rotation_task(self):
        path = self.secret_file("app/.env.local", 0o600)
        t = triage.classify(f("present", "low",
                              "API key in a private project environment file",
                              where=f"{path}:3"), "secrets")
        self.assertEqual((t["owner"], t["command"]), (triage.YOU_CONFIRM, ""))
        self.assertIn("Git-ignored", t["action"])

    def test_a_private_tool_credential_store_is_a_confirmation(self):
        path = self.secret_file(".config/gh/hosts.yml", 0o600)
        t = triage.classify(f("present", "critical", "GitHub token in plaintext",
                              where=f"{path}:4"), "secrets")
        self.assertEqual(t["owner"], triage.YOU_CONFIRM)
        self.assertIn("tool's own credential store", t["action"])

    def test_an_exposed_tool_credential_store_is_a_task(self):
        path = self.secret_file(".config/gh/hosts.yml", 0o644)
        t = triage.classify(f("present", "critical", "GitHub token in plaintext",
                              where=f"{path}:4"), "secrets")
        self.assertEqual((t["owner"], t["command"]), (triage.YOU_DO, f"chmod 600 {path}"))

    def test_unencrypted_private_keys_get_a_passphrase_command(self):
        path = self.secret_file(".ssh/id_ed25519", 0o600)
        t = triage.classify(f("present", "high", "private key block (unencrypted) stored locally",
                              where=f"{path}:1"), "secrets")
        self.assertEqual(t["command"], f"ssh-keygen -p -f {path}")

    def test_no_location_means_no_half_command(self):
        t = triage.classify(f("present", "critical", "API key in plaintext"), "secrets")
        self.assertEqual(t["command"], "")

    def test_read_only_suggestions_are_confirmations(self):
        t = triage.classify(f("services", "medium", "service installed recently",
                              detail='"Claude" — \\SystemRoot\\x.sys'), "firewall")
        self.assertNotEqual(t["owner"], triage.JARVIS)

    def test_detections_default_to_confirm_never_to_handled(self):
        for job, cat in (("memscan", "injected code"), ("sysmon", "injection"),
                         ("hunt", "named process"), ("mystery", "brand-new-category")):
            with self.subTest(cat):
                self.assertEqual(self.owner(f(cat), job), triage.YOU_CONFIRM)

    def test_process_churn_is_not_a_task(self):
        self.assertEqual(triage.current({"scan": {"findings": [f("process", "critical")]}}), [])


class EmailUiTests(unittest.TestCase):
    def test_utility_classes_compile_to_inline_css(self):
        self.assertEqual(ui.tw("p-4 rounded-xl bg-slate-900 text-white"),
                         'style="padding:16px;border-radius:12px;background-color:#0f172a;color:#ffffff"')
        self.assertIn("border-left-color:#dc2626", ui.tw("border-l-red-600"))

    def test_unknown_utility_classes_fail_loudly(self):
        with self.assertRaises(ValueError):
            ui.tw("bg-pink-400")

    def test_escaping(self):
        card = ui.finding_card(f("x", title="<script>alert(1)</script>"), "job",
                               {"owner": triage.YOU_CONFIRM, "action": "a & b", "command": "rm '<x>'"})
        self.assertNotIn("<script>", card)
        self.assertIn("&lt;script&gt;", card)


class DigestTests(unittest.TestCase):
    def test_digest_separates_what_needs_you_from_what_jarvis_handles(self):
        secret = f("present", "critical", "OpenAI API key in plaintext", where="/h/.env:1")
        outage = f("daemon", "medium", "the Windows monitor's email path is failing")
        thread = f("injection", "high", "dwm.exe created a thread")
        gone = f("rules", "high", "old rule")
        ordered = [("a", {"finding": secret, "job": "secrets", "tag": "NEW", "first": 0, "level": 0}),
                   ("b", {"finding": outage, "job": "watchdogs", "tag": "ESCALATED", "first": 0, "level": 1}),
                   ("c", {"finding": thread, "job": "sysmon", "tag": "NEW", "first": 0, "level": 0}),
                   ("d", {"finding": gone, "job": "firewall", "tag": "RESOLVED", "first": 0, "level": 0})]
        subject, text, html = emails.digest(ordered, True, None, None, 7200)
        self.assertIn("(and 3 more, 2 need you)", subject)
        self.assertIn("2 need you", subject)
        sections = [l for l in text.splitlines() if re.match(r"^(NEEDS YOU|JARVIS IS HANDLING|NO LONGER)", l)]
        self.assertEqual(sections, ["NEEDS YOU — ACTION (1)", "NEEDS YOU — CONFIRM (1)",
                                    "JARVIS IS HANDLING (1)", "NO LONGER SEEN (1)"])
        self.assertLess(text.index("OpenAI API key"), text.index("JARVIS IS HANDLING"))
        self.assertIn("$ chmod 600 /h/.env", text)
        for label in ("Needs you — action · 1", "Needs you — confirm · 1", "JARVIS is handling · 1"):
            self.assertIn(label, html)
        self.assertIn("reminder · 2h open", html)


if __name__ == "__main__":
    unittest.main()


class DigestDesignTests(unittest.TestCase):
    def _ordered(self, severity="critical"):
        a = f("present", severity, "OpenAI API key in plaintext", where="/h/.env:1")
        b = {**a, "title": "Second secret", "subject_id": "edge-1"}
        a = {**a, "subject_id": "edge-1"}
        return [("a", {"finding": a, "job": "secrets", "tag": "NEW", "first": 0, "level": 0}),
                ("b", {"finding": b, "job": "secrets", "tag": "NEW", "first": 0, "level": 0})]

    def test_urgent_digest_arrives_red_with_hero_and_mood(self):
        subject, text, html = emails.digest(self._ordered(), True, None, None, 7200)
        self.assertIn("#b91c1c", html)  # red-700 hero
        self.assertIn("need you", html)
        self.assertIn("These need you now.", text)

    def test_calm_digest_arrives_green_with_splendid_mood(self):
        subject, text, html = emails.digest([], False, None, None, 7200)
        self.assertIn("Nothing needs you", subject)
        self.assertIn("#047857", html)  # emerald-700 hero
        self.assertIn("Splendid.", text)

    def test_related_findings_render_as_story_cards(self):
        subject, text, html = emails.digest(self._ordered(), True, None, None, 7200)
        self.assertIn("RELATED ACTIVITY (1 story)", text)
        self.assertIn("2 related observations", text)
        self.assertIn("one of these led directly to the next", html)
        self.assertIn("border-left-color:#7c3aed", html)  # violet story accent

    def test_story_headlines_are_escaped(self):
        evil = {**f("present", "critical", "<img src=x>", where="x"), "subject_id": "e",
                "title": "<img src=x>"}
        evil2 = {**evil, "title": "second <b>half</b>"}
        ordered = [("a", {"finding": evil, "job": "j", "tag": "NEW", "first": 0, "level": 0}),
                   ("b", {"finding": evil2, "job": "j", "tag": "NEW", "first": 0, "level": 0})]
        _s, _t, html = emails.digest(ordered, True, None, None, 7200)
        self.assertNotIn("<img src=x>", html)
        self.assertIn("&lt;img", html)

    def test_health_email_wears_violet_with_score_hero(self):
        result = {"score": 80, "grade": "B+", "coverage": 90, "areas": [],
                  "next_steps": []}
        subject, text, html = emails.health(result, 0, {}, 7200)
        self.assertIn("#6d28d9", html)  # violet-700 hero
        self.assertIn("80%", html)
        self.assertIn("Splendid.", text)

    def test_unknown_tone_falls_back_to_slate(self):
        self.assertIn("#0f172a", ui.header("k", "t", "s", tone="nope"))
