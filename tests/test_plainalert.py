"""Every notification the daemon sends reads in plain words and keeps its facts.

Covers the plain-words layer (response/plainalert.py) and every message built
from it: the alert email (subject, text, HTML), the phone payload, webhook,
ntfy and syslog text (all carry the same subject and text), the outage and
recovery messages, the updates notice, the test message and the desktop toast.
"""

import html as htmllib
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.host import updates
from jarvis.core import brand
from jarvis.response import alert, categories, plainalert, toast
from jarvis.response.notify import channel
from jarvis.response.reporting import emails

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOW = 1_762_000_000

# A plain sentence never claims a confirmed compromise, nor a clean bill of health.
OVERCLAIM = re.compile(
    r"\b(you (have been|were|are) (hacked|compromised|infected)|is (infected|compromised)|"
    r"confirmed (attack|compromise|malware)|is malware|(computer|system|machine) is (safe|secure|clean)|"
    r"you are safe|no threats|all clear|nothing to worry)\b", re.IGNORECASE)

# Facts with no jargon of their own, so any jargon found came from a template.
CRIT = {"category": "persistence", "severity": "critical", "host": "windows",
        "title": "scheduled task \\Updater runs C:\\Users\\a\\AppData\\Local\\Temp\\upd.exe",
        "detail": "unsigned, created by powershell.exe", "where": "Task Scheduler \\Updater"}
OUTAGE = {"category": "collectors", "severity": "high", "host": "wsl",
          "title": "process list is failing", "detail": "Windows bridge timed out",
          "where": "process list"}
DOWN = {"category": "daemon", "severity": "critical", "host": "wsl",
        "title": "the background service has stopped", "detail": "exit code 1", "where": "service"}
UPDATE = {"category": "updates", "severity": "high", "title": "Google Chrome 120 is out of date",
          "where": "winget"}
WEAK = {"category": "rules", "severity": "high", "title": "inbound rule allows any address on port 3389",
        "where": "Windows Firewall"}
SECRET = {"category": "present", "severity": "critical", "title": "OpenAI API key in plaintext",
          "where": "/h/.env:1"}
ODD = {"category": "no-such-kind", "severity": "medium", "title": "odd thing at 10.0.0.7:4444"}


def _item(f, job, tag="NEW"):
    return {"finding": f, "job": job, "tag": tag, "first": NOW - 7200, "queued": NOW, "level": 1}


def _health():
    return {"score": 72, "grade": "fair", "coverage": 93, "next_steps": [],
            "areas": [{"name": "Active threats", "score": 60, "open": {"critical": 1}, "blind": ["a"]}]}


def _visible(html):
    return htmllib.unescape(re.sub(r"<[^>]+>", " ", re.sub(r"<style.*?</style>", "", html, flags=re.S)))


def _digests():
    """(name, subject, text, html) for every kind of alert email."""
    cases = {
        "critical threat": ([("a", _item(CRIT, "hunt"))], True),
        "check stopped": ([("a", _item(OUTAGE, "coverage"))], True),
        "service stopped": ([("a", _item(DOWN, "watchdogs"))], True),
        "update": ([("a", _item(UPDATE, "updates"))], False),
        "weakness": ([("a", _item(WEAK, "firewall"))], False),
        "secret": ([("a", _item(SECRET, "secrets"))], True),
        "unknown kind": ([("a", _item(ODD, "other"))], False),
        "reminder": ([("a", _item(WEAK, "firewall", "ESCALATED"))], False),
        "worse": ([("a", _item(CRIT, "hunt", "WORSENED"))], True),
        "no longer seen": ([("a", _item(CRIT, "hunt", "RESOLVED"))], False),
        "several": ([("a", _item(CRIT, "hunt")), ("b", _item(OUTAGE, "coverage")),
                     ("c", _item(WEAK, "firewall")), ("d", _item(UPDATE, "updates")),
                     ("e", _item(ODD, "other")), ("f", _item(SECRET, "secrets")),
                     ("g", _item(DOWN, "watchdogs", "RESOLVED"))], True),
        "empty": ([], False),
    }
    out = []
    for name, (ordered, urgent) in cases.items():
        for health in (None, _health()):
            s, t, h = emails.digest(ordered, urgent, health, 2 if health else None, NOW)
            out.append((name, s, t, h))
    return out


class GuideTests(unittest.TestCase):
    def test_guide_is_the_interfaces_guide(self):
        path = os.path.join(ROOT, "desktop", "ui", "src", "lib", "guide.json")
        if not os.path.exists(path):
            self.skipTest("desktop interface not in this checkout")
        with open(path) as fh:
            app = json.load(fh)
        self.assertEqual({k: list(v) for k, v in plainalert.GUIDE.items()}, app)

    def test_guide_matches_the_dashboard(self):
        with open(os.path.join(ROOT, "jarvis", "web", "static", "dashboard.js")) as fh:
            js = fh.read()
        for cat, sentences in plainalert.GUIDE.items():
            for s in sentences:
                self.assertIn(json.dumps(s), js, cat)

    def test_every_category_and_kind_has_a_plain_sentence_without_overclaim(self):
        cats = list(plainalert.GUIDE) + list(plainalert.ALIASES) + ["", "unheard-of"]
        for cat in cats:
            for sev in ("critical", "high", "medium", "low", None):
                f = {"category": cat, "severity": sev, "title": "x"}
                sentence = plainalert.lead(f, "")[0]
                self.assertTrue(sentence.endswith("."), sentence)
                self.assertFalse(OVERCLAIM.search(sentence), sentence)
        for kind, (means, todo) in plainalert.FALLBACK.items():
            for s in (means, todo, plainalert.SHORT[kind]):
                self.assertFalse(plainalert.jargon(s), s)
                self.assertFalse(OVERCLAIM.search(s), s)

    def test_missing_fields_still_give_a_message(self):
        for f in (None, {}, {"title": ""}, {"severity": "critical"}):
            lines = plainalert.lead(f)
            self.assertTrue(lines[0])
            self.assertIn("What it saw: something it could not name", lines)
        self.assertEqual(plainalert.subject([]), "[ARGUS-INSTINCT] Nothing needs you right now")


class LabelTests(unittest.TestCase):
    def test_category_labels_are_plain(self):
        for key, label in categories.LABELS.items():
            self.assertFalse(plainalert.jargon(label), label)
            self.assertNotIn("monitoring", label.lower())

    def test_phone_app_shows_the_same_labels(self):
        path = os.path.join(ROOT, "hosted", "notify-cloudflare", "public", "lib", "sync.js")
        if not os.path.exists(path):
            self.skipTest("phone app not in this checkout")
        with open(path) as fh:
            block = re.search(r"CATEGORIES = \{(.*?)\};", fh.read(), re.S).group(1)
        self.assertEqual(dict(re.findall(r'(\w+): "([^"]+)"', block)), categories.LABELS)


class JargonTests(unittest.TestCase):
    def assertPlain(self, text, where):
        self.assertEqual(plainalert.jargon(text), [], f"{where}: {text[:400]}")
        self.assertFalse(OVERCLAIM.search(text), f"{where}: {text[:400]}")

    def test_every_alert_email_is_in_plain_words(self):
        for name, subject, text, html in _digests():
            with self.subTest(name):
                self.assertPlain(subject, name + " subject")
                self.assertPlain(text, name + " text")
                self.assertPlain(_visible(html), name + " html")

    def test_scheduled_summaries_are_plain(self):
        f = {"category": "rules", "severity": "high", "title": "inbound rule open", "where": "fw"}
        pending = [("k", _item(f, "firewall")), ("r", _item({**f, "title": "old task"}, "intrusion", "RESOLVED"))]
        snaps = {"firewall": {"ts": 1, "findings": [f], "error": ""}}
        custody = {"vault_job": {"ok": True, "vaulted_segments": 36}, "sysmon": {"state": "drift"}}
        made = {"briefing": emails.briefing(pending, _health(), 3, snaps, NOW, conf={}, custody=custody,
                                            part="evening"),
                "health": emails.health(_health(), 3, snaps, NOW, conf={}),
                "action plan": emails.action_plan(_health(), (), snaps, NOW, conf={})[:3]}
        for name, (subject, text, html) in made.items():
            with self.subTest(name):
                self.assertPlain(subject + " " + text + " " + _visible(html), name)
                self.assertIn("inbound rule open", text)

    def test_every_channel_carries_the_plain_part(self):
        _name, subject, text, _html = _digests()[0]
        p = channel.payload(subject, text, "critical", "pc", NOW, category="threat")
        self.assertPlain(p["title"] + " " + p["body"] + " " + p["category_label"], "phone")
        self.assertTrue(p["body"].startswith("Something new needs you now."), p["body"])
        sent = {}

        def post(url, body, headers, label=""):
            sent[label] = (body, headers)
            return ""
        conf = {"webhook_url": "https://hook.example/x", "ntfy_url": "https://ntfy.example/t"}
        with mock.patch.object(alert, "_post", side_effect=post), \
             mock.patch.object(alert, "channels", return_value=["webhook", "ntfy", "syslog"]), \
             mock.patch.object(alert, "send_syslog", side_effect=lambda s, t, **k: sent.setdefault("syslog", (s, t)) and ""):
            self.assertEqual(alert.deliver(conf, subject, text, category="threat", severity="critical"), "")
        hook = json.loads(sent["webhook"][0])
        self.assertPlain(hook["text"] + hook["content"] + hook["category_label"], "webhook")
        self.assertPlain(sent["ntfy server"][1]["Title"] + sent["ntfy server"][0].decode(), "ntfy")
        self.assertPlain(" ".join(sent["syslog"]), "syslog")

    def test_outage_and_recovery_messages_are_plain(self):
        from jarvis.core.store import Store
        from jarvis.service import selfcheck
        verdict = dict(healthy=False, problems=["no new results for 900s"], newest_kind="scan",
                       newest_ts=NOW - 900, age=900, active_state="failed", scope="system")
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(selfcheck, "now", return_value=NOW), \
                mock.patch.object(alert, "load_conf", return_value={}), \
                mock.patch.object(alert, "enabled", return_value=True), \
                mock.patch.object(alert, "deliver", return_value="") as send:
            path = os.path.join(tmp, "s.db")
            Store(path).close()
            selfcheck._notify(path, verdict, restart_err="unit failed", restarted=True)
            selfcheck._notify(path, {**verdict, "healthy": True})
        (down, up) = send.call_args_list
        for call, sev in ((down, "critical"), (up, "high")):
            _conf, subject, text = call.args
            plain = text.split("Details:")[0]
            self.assertPlain(subject + " " + plain, subject)
            self.assertEqual(call.kwargs, {"category": "system", "severity": sev})
            self.assertIn("Details:", text)
        self.assertEqual(down.args[1], selfcheck.SUBJECT_DOWN)
        self.assertIn("did not work", down.args[2])
        for fact in ("no new results for 900s", "Automatic restart FAILED: unit failed", "failed (system)"):
            self.assertIn(fact, down.args[2])
        self.assertIn("newest snapshot: scan", up.args[2])

    def test_updates_and_test_messages_are_plain(self):
        for names, auto in ((["Google Chrome"], 0), (["Google Chrome", "7-Zip"], 1)):
            subject, text = updates.notice_text(names, auto)
            self.assertPlain(subject + " " + text, "updates")
            for n in names:
                self.assertIn(n, text)
            self.assertIn(f"{len(names)} important update", subject)
        self.assertIn("1 important update for", updates.notice_text(["a"])[1])
        self.assertPlain(alert.TEST_SUBJECT + " " + alert.TEST_TEXT, "test message")

    def test_every_toast_is_plain(self):
        for f, job in ((CRIT, "hunt"), (OUTAGE, "coverage"), (DOWN, "watchdogs"), (UPDATE, "updates"),
                       (WEAK, "firewall"), (ODD, "other"), ({**CRIT, "detail": ""}, "hunt")):
            title, body = toast.text(f, job)
            self.assertPlain(body, "toast")
            self.assertTrue(title.startswith("ARGUS-INSTINCT: "), title)


class FactsTests(unittest.TestCase):
    def test_alert_email_keeps_title_where_severity_and_detail(self):
        for f, job in ((CRIT, "hunt"), (OUTAGE, "coverage"), (SECRET, "secrets"), (ODD, "other")):
            subject, text, html = emails.digest([("a", _item(f, job))], True, None, None, NOW)
            plain = text.split("DETAILS")[0]
            self.assertIn(f"What it saw: {f['title']}", plain)
            self.assertIn(f"How serious: {f['severity']}", plain)
            if f.get("where"):
                self.assertIn(f"Where: {f['where']}", plain)
            if f.get("detail"):
                self.assertIn(f["detail"], text)
            self.assertIn(f"[{f['severity'].upper()}]", text)        # the details are unchanged
            page = _visible(html)
            self.assertIn(f"What it saw: {f['title']}", page)
            self.assertIn(plainalert.title_of(f)[:20], subject)

    def test_the_phone_sees_the_facts_inside_its_limit(self):
        ordered = [(str(i), _item({**CRIT, "title": f"task {i}"}, "hunt")) for i in range(3)]
        subject, text, _html = emails.digest(ordered, True, None, None, NOW)
        p = channel.payload(subject, text, "critical", "pc", NOW, category="threat")
        for i in range(3):
            self.assertIn(f"What it saw: task {i}", p["body"])
        self.assertIn("(and 2 more, 3 need you)", p["title"])

    def test_no_longer_seen_never_claims_a_fix(self):
        _s, text, _h = emails.digest([("a", _item(CRIT, "hunt", "RESOLVED"))], False, None, None, NOW)
        self.assertIn("No longer seen. That alone does not prove it was fixed.", text)
        self.assertIn(f"What it saw: {CRIT['title']}", text)

    def test_toast_keeps_title_and_detail(self):
        title, body = toast.text(CRIT, "hunt")
        self.assertEqual(title, "ARGUS-INSTINCT: " + CRIT["title"])
        self.assertTrue(body.endswith("What it saw: " + CRIT["detail"]), body)


class LimitTests(unittest.TestCase):
    def test_subjects_fit_the_lock_screen_and_keep_the_count(self):
        long = {**CRIT, "title": "JARVIS " + "x" * 400}
        ordered = [("a", _item(long, "hunt")), ("b", _item(WEAK, "firewall"))]
        subject, _t, _h = emails.digest(ordered, True, None, None, NOW)
        self.assertEqual(brand.brand(subject), subject)
        self.assertLessEqual(len(subject), channel.LOCK_SCREEN_TITLE)
        self.assertRegex(subject, r"… \(and 1 more, \d need you\)$")
        p = channel.payload(subject, "b" * 5000, "critical", "pc", NOW)
        self.assertLessEqual(len(p["title"]), channel.LOCK_SCREEN_TITLE)
        self.assertLessEqual(len(p["body"]), channel.BODY)

    def test_toast_fits_after_branding(self):
        f = {**CRIT, "title": "JARVIS " * 40, "detail": "JARVIS " * 80}
        title, body = (brand.brand(x) for x in toast.text(f, "hunt"))
        self.assertLessEqual(len(title), toast.TITLE_LIMIT)
        self.assertLessEqual(len(body), toast.BODY_LIMIT)
        self.assertTrue(body.endswith("…"))


if __name__ == "__main__":
    unittest.main()
