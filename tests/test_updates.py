"""Outdated software on every package manager, the bounded updater and
categorized notifications (jarvis/collectors/host/updates.py,
jarvis/response/updater.py, jarvis/response/categories.py).

Invariants:
  U1 a manager that cannot be listed is a visibility finding, never "up to date"
  U2 "important" is the fixed EXPOSED rule or a security pocket
  U3 the daemon updates only user-scope winget and Homebrew items, only when
     the owner opted in, never pinned, excluded or admin-needing ones; a typo
     in the policy falls back to notify
  U4 at most AUTO_PER_DAY items a day, single flight, failures not retried
     automatically for a day
  U5 an update counts only when a fresh listing shows the new version; an
     unreadable manager afterwards is "not verified"
  U6 every attempt is logged owner-only with the versions before and after
  U7 every notification carries one category, the same on every channel
"""

import json
import os
import stat
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.host import updates
from jarvis.core import incidents
from jarvis.response import alert, categories, updater

# Synthetic winget tables with the shapes measured on 2026-11-02: names padded
# by display width and containing double spaces, "< x" versions, Unknown.
WINGET_ALL = """\
Name                                         Id                          Version        Available      Source
----------------------------------------------------------------------------------------------------------------
Example Browser                              Example.Browser             120.0.1        121.0.0        winget
Runtime  17.0.19+10 (x64)                    Vendor.Runtime.17           17.0.19.10     17.0.21.1021   winget
Some Launcher                                Vendor.Launcher             < 3.14.7       3.14.7         winget
Scanner Tool                                 Vendor.Scanner              Unknown        6.7.81.0       winget
Plain Game                                   Studio.PlainGame            1.0            1.1            winget
Git                                          Git.Git                     2.53.0         2.56.0.4       winget
5 upgrades available.
"""
WINGET_USER = """\
Name                                         Id                          Version        Available      Source
----------------------------------------------------------------------------------------------------------------
Git                                          Git.Git                     2.53.0         2.56.0.4       winget
Plain Game                                   Studio.PlainGame            1.0            1.1            winget
2 upgrades available.
"""
APT = """\
Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst cowsay [3.03] (3.04 Ubuntu:24.04/noble-updates [all])
Conf libssl3t64 (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-updates [amd64])
"""


def item(manager="winget", pid="Git.Git", name="Git", installed="1", available="2", **kw):
    return updates._item(manager, pid, name, installed, available, **kw)


class ParserTests(unittest.TestCase):
    def test_winget_is_parsed_from_the_right(self):
        rows = {i["id"]: i for i in updates.parse_winget(WINGET_ALL)}
        self.assertEqual(sorted(rows), sorted(["Example.Browser", "Vendor.Runtime.17", "Vendor.Launcher",
                                               "Vendor.Scanner", "Studio.PlainGame", "Git.Git"]))
        self.assertEqual(rows["Vendor.Runtime.17"]["name"], "Runtime 17.0.19+10 (x64)")
        self.assertEqual(rows["Vendor.Launcher"]["installed"], "< 3.14.7")
        self.assertEqual(rows["Vendor.Scanner"]["installed"], "Unknown")
        self.assertEqual(rows["Git.Git"]["available"], "2.56.0.4")
        self.assertTrue(all(r["needs_admin"] for r in rows.values()))   # scope unknown: admin

    def test_winget_user_scope_is_merged_in_the_windows_listing(self):
        doc = {"winget": WINGET_ALL, "winget_user": WINGET_USER, "choco": "chocolatey|2.7.2|2.7.5|false\n"}
        with mock.patch("jarvis.platform.host.has_windows", return_value=True):
            found, failed = updates.list_windows(ps=lambda script, timeout: doc)
        self.assertEqual(failed, {})
        w = {i["id"]: i for i in found["winget"]}
        self.assertEqual((w["Git.Git"]["scope"], w["Git.Git"]["needs_admin"]), ("user", False))
        self.assertEqual((w["Example.Browser"]["scope"], w["Example.Browser"]["needs_admin"]), ("machine", True))
        self.assertEqual(found["choco"][0]["id"], "chocolatey")
        self.assertTrue(found["choco"][0]["needs_admin"])

    def test_windows_without_an_answer_is_a_failure_not_empty(self):
        with mock.patch("jarvis.platform.host.has_windows", return_value=True):
            found, failed = updates.list_windows(ps=lambda script, timeout: None)
        self.assertEqual(found, {})
        self.assertEqual(set(failed), {"winget", "choco"})

    def test_apt_security_pocket_and_no_removals(self):
        rows = {i["id"]: i for i in updates.parse_apt(APT)}
        self.assertEqual(sorted(rows), ["cowsay", "libssl3t64"])
        self.assertTrue(rows["libssl3t64"]["security"] and rows["libssl3t64"]["important"])
        self.assertFalse(rows["cowsay"]["important"])
        self.assertEqual(rows["libssl3t64"]["installed"], "3.0.13-0ubuntu3.4")

    def test_brew_snap_choco(self):
        brew = json.dumps({"formulae": [{"name": "openssl@3", "installed_versions": ["3.4.0"],
                                         "current_version": "3.4.1", "pinned": False},
                                        {"name": "gcc", "installed_versions": ["15"], "current_version": "16",
                                         "pinned": True}], "casks": []})
        b = {i["id"]: i for i in updates.parse_brew(brew)}
        self.assertTrue(b["openssl@3"]["important"])
        self.assertTrue(b["gcc"]["pinned"])
        self.assertIsNone(updates.parse_brew("not json"))
        self.assertEqual(updates.parse_snap("All snaps up to date.\n"), [])
        snap = updates.parse_snap("Name  Version  Rev  Size  Publisher  Notes\nfirefox 130 4 1MB moz -\n")
        self.assertEqual((snap[0]["id"], snap[0]["available"], snap[0]["important"]), ("firefox", "130", True))
        self.assertEqual(updates.parse_choco("x|1|1|false\n"), [])

    def test_important_is_the_fixed_rule(self):
        self.assertTrue(updates.important("winget", "Git.Git")[0])
        self.assertTrue(updates.important("winget", "Vendor.Runtime", "Microsoft Build of OpenJDK")[0])
        self.assertTrue(updates.important("apt", "cowsay", security=True)[0])
        self.assertFalse(updates.important("winget", "Studio.PlainGame", "Plain Game")[0])


class PolicyTests(unittest.TestCase):
    def test_unknown_mode_falls_back_to_notify(self):
        self.assertEqual(updates.policy({"auto_update": "everything!"})["mode"], "notify")
        self.assertEqual(updates.policy({})["mode"], "notify")

    def test_only_unelevated_items_update_themselves(self):
        imp = updates.policy({"auto_update": "important", "auto_update_exclude": ["Vendor.Skip"]})
        every = updates.policy({"auto_update": "all"})
        user_git = item(scope="user")
        self.assertTrue(updates.auto_eligible(user_git, imp))
        self.assertFalse(updates.auto_eligible(item(scope="machine", needs_admin=True), imp))
        self.assertFalse(updates.auto_eligible(item("choco", "chocolatey", needs_admin=True), every))
        self.assertFalse(updates.auto_eligible(item("apt", "libssl3", security=True, needs_admin=True), every))
        self.assertFalse(updates.auto_eligible(item(pid="Vendor.Skip", name="git", scope="user"), imp))
        self.assertFalse(updates.auto_eligible(item("brew", "openssl@3", pinned=True, scope="user"), every))
        game = item(pid="Studio.PlainGame", name="Plain Game", scope="user")
        self.assertFalse(updates.auto_eligible(game, imp))
        self.assertTrue(updates.auto_eligible(game, every))
        self.assertFalse(updates.auto_eligible(user_git, updates.policy({"auto_update": "notify"})))


class FindingTests(unittest.TestCase):
    def test_unlisted_manager_is_visibility_and_coverage_partial(self):
        p = {"at": 0, "items": [item(scope="user")], "failed": {"choco": "PowerShell gave no answer"},
             "managers": ["winget"]}
        out = updates.findings(p, updates.policy({}))
        self.assertIn("could not list updates from choco", [f["title"] for f in out])
        self.assertEqual(incidents.coverage_status(out), "partial")
        self.assertNotIn("every package manager reports nothing outdated", [f["title"] for f in out])

    def test_security_items_raise_severity_and_name_the_owner_command(self):
        p = {"at": 0, "items": [item("apt", "libssl3", security=True, needs_admin=True)], "failed": {},
             "managers": ["apt"]}
        [f] = updates.findings(p, updates.policy({"auto_update": "important"}))
        self.assertEqual(f["severity"], "high")
        self.assertIn("jarvis update apply", f["detail"])
        self.assertEqual(categories.of_finding(f, "updates"), "updates")


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.log = os.path.join(self._tmp.name, "u", "log.jsonl")

    def test_commands_never_remove_and_refuse_unsafe_ids(self):
        kind, argv = updater.command(item("apt", "libssl3"))
        self.assertEqual((kind, argv[:3]), ("linux", ["apt-get", "install", "--only-upgrade"]))
        kind, script = updater.command(item(scope="user"))
        self.assertIn("winget upgrade --id 'Git.Git' --exact --silent", script)
        self.assertIn("--scope user", script)
        with self.assertRaises(ValueError):
            updater.command(item(pid="Evil'; Remove-Item C:\\ -Recurse"))
        with self.assertRaises(ValueError):
            updater.revert_command({"manager": "brew", "id": "x", "from": "1"})
        kind, script = updater.revert_command({"manager": "winget", "id": "Git.Git", "from": "2.53.0"})
        self.assertIn("--version '2.53.0'", script)

    def test_verified_only_by_a_fresh_listing(self):
        a, b, c = item(pid="A", installed="1"), item(pid="B", installed="1"), item("brew", "C", installed="1")
        fresh = {"items": [item(pid="B", installed="1")], "failed": {"brew": "did not run"},
                 "managers": ["winget"]}
        got = updater.verify([a, b, c], fresh)
        self.assertEqual(got[("winget", "A")][0], True)       # gone from the listing
        self.assertEqual(got[("winget", "B")][0], False)      # still at the old version
        self.assertEqual(got[("brew", "C")][0], False)        # unreadable: not verified

    def test_apply_logs_owner_only_with_before_and_after(self):
        items = [item(pid="A", installed="1", available="2"), item(pid="B", installed="1", available="2")]
        runners = {"ps": lambda script, timeout: (0, "ok") if "'A'" in script else (1, "installer failed")}
        fresh = {"items": [item(pid="B", installed="1")], "failed": {}, "managers": ["winget"]}
        res = updater.apply(items, "owner", runners=runners, plan_fn=lambda: fresh, log_path=self.log)
        rows = {r["id"]: r for r in res["results"]}
        self.assertTrue(rows["A"]["verified"])
        self.assertFalse(rows["B"]["verified"])
        self.assertEqual(rows["B"]["error"], "installer failed")
        self.assertEqual(stat.S_IMODE(os.stat(self.log).st_mode), 0o600)
        logged = updater.read_log(self.log)
        self.assertEqual([(r["id"], r["from"], r["to"], r["actor"]) for r in logged],
                         [("A", "1", "2", "owner"), ("B", "1", "2", "owner")])


class FakeStore:
    def __init__(self):
        self.meta = {}
        self.path = ""

    def get_meta(self, k, d=None):
        return self.meta.get(k, d)

    def set_meta(self, k, v):
        self.meta[k] = v


class AutoTests(unittest.TestCase):
    def test_budget_single_flight_and_no_automatic_retry_of_failures(self):
        store = FakeStore()
        calls = []

        def fake_apply(todo, actor):
            calls.append([i["id"] for i in todo])
            return {"finished_at": 1, "results": [
                {"manager": i["manager"], "id": i["id"], "name": i["name"], "at": 1000.0,
                 "verified": i["id"] != "P1"} for i in todo]}

        many = [item(pid=f"P{n}", scope="user") for n in range(updater.AUTO_PER_DAY + 5)]
        self.assertTrue(updater.start_auto(store, many, now=1000.0, apply_fn=fake_apply, background=False))
        self.assertEqual(len(calls[0]), updater.AUTO_PER_DAY)          # capped at the daily budget
        self.assertFalse(updater.start_auto(store, many, now=2000.0, apply_fn=fake_apply, background=False))
        self.assertFalse(updater._lock.locked())

    def test_a_failed_item_waits_a_day_while_budget_remains(self):
        store = FakeStore()
        calls = []

        def fake_apply(todo, actor):
            calls.append([i["id"] for i in todo])
            return {"finished_at": 1, "results": [
                {"manager": i["manager"], "id": i["id"], "name": i["name"], "at": 1000.0,
                 "verified": i["id"] != "P1"} for i in todo]}

        first = [item(pid=p, scope="user") for p in ("P0", "P1", "P2")]
        self.assertTrue(updater.start_auto(store, first, now=1000.0, apply_fn=fake_apply, background=False))
        # Six hours later the next job run lists P1 (still outdated) and a new P3.
        later = [item(pid="P1", scope="user"), item(pid="P3", scope="user")]
        self.assertTrue(updater.start_auto(store, later, now=1000.0 + 6 * 3600, apply_fn=fake_apply,
                                           background=False))
        self.assertEqual(calls[1], ["P3"])
        # A third run the same day still remembers P1's failure (not only the last run's results).
        self.assertTrue(updater.start_auto(store, [item(pid="P1", scope="user"), item(pid="P4", scope="user")],
                                           now=1000.0 + 12 * 3600, apply_fn=fake_apply, background=False))
        self.assertEqual(calls[2], ["P4"])
        calls.pop()
        # A day after the failure it may be tried again.
        self.assertTrue(updater.start_auto(store, [item(pid="P1", scope="user")], now=1000.0 + 86401,
                                           apply_fn=fake_apply, background=False))
        self.assertEqual(calls[2], ["P1"])

    def test_the_job_starts_auto_only_when_opted_in(self):
        store = FakeStore()
        p = {"at": 0, "items": [item(scope="user")], "failed": {}, "managers": ["winget"]}
        started = []
        for mode, expect in (("notify", 0), ("important", 1)):
            updates.audit(store, plan_fn=lambda: p, conf={"auto_update": mode},
                          start_auto=lambda s, e, now=None: started.append(e), notify=lambda *a: None)
            self.assertEqual(len(started), expect, mode)


class NotifyTests(unittest.TestCase):
    def test_new_important_updates_notify_once_with_the_updates_category(self):
        store, sent = FakeStore(), []
        p = {"at": 0, "items": [item(scope="user")], "failed": {}, "managers": ["winget"]}
        conf = {"ntfy_url": "https://ntfy.example/x"}
        deliver = lambda conf, subject, text, category=None: sent.append((subject, category)) or ""  # noqa: E731
        pol = updates.policy(conf)
        self.assertTrue(updates.notify_owner(store, conf, p, pol, 1000.0, deliver=deliver))
        self.assertFalse(updates.notify_owner(store, conf, p, pol, 1000.0 + 13 * 3600, deliver=deliver))
        self.assertEqual(sent[0][1], "updates")
        self.assertFalse(updates.notify_owner(store, {**conf, "notify_updates": False},
                                              {**p, "items": [item(pid="New.App", name="firefox")]},
                                              pol, 1e9, deliver=deliver))


class CategoryTests(unittest.TestCase):
    def test_classifier_and_precedence(self):
        self.assertEqual(categories.of_finding({"category": "collectors"}), "monitoring")
        self.assertEqual(categories.of_finding({"category": "daemon"}), "system")
        self.assertEqual(categories.of_finding({"category": "intel"}), "monitoring")       # unscored upkeep
        self.assertEqual(categories.of_finding({"category": "auditd"}, "auditd"), "exposure")  # scored hardening
        self.assertEqual(categories.of_finding({"category": "patches"}), "updates")
        self.assertEqual(categories.of_finding({"category": "persistence"}, "hidden"), "threat")
        self.assertEqual(categories.of_finding({"category": "posture"}, "posture"), "exposure")
        self.assertEqual(categories.dominant(["updates", "monitoring", "threat"]), "threat")
        self.assertEqual(categories.dominant([]), "exposure")

    def test_every_channel_carries_the_category(self):
        conf = {"webhook_url": "https://hook.example/x", "ntfy_url": "https://ntfy.example/t"}
        seen = {}

        def post(url, body, headers, label=""):
            seen[label or url] = (body, headers)
            return ""

        with mock.patch.object(alert, "_post", side_effect=post), \
             mock.patch.object(alert, "channels", return_value=["webhook", "ntfy"]):
            err = alert.deliver(conf, "[ARGUS-INSTINCT] 3 important update(s) available", "text",
                                category="updates", severity="medium")
        self.assertEqual(err, "")
        bodies = {k: v for k, v in seen.items()}
        hook = [json.loads(b) for b, _h in bodies.values() if b[:1] == b"{"][0]
        self.assertEqual((hook["category"], hook["category_label"], hook["priority"]),
                         ("updates", "Updates", "medium"))
        ntfy = [h for b, h in bodies.values() if "Tags" in h][0]
        self.assertIn("updates", ntfy["Tags"])
        self.assertTrue(ntfy["Title"].startswith("[Updates]"))

    def test_phone_payload_has_category_and_unknown_is_system(self):
        from jarvis.response.notify import channel
        p = channel.payload("t", "b", "high", "h", 1, category="monitoring", counts={"monitoring": 2, "x": 9})
        self.assertEqual((p["category"], p["category_label"], p["counts"]), ("monitoring", "Not being checked",
                                                                             {"monitoring": 2}))
        self.assertEqual(channel.payload("t", "b", "high", "h", 1, category="bogus")["category"], "system")
        self.assertEqual(channel.payload("t", "b", "ok", "h", 1, kind="test")["category"], "test")


if __name__ == "__main__":
    unittest.main()
