"""Trust and clarity: plain-language findings, honest status wording, approvals, notifications, reports.

Runs the page's own pure helpers in node (see test_dashboard_shell.run_node) and checks the markup and
styles that carry the safety behaviour. No test here changes anything on the machine.
"""

import json
import re
import unittest

from tests.test_dashboard_shell import F_CRIT, HTML, NODE, SHELL_CSS, VIEWS, det, model, run_node

CSS = SHELL_CSS.read_text(encoding="utf-8")
SECRET = "sk-" + "Zq7Wx8Er" * 4


def F(**kw):
    base = {"job": "control", "category": "persistence", "severity": "high", "title": "scheduled task",
            "detail": "ARGUS input hook -> conhost.exe", "where": "C:/Windows/System32/Tasks/x", "host": "win", "id": "ab12cd34"}
    return {**base, **kw}


def lot(n, **kw):
    return [F(title=f"item {i}", where=f"w{i}", id=f"{i:08x}", **kw) for i in range(n)]


@unittest.skipUnless(NODE, "node is not installed")
class OverviewHonestyTests(unittest.TestCase):
    def m(self, state):
        return run_node("overviewModel(%s, 1000)" % json.dumps(state))

    def test_serious_is_counted_apart_from_the_total(self):
        findings = lot(4, severity="high") + lot(2, severity="medium", category="rules")
        for i, f in enumerate(findings):
            f["title"] = f"t{i}"
        out = self.m(model(findings=findings, healthy=3))
        self.assertEqual((out["counts"]["total"], out["counts"]["serious"], out["counts"]["toReview"]), (6, 4, 6))
        self.assertIn("found 6 items to review, including 4 marked as serious", out["detail"])
        self.assertIn("Some items may have legitimate explanations", out["detail"])
        self.assertNotIn("6 marked as serious", out["detail"])
        self.assertEqual(out["headline"], "Needs attention")

    def test_informational_items_are_neither_serious_nor_items_to_review(self):
        info = [F(title=f"info {i}", severity="low", category="history", where=f"w{i}") for i in range(30)]
        out = self.m(model(findings=info + [F(title="s", severity="critical")], healthy=3))
        self.assertEqual((out["counts"]["toReview"], out["counts"]["serious"], out["counts"]["info"]), (1, 1, 30))
        self.assertIn("30 informational observations", out["detail"])

    def test_medium_only_is_review_recommended_not_needs_attention(self):
        out = self.m(model(findings=[F(severity="medium", category="rules")], healthy=3))
        self.assertEqual((out["level"], out["headline"]), ("review", "Review recommended"))

    def test_no_state_uses_reassuring_words_unless_everything_reports(self):
        banned = re.compile(r"your computer is safe|all clear|you are (safe|protected|secure)", re.I)
        states = [model(healthy=4), model(detectors=[det("failing")], healthy=3), model(findings=[F_CRIT], healthy=2),
                  model(detectors=[det("never_ran")], healthy=3, score=99), model(findings=[F(severity="medium", category="rules")], healthy=1),
                  {"security": None, "findings": [], "jobs": [], "questions": [], "checks": []}]
        for st in states:
            out = self.m(st)
            for text in (out["headline"], out["detail"], out["monLine"], out["lastLine"], out["scoreLine"]):
                self.assertIsNone(banned.search(text), text)
            if out["level"] == "ok":
                self.assertEqual(out["totals"]["blind"] + out["totals"]["partial"], 0)

    def test_changes_sentence_appears_only_when_the_server_supplied_it(self):
        none = self.m(model(findings=[F_CRIT], healthy=3))
        self.assertNotIn("No changes have been made", none["detail"])
        st = model(findings=[F_CRIT], healthy=3)
        st["assistant"] = {"changes": {"text": "No changes have been made to your computer by ARGUS-INSTINCT."}, "pending": [], "audit": []}
        self.assertTrue(self.m(st)["detail"].endswith("No changes have been made to your computer by ARGUS-INSTINCT."))
        st["assistant"]["changes"]["text"] = "ARGUS-INSTINCT has applied 2 automatic response actions."
        self.assertIn("applied 2 automatic", self.m(st)["detail"])
        self.assertNotIn("No changes have been made", self.m(st)["detail"])

    def test_last_check_time_and_staleness_are_stated(self):
        fresh = model(healthy=2)
        for d in fresh["detector_health"]["detectors"]:
            d["last_success"] = 990
        self.assertIn("10 seconds ago", self.m(fresh)["lastLine"])
        self.assertFalse(self.m(fresh)["last"]["stale"])
        old = model(healthy=2)
        for d in old["detector_health"]["detectors"]:
            d["last_success"] = 1000 - 7200
        out = self.m(old)
        self.assertTrue(out["last"]["stale"])
        self.assertIn("2 hours ago", out["lastLine"])
        self.assertIn("out of date", out["lastLine"])
        self.assertIn("No check has completed yet", self.m(model(detectors=[det("never_ran")]))["lastLine"])

    def test_the_counts_on_screen_agree_with_the_sentence_beside_them(self):
        # The tile and the sentence must count the same thing: checks that are not reporting.
        dets = [dict(det("failing", f"C{i}"), id=f"c{i}") for i in range(3)]
        mon = [F(job="watchdogs", category="daemon", severity="high", title=f"monitor {i}", where=f"w{i}") for i in range(5)]
        out = self.m(model(findings=[F_CRIT] + mon, detectors=dets, healthy=4))
        self.assertEqual(out["counts"]["notReporting"], 3)
        self.assertEqual(out["counts"]["monitoringFindings"], 5)
        self.assertIn("3 checks are also not reporting", out["detail"])
        self.assertEqual(out["counts"]["notReporting"], len(out["problems"]))

    def test_the_explanation_is_split_into_short_paragraphs_that_join_to_the_full_text(self):
        out = self.m(model(findings=[F_CRIT], detectors=[det("failing")], healthy=3))
        self.assertGreaterEqual(len(out["parts"]), 2)
        self.assertEqual(" ".join(out["parts"]), out["detail"])
        self.assertTrue(all(len(p) < 330 for p in out["parts"]))

    def test_monitoring_status_distinguishes_working_partial_and_down(self):
        self.assertEqual(self.m(model(healthy=3))["monitoring"], "working")
        self.assertEqual(self.m(model(detectors=[det("failing")], healthy=2))["monitoring"], "partial")
        down = self.m(model(detectors=[det("failing"), det("never_ran", "B")]))
        self.assertEqual(down["monitoring"], "down")
        self.assertIn("not working", down["monLine"])


@unittest.skipUnless(NODE, "node is not installed")
class FindingExplanationTests(unittest.TestCase):
    def ex(self, f, others=()):
        return run_node("explainFinding(%s, %s)" % (json.dumps(f), json.dumps(list(others))))

    def test_every_part_is_present_and_in_plain_language(self):
        e = self.ex(F())
        self.assertEqual(e["what"], "ARGUS-INSTINCT found a program that is set to run by itself at certain times.")
        self.assertIn("System32", e["where"])
        for key in ("whyFlagged", "facts", "risks", "benign", "unknown", "confidence", "steps", "next"):
            self.assertTrue(e[key], key)
        self.assertGreaterEqual(len(e["benign"]), 1)
        self.assertEqual(e["severity"], "Serious")

    def test_a_persistence_item_is_not_called_malicious_and_unknowns_are_listed(self):
        e = self.ex(F())
        text = json.dumps(e).lower()
        for banned in ("is malware", "is malicious", "has been hacked", "you are infected"):
            self.assertNotIn(banned, text)
        self.assertIn("Whether you installed it yourself or expected it", e["unknown"])
        self.assertTrue(any("installed" in b or "maintenance" in b for b in e["benign"]))

    def test_a_missing_location_is_an_explicit_unknown_not_a_guess(self):
        e = self.ex(F(where=""))
        self.assertEqual(e["where"], "")
        self.assertTrue(any("did not save a location" in u for u in e["unknown"]))

    def test_confidence_is_never_a_number_and_is_kept_apart_from_severity(self):
        for sev in ("critical", "high", "medium", "low"):
            c = self.ex(F(severity=sev))["confidence"]
            self.assertEqual(c["level"], "unscored")
            self.assertNotRegex(c["text"], r"\d+\s*%")
            self.assertIn("cannot say how sure it is", c["text"])
            self.assertIn("how much harm it could do, not how likely", c["text"])

    def test_evidence_basis_counts_only_real_corroboration(self):
        alone = self.ex(F())["confidence"]
        self.assertEqual((alone["collectors"], alone["forensics"], alone["strength"]), (1, 0, "Only one sign"))
        other = F(job="intrusion")
        both = self.ex(F(), [F(), other])["confidence"]
        self.assertEqual(both["collectors"], 2)
        self.assertEqual(both["strength"], "More than one sign")
        self.assertIn("noticed by 2 checks", both["text"])
        self.assertEqual(self.ex(F(forensics=["a", "b"]))["confidence"]["forensics"], 2)

    def test_unknown_categories_fall_back_to_the_real_title_and_severity(self):
        e = self.ex(F(category="never-heard-of-it", title="odd thing", severity="medium"))
        self.assertIn("“odd thing”", e["what"])
        self.assertEqual(e["severity"], "Worth a look")
        self.assertTrue(e["benign"])

    def test_secrets_never_reach_the_explanation(self):
        e = self.ex(F(title="OpenAI API key in plaintext", category="data at rest", detail=f"token={SECRET}",
                      where=f"C:/dev/.env?key={SECRET}"))
        self.assertNotIn(SECRET, json.dumps(e))

    def test_monitoring_explanation_states_what_is_unavailable_and_what_that_does_not_prove(self):
        p = {"id": "scan", "label": "Processes & network", "what": "Processes & network", "state": "failing", "last": None,
             "next": "Re-run it.", "command": "scan", "affects": "Yes. The overall status is not reliable while this check is down."}
        e = run_node("explainMonitor(%s)" % json.dumps(p))
        self.assertEqual(e["working"], "No")
        self.assertIn("cannot confirm this area", e["unavailable"])
        self.assertIn("does not mean that nothing suspicious is happening", e["caution"])
        self.assertEqual(e["lastGood"], "never")
        self.assertIn("jarvis scan", " ".join(e["next"]))
        self.assertIn("overall status", e["affects"])
        unknown = run_node("explainMonitor(%s)" % json.dumps({**p, "affects": "", "command": ""}))
        self.assertIn("did not report", unknown["affects"])
        self.assertNotIn("jarvis ", " ".join(unknown["next"]))


@unittest.skipUnless(NODE, "node is not installed")
class ApprovalWordingTests(unittest.TestCase):
    DETAILS = {"title": "Re-run the “X” check once", "proposes": "Queue one extra run.", "why": "It never reported.",
               "target": {"kind": "collector", "id": "hunt", "label": "X"}, "expected": "A newer result.", "risks": "CPU for one audit.",
               "reversible": "Nothing to undo.", "if_nothing": "Nothing runs.", "elevated": "No elevated permissions.",
               "exact": "One read-only run.", "evidence": ["It never reported."], "confirm_label": "Approve: run “X” once",
               "token": "tok123", "expires_at": 2000}
    TEN = ("proposes", "why", "target", "expected", "risks", "reversible", "ifNothing", "elevated", "exact", "evidence")

    def test_an_assistant_proposal_carries_all_ten_things_a_person_needs(self):
        spec = run_node("approvalSpecFromDetails(%s)" % json.dumps(self.DETAILS))
        for key in self.TEN:
            self.assertTrue(spec[key], key)
        self.assertIn("hunt", spec["target"])
        self.assertTrue(spec["confirmLabel"].startswith("Approve:"))
        self.assertNotEqual(spec["confirmLabel"].strip().lower(), "ok")
        self.assertEqual(spec["token"], "tok123")

    def test_fix_proposals_state_that_nothing_is_applied_from_the_page(self):
        f = {"id": "fx-0123abcd", "title": "Fix the thing", "problem": "A check fails", "status": "proposed", "directive_objective": "repair"}
        approve = run_node("approvalSpecForFix(%s, 'approve')" % json.dumps(f))
        authorize = run_node("approvalSpecForFix(%s, 'authorize')" % json.dumps(f))
        for spec in (approve, authorize):
            for key in self.TEN:
                self.assertTrue(spec[key], key)
            self.assertIn("14 days", spec["ifNothing"])
            self.assertIn("fx-0123abcd", spec["confirmLabel"])
        self.assertIn("applies no patch", approve["exact"])
        self.assertIn("No file is changed by this click", authorize["exact"])
        self.assertIn("jarvis fix apply fx-0123abcd", authorize["expected"])
        self.assertIn("rollback", authorize["reversible"])

    def test_lifecycle_never_says_fixed_or_resolved_and_completed_needs_a_result(self):
        states = run_node("Object.keys(LIFECYCLE).map(k => [k, lifecycleInfo(k)])")
        labels = {k: v for k, v in states}
        for k, v in labels.items():
            self.assertNotRegex(v["label"].lower(), r"fixed|resolved|safe")
        self.assertIn("fresh, valid result", labels["completed"]["note"])
        self.assertIn("not run yet", labels["approved_queued"]["note"])
        for k in ("cancelled", "expired", "denied", "already_used"):
            self.assertIn("Nothing was changed", labels[k]["note"] + "Nothing was changed")
        self.assertEqual(set(labels), {"awaiting_approval", "approved_queued", "completed", "failed", "cancelled", "expired",
                                       "denied", "already_used"})

    def test_fix_statuses_map_to_honest_labels(self):
        got = {s: run_node("fixStateOf(%s)" % json.dumps(s)) for s in ("proposed", "approved", "review", "draft_failed", "applied", "rejected", "expired", "weird")}
        self.assertEqual(got["proposed"]["key"], "awaiting_approval")
        self.assertEqual(got["approved"]["key"], "approved_queued")
        self.assertIn("authorization", got["review"]["label"])
        self.assertEqual(got["draft_failed"]["key"], "failed")
        self.assertIn("terminal", got["applied"]["label"])
        self.assertEqual(got["weird"]["key"], "denied")        # an unknown status is never presented as success

    def test_the_page_never_offers_a_one_click_fix_approval(self):
        # Approve/authorize must go through the confirmation; only reject and retry post directly.
        self.assertNotRegex(HTML, r"decideFix\('[^']*','approve'\)")
        self.assertNotRegex(HTML, r"decideFix\('[^']*','authorize'\)")
        self.assertIn('data-act="fixconfirm"', HTML)


class ApprovalMarkupTests(unittest.TestCase):
    def test_confirmation_is_a_native_modal_dialog_that_starts_on_the_safe_choice(self):
        self.assertRegex(HTML, r'<dialog id="approval"[^>]*aria-labelledby="ap-title"')
        self.assertIn("dlg.showModal()", HTML)
        self.assertIn('$("ap-return").focus();', HTML)
        order = [m.group(1) for m in re.finditer(r'data-ap="(\w+)"', HTML[HTML.index("function openApproval"):HTML.index("function closeApproval")])]
        self.assertEqual(order[:2], ["return", "review"])
        self.assertIn("Return without making changes", HTML)

    def test_dismissing_the_dialog_makes_no_request(self):
        block = HTML[HTML.index("function closeApproval"):HTML.index("async function approvalResult")]
        self.assertNotIn("fetch(", block)
        self.assertNotIn("postJSON(", block)
        self.assertRegex(HTML, r'\$\("approval"\)\.addEventListener\("cancel", \(\) => \{ approvalSpec = null; \}\)')

    def test_approve_is_not_the_visually_dominant_control(self):
        approve = re.search(r"\.apactions \.apapprove \{[^}]*\}", CSS).group(0)
        safe = re.search(r"\.apactions #ap-return \{[^}]*\}", CSS).group(0)
        self.assertNotIn("var(--accent)", approve)
        self.assertNotRegex(approve, r"background:\s*var\(--(accent|ok|crit)")
        self.assertIn("background: var(--accent)", safe)                  # the safe choice is the prominent one
        weight = lambda rule: int(re.search(r"font-weight:\s*(\d+)", rule).group(1))
        self.assertLess(weight(approve), weight(safe))

    def test_the_dialog_is_centred_despite_the_stylesheet_reset(self):
        # The Tailwind reset zeroes every margin, which pins an unstyled <dialog> to the top-left corner.
        self.assertRegex(CSS, r"\.approval \{ margin: auto;")

    def test_chat_proposals_are_decided_in_the_dialog_not_with_a_bare_button(self):
        self.assertIn("a.action === \"approve\" || a.action === \"cancel\"", HTML)
        self.assertIn("Review and decide", HTML)

    def test_every_backend_state_has_a_label(self):
        for key in ("awaiting_approval", "approved_queued", "completed", "failed", "cancelled", "expired"):
            self.assertIn(key + ":", HTML)


@unittest.skipUnless(NODE, "node is not installed")
class NotificationTests(unittest.TestCase):
    def derive(self, state, store=None, now=1000):
        return run_node("deriveNotifications(%s, %s, %d)" % (json.dumps(state), json.dumps(store or {"seen": {}, "items": [], "baseline": False}), now))

    def test_first_visit_records_what_exists_as_known_not_news(self):
        r = self.derive(model(findings=[F_CRIT], detectors=[det("failing")], healthy=2))
        self.assertEqual(r["fresh"], [])
        self.assertTrue(r["store"]["items"])
        for i in r["store"]["items"]:
            self.assertTrue(i["known"] and i["read"])

    def test_a_new_serious_finding_notifies_once_and_unchanged_state_stays_quiet(self):
        base = self.derive(model(healthy=3))["store"]
        r1 = self.derive(model(findings=[F_CRIT], healthy=3), base, 1100)
        self.assertEqual([f["type"] for f in r1["fresh"]], ["finding"])
        self.assertIn("It has not been confirmed as harmful", r1["fresh"][0]["text"])
        r2 = self.derive(model(findings=[F_CRIT], healthy=3), r1["store"], 1200)
        r3 = self.derive(model(findings=[F_CRIT], healthy=3), r2["store"], 1300)
        self.assertEqual((r2["fresh"], r3["fresh"]), ([], []))
        self.assertEqual(len([i for i in r3["store"]["items"] if i["type"] == "finding"]), 1)

    def test_a_resolved_finding_stays_in_history_and_is_not_announced_again_if_it_returns(self):
        base = self.derive(model(healthy=3))["store"]
        s1 = self.derive(model(findings=[F_CRIT], healthy=3), base, 1100)["store"]
        gone = self.derive(model(healthy=3), s1, 1200)["store"]
        self.assertFalse([i for i in gone["items"] if i["type"] == "finding"][0]["active"])
        back = self.derive(model(findings=[F_CRIT], healthy=3), gone, 1300)
        self.assertEqual(back["fresh"], [])

    def test_important_monitoring_failures_notify_individually_and_the_rest_are_summarised(self):
        base = self.derive(model(healthy=3))["store"]
        important = det("failing", "Core"); important["id"] = "core"; important["criticality"] = "high"
        minor = [dict(det("never_ran", f"m{i}"), id=f"m{i}", criticality="low") for i in range(4)]
        r = self.derive(model(detectors=[important] + minor, healthy=3), base, 1100)
        types = [(f["type"], f["important"] if "important" in f else False) for f in r["fresh"]]
        self.assertEqual(types.count(("monitoring", True)), 1)
        self.assertEqual(sum(1 for f in r["fresh"] if f["type"] == "monitoring"), 2)       # one important + one summary
        self.assertIn("4 other checks not reporting", " ".join(f["title"] for f in r["fresh"]))
        for f in r["fresh"]:
            if f.get("important"):
                self.assertIn("does not mean your computer has been attacked", f["text"])

    def test_proposals_needing_approval_are_always_unread_and_say_nothing_changed(self):
        st = model(healthy=3)
        st["assistant"] = {"pending": [{"token": "tok1", "title": "Re-run the “X” check once"}], "audit": [], "changes": None}
        first = self.derive(st)
        item = [i for i in first["store"]["items"] if i["type"] == "approval"][0]
        self.assertFalse(item["read"])
        self.assertIn("No change has been made", item["text"])
        self.assertEqual(item["link"]["act"], "openproposal")

    def test_results_come_from_the_audit_trail_and_claim_only_what_it_recorded(self):
        base = self.derive(model(healthy=3))["store"]
        st = model(healthy=3)
        st["assistant"] = {"pending": [], "changes": None, "audit": [
            {"ts": 5, "op": "approve", "action": "rerun_monitor", "outcome": "queued"},
            {"ts": 6, "op": "run", "action": "verify_monitor", "outcome": "verified"},
            {"ts": 7, "op": "approve", "action": "rerun_monitor", "outcome": "failed"},
            {"ts": 8, "op": "run", "action": "verify_monitor", "outcome": "not_verified"}]}
        texts = {f["key"]: f["text"] for f in self.derive(st, base, 2000)["fresh"]}
        self.assertEqual(len(texts), 3)                                   # not_verified is not an event
        queued = next(t for k, t in texts.items() if k.startswith("r:5"))
        self.assertIn("not confirmed until a fresh result", queued)
        self.assertNotRegex(queued.lower(), r"fixed|resolved|succeeded")
        self.assertIn("Confirmed by a fresh, valid result", next(t for k, t in texts.items() if k.startswith("r:6")))
        self.assertIn("nothing happened", next(t for k, t in texts.items() if k.startswith("r:7")))

    def test_a_result_notification_names_which_check_it_is_about(self):
        base = self.derive(model(healthy=3))["store"]
        st = model(healthy=3)
        st["jobs"] = [{"name": "hunt", "label": "Threat-intel indicator hunt"}]
        st["assistant"] = {"pending": [], "changes": None, "audit": [
            {"ts": 5, "op": "approve", "action": "rerun_monitor", "outcome": "queued", "target": {"job": "hunt"}},
            {"ts": 6, "op": "run", "action": "verify_monitor", "outcome": "verified", "target": {"job": "hunt"}},
            {"ts": 7, "op": "approve", "action": "rerun_monitor", "outcome": "failed", "target": {"job": "gone"}}]}
        titles = {f["key"][:3]: f["title"] for f in self.derive(st, base, 2000)["fresh"]}
        self.assertEqual(titles["r:5"], "Re-run of “Threat-intel indicator hunt”")
        self.assertEqual(titles["r:6"], "Verification of “Threat-intel indicator hunt”")
        self.assertEqual(titles["r:7"], "Re-run of a check")                # an unknown job is not guessed at

    def test_every_notification_links_to_a_real_destination(self):
        st = model(findings=[F_CRIT], detectors=[dict(det("failing"), criticality="high")], healthy=2)
        st["fix"] = [{"id": "fx-0123abcd", "title": "t", "status": "review", "generation_state": "done"}]
        st["assistant"] = {"pending": [{"token": "t", "title": "p"}], "audit": [], "changes": None}
        store = self.derive(model(healthy=2))["store"]
        for item in self.derive(st, store, 1100)["fresh"]:
            self.assertIn(item["link"]["go"], set(VIEWS) | {"reviewqueue"})

    def test_dismissal_rules_protect_serious_findings_and_important_failures(self):
        base = self.derive(model(healthy=3))["store"]
        important = dict(det("failing", "Core"), id="core", criticality="high")
        store = self.derive(model(findings=[F_CRIT], detectors=[important], healthy=2), base, 1100)["store"]
        out = run_node("(()=>{const s=%s; const keys=s.items.map(i=>[i.key,i.type,canDismiss(i)]);"
                       "const k=s.items.find(i=>i.type==='finding').key; const after=dismissNotification(s,k);"
                       "return {keys, still: visibleNotifications(after).some(i=>i.key===k)}})()" % json.dumps(store))
        by_type = {t: ok for _k, t, ok in out["keys"]}
        self.assertFalse(by_type["finding"])
        self.assertFalse(by_type["monitoring"])
        self.assertTrue(out["still"])                                      # dismissing a critical finding's notice does nothing
        minor = self.derive(model(findings=[F(severity="high", title="minor")], healthy=3), base, 1100)["store"]
        ok = run_node("(()=>{const s=%s; const k=s.items[0].key; const a=dismissNotification(s,k);"
                      "return {can: canDismiss(s.items[0]), hidden: !visibleNotifications(a).some(i=>i.key===k), unread: unreadCount(a)}})()" % json.dumps(minor))
        self.assertTrue(ok["can"] and ok["hidden"])

    def test_dismissing_a_notification_never_touches_the_finding_list(self):
        st = model(findings=[F_CRIT], healthy=3)
        before = json.dumps(st["findings"])
        store = self.derive(model(healthy=3))["store"]
        run_node("(()=>{const s=deriveNotifications(%s, %s, 1100).store; dismissNotification(s, s.items[0].key); markRead(s, null); return 1})()"
                 % (json.dumps(st), json.dumps(store)))
        self.assertEqual(json.dumps(st["findings"]), before)

    def test_read_state_and_unread_count(self):
        base = self.derive(model(healthy=3))["store"]
        s = self.derive(model(findings=[F_CRIT, F(title="two")], healthy=3), base, 1100)["store"]
        out = run_node("(()=>{const s=%s; const n=unreadCount(s); const one=markRead(s, s.items[0].key); const all=markRead(s, null);"
                       "return [n, unreadCount(one), unreadCount(all)]})()" % json.dumps(s))
        self.assertEqual(out, [2, 1, 0])

    def test_titles_stored_for_later_never_contain_a_secret(self):
        base = self.derive(model(healthy=3))["store"]
        f = F_CRIT | {"title": f"OpenAI key {SECRET} in plaintext"}
        r = self.derive(model(findings=[f], healthy=3), base, 1100)
        self.assertNotIn(SECRET, json.dumps(r))

    def test_the_history_is_bounded(self):
        store = {"seen": {}, "items": [], "baseline": True}
        for i in range(130):
            store = self.derive(model(findings=[F(title=f"t{i}", severity="high")], healthy=3), store, 1000 + i)["store"]
        self.assertLessEqual(len(store["items"]), 100)


class NotificationMarkupTests(unittest.TestCase):
    def test_bell_panel_and_live_region_are_wired_for_keyboard_and_screen_readers(self):
        self.assertRegex(HTML, r'<button id="bell"[^>]*aria-haspopup="dialog"[^>]*aria-expanded="false"[^>]*aria-controls="notifs"')
        self.assertRegex(HTML, r'<section id="notifs"[^>]*role="dialog"[^>]*aria-labelledby="notif-title"[^>]*hidden')
        self.assertIn('e.key === "Escape" && !$("notifs").hidden', HTML)
        self.assertIn('$("bell").focus()', HTML)                                       # focus returns to the bell
        self.assertIn('aria-live="polite"', HTML[HTML.index('id="toasts"') - 80:HTML.index('id="toasts"') + 80])

    def test_the_panel_says_what_notifications_can_and_cannot_do(self):
        self.assertIn("Pop-ups on this computer use the Notify me button and work only while this page is open", HTML)
        self.assertIn("Dismissing a notification never changes a finding", HTML)
        self.assertIn("ARGUS-INSTINCT has no background notifier", HTML)

    def test_critical_findings_are_not_announced_twice(self):
        self.assertIn('!(x.type === "finding" && x.sev === "critical")', HTML)

    def test_existing_os_notification_path_is_kept(self):
        for needle in ("function notifyCriticals", "new Notification(", 'id="notify"', "toggleNotify()"):
            self.assertIn(needle, HTML, needle)


class DetailLevelAndAccessibilityTests(unittest.TestCase):
    def test_simple_and_advanced_share_one_interface(self):
        self.assertRegex(HTML, r'<span class="segmented" id="detaillevel" role="group" aria-label="Level of detail">')
        self.assertIn('body[data-detail="simple"] .adv { display: none; }', CSS)
        self.assertIn('document.body.dataset.detail = detailLevel', HTML)
        self.assertIn('details class="tech" ${adv ? "open" : ""}', HTML)           # advanced opens the technical section
        self.assertEqual(HTML.count('id="detaillevel"'), 1)

    def test_the_preference_is_stored_in_the_same_way_as_the_theme_and_survives_missing_storage(self):
        self.assertIn('const DETAIL_KEY = "jarvis.detail"', HTML)
        for line in re.findall(r"localStorage\.(?:get|set)Item\(DETAIL_KEY[^\n]*", HTML):
            self.assertIn("try", HTML[HTML.index(line) - 80:HTML.index(line) + len(line)])

    def test_glossary_terms_are_keyboard_focusable_with_a_visible_definition(self):
        self.assertIn('class="gl" tabindex="0" role="note" data-def=', HTML)
        self.assertIn(".gl:hover::after, .gl:focus::after", CSS)
        self.assertIn(".gl:focus-visible", CSS)

    def test_severity_is_conveyed_with_words_and_not_colour_alone(self):
        self.assertIn("SEVERITY_WORDS", HTML)
        self.assertIn('${esc(ex.severity)}${adv ? ` (${esc(f.severity)})` : ""}', HTML)

    def test_motion_is_restrained_and_tooltips_do_not_animate(self):
        self.assertIn("prefers-reduced-motion", CSS)
        self.assertNotRegex(CSS, r"@keyframes\s+(?!beat)")

    def test_location_values_can_be_copied_and_the_copy_is_masked(self):
        self.assertIn('data-act="copy"', HTML)
        self.assertIn("copyBtn(redact(w), \"location\")", HTML)
        self.assertIn("navigator.clipboard.writeText", HTML)

    def test_the_finding_card_has_every_section_a_beginner_needs(self):
        for heading in ("What was found", "Where", "Why ARGUS-INSTINCT flagged it", "What it could mean", "How confident is ARGUS-INSTINCT?",
                        "What you can do", "Technical details", "Ordinary explanations", "Not known"):
            self.assertIn(heading, HTML, heading)

    def test_the_monitor_card_answers_the_five_monitoring_questions(self):
        for heading in ("What this check looks at", "Is it working?", "What is unavailable", "Does it affect the overall status?",
                        "What you can do"):
            self.assertIn(heading, HTML, heading)

    def test_marking_as_expected_is_only_described_where_the_product_supports_it(self):
        # `jarvis ack` exists in the terminal; the page has no dismiss-as-expected control, so it must not pretend to.
        self.assertIn("That is not available from this page", HTML)
        self.assertNotRegex(HTML, r'data-act="(ack|dismissfinding|markexpected)"')


@unittest.skipUnless(NODE, "node is not installed")
class ReportRenderingTests(unittest.TestCase):
    REPORT = {"title": "Check of X", "status": "complete", "read_only": True, "mode_label": "Read-only: nothing was changed",
              "checked": ["the stored result"], "found": ["it failed"], "meaning": ["maybe a permission problem"],
              "certainty": "Based on the stored result only.", "recommendation": ["Re-run it."],
              "not_done": ["Nothing on this computer was changed."], "technical": ""}

    def test_sections_come_in_the_fixed_order_with_the_fixed_headings(self):
        out = run_node("reportSections(%s).map(s => s.label)" % json.dumps(self.REPORT))
        self.assertEqual(out, ["What I checked", "What I found", "What this might mean", "How certain I am",
                               "What I recommend", "What I have not done"])

    def test_what_i_have_not_done_is_always_shown_and_secrets_are_masked(self):
        r = {**self.REPORT, "found": [f"saw token={SECRET}"]}
        out = run_node("reportSections(%s)" % json.dumps(r))
        self.assertEqual(out[-1]["key"], "not_done")
        self.assertNotIn(SECRET, json.dumps(out))

    def test_the_page_labels_reports_read_only_and_incomplete(self):
        self.assertIn("r.mode_label", HTML)
        self.assertIn("Technical evidence", HTML)


if __name__ == "__main__":
    unittest.main()
