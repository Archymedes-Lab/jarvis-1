"""The application shell: sidebar navigation, views, and the plain-language layer.

Three kinds of check:
  * markup: the sidebar, view headings, skip link and drawer controls exist and
    every destination the page links to resolves;
  * behaviour: the pure helpers in the page's `plain:begin/plain:end` block are
    executed in node against fixtures (masking, classification, the Overview's
    status wording and its refusal to look healthy while monitoring is partial);
  * wiring: /api/state carries the finding ids the "Explain simply" button needs.

Fixtures never contain real credentials; secret-shaped strings are assembled at
run time from fragments.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from jarvis.core.store import Store
from jarvis.response import acknowledge
from jarvis.service.scheduler import Scheduler
from jarvis.web.server import build_state

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "jarvis" / "web" / "static" / "dashboard.html"
SHELL_CSS = ROOT / "jarvis" / "web" / "styles" / "shell.css"
# The page and its script (no inline script under the CSP): tests read both.
SCRIPT = ROOT / "jarvis" / "web" / "static" / "dashboard.js"
HTML = PAGE.read_text(encoding="utf-8") + "\n" + SCRIPT.read_text(encoding="utf-8")
VIEWS = ("overview", "security", "accounts", "network", "monitoring", "assistant", "pricing", "settings")
NODE = shutil.which("node")


def plain_block():
    m = re.search(r"// plain:begin.*?// plain:end", HTML, re.S)
    assert m, "plain block missing"
    return m.group(0)


def run_node(expr):
    """Evaluate a JS expression with the page's plain helpers in scope; -> parsed JSON."""
    prog = plain_block() + "\nconsole.log(JSON.stringify((" + expr + ")));"
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
        fh.write(prog)
    try:
        r = subprocess.run([NODE, fh.name], capture_output=True, text=True, encoding="utf-8")
    finally:
        os.unlink(fh.name)
    assert r.returncode == 0, r.stderr[:500]
    return json.loads(r.stdout)


class SidebarMarkupTests(unittest.TestCase):
    def test_nine_destinations_each_with_an_icon_and_a_text_label(self):
        nav = re.search(r'<nav id="sidenav".*?</nav>', HTML, re.S).group(0)
        links = re.findall(r"<a [^>]*>.*?</a>", nav, re.S)
        labels = [re.sub(r"<[^>]+>", "", a).strip() for a in links]
        self.assertEqual(labels, ["Overview", "Security", "Processes", "Accounts", "Network",
                                  "Monitoring", "Assistant", "Pricing", "Settings"])
        for a in links:
            self.assertIn('<svg class="ico" aria-hidden="true">', a)          # icon, hidden from readers
            self.assertRegex(a, r'title="[^"]{8,}"')                          # tooltip with a description

    def test_existing_pages_stay_reachable(self):
        for href in ("/procs", "/coverage", "/geo"):
            self.assertIn(f'href="{href}"', HTML)

    def test_landmarks_skip_link_and_drawer_controls(self):
        self.assertIn('<a class="skip" href="#main">', HTML)
        self.assertIn('<main id="main" tabindex="-1">', HTML)
        self.assertIn('aria-label="Main navigation"', HTML)
        self.assertRegex(HTML, r'<button id="menu"[^>]*aria-controls="sidebar"[^>]*aria-expanded="false"[^>]*aria-label="[^"]+"')
        self.assertIn("aria-current", HTML)
        self.assertIn(".inert = true", HTML)                                   # page behind an open drawer is inert
        self.assertIn('e.key === "Escape"', HTML)

    def test_every_view_has_one_heading_a_nav_entry_and_a_title(self):
        for v in VIEWS:
            self.assertEqual(HTML.count(f'id="h-{v}"'), 1, v)
            self.assertIn(f'data-view="{v}"', HTML, v)
            self.assertIn(f'data-views="{v}', HTML.replace('data-views="', 'data-views="'), v)
            self.assertIn(f'{v}: "', HTML.split("const VIEWS =")[1].split("};")[0], v)

    def test_every_data_views_value_is_a_known_view(self):
        for attr in re.findall(r'data-views="([^"]+)"', HTML):
            for v in attr.split():
                self.assertIn(v, VIEWS, attr)

    def test_every_in_page_link_target_resolves(self):
        ids = set(re.findall(r'\bid="([^"]+)"', HTML))
        legacy = set(re.findall(r'"?([\w-]+)"?: "', re.search(r"const LEGACY = \{(.*?)\};", HTML, re.S).group(1)))
        targets = set(re.findall(r"jump\('([\w-]+)'\)", HTML)) | set(re.findall(r'data-go="([\w-]+)"', HTML)) \
            | {h for h in re.findall(r'href="#([\w-]+)"', HTML)}
        targets |= {"how-score", "reviewqueue", "monitoring", "security", "assistant"}
        for t in targets:
            self.assertTrue(t in ids or t in legacy or t in VIEWS, f"dead link target: {t}")

    def test_first_load_does_not_steal_keyboard_focus(self):
        # Moving focus to the heading on load made the first Tab skip the sidebar.
        self.assertIn("routeFromHash(true);", HTML)
        self.assertIn("focus: initial !== true", HTML)

    def test_old_anchors_keep_working_through_the_legacy_map(self):
        legacy = re.search(r"const LEGACY = \{(.*?)\};", HTML, re.S).group(1)
        for old in ("priorities", "findings-section", "reviewqueue", "more"):
            self.assertIn(old, legacy)

    def test_existing_controls_are_preserved(self):
        for needle in ('id="q"', 'id="notify"', 'id="pause"', 'id="theme"', 'data-t="light"', 'data-t="dark"',
                       'data-t="auto"', 'id="alertbar"', 'id="beat"', 'id="livetxt"', 'data-click="notify"',
                       'data-click="pause"'):
            self.assertIn(needle, HTML, needle)

    def test_no_new_external_origins_or_telemetry(self):
        self.assertEqual(re.findall(r'(?:src|href)\s*=\s*["\'](?:https?:)?//', HTML), [])
        body = HTML[HTML.index("// plain:begin"):]
        self.assertEqual(re.findall(r"fetch\(\s*[\"'`]https?:", body), [])


class StyleTests(unittest.TestCase):
    css = SHELL_CSS.read_text(encoding="utf-8")

    def test_shell_css_is_appended_verbatim_to_the_single_compiled_stylesheet(self):
        block = re.search(r'<style id="ui">(.*?)</style>', HTML, re.S).group(1)
        self.assertIn("/* shell.css: plain CSS appended by build_ui.sh */", block)
        self.assertTrue(block.rstrip().endswith(self.css.strip()), "rebuild: scripts/dev/build_ui.sh")
        self.assertEqual(HTML.count("<style"), 1)

    def test_focus_hover_current_and_reduced_motion_states_exist(self):
        for needle in (".sidebar a:focus-visible", ".sidebar a:hover", '.sidebar a[aria-current="page"]',
                       "prefers-reduced-motion"):
            self.assertIn(needle, self.css, needle)

    def test_sidebar_is_persistent_on_desktop_and_a_drawer_when_narrow(self):
        self.assertRegex(self.css, r"\.sidebar \{[^}]*position: fixed")
        narrow = self.css.split("@media (max-width: 1100px)")[1].split("@media")[0]
        self.assertIn(".sidebar { transform: translateX(-102%)", narrow)
        self.assertIn(".menu { display: inline-flex; }", narrow)
        self.assertRegex(self.css, r"\.menu \{ display: none;")

    def test_views_hide_what_is_not_theirs(self):
        for v in VIEWS:
            self.assertIn(f'body[data-view="{v}"] [data-views]:not([data-views~="{v}"])', self.css, v)

    def test_themes_use_existing_tokens_not_new_colour_systems(self):
        for token in ("var(--panel", "var(--fg)", "var(--crit", "var(--ok"):
            self.assertIn(token, self.css)


@unittest.skipUnless(NODE, "node is not installed")
class MaskingTests(unittest.TestCase):
    def secrets(self):
        return {"openai": "sk-" + "A1b2C3d4" * 4, "github": "ghp_" + "x9Y8w7V6" * 4, "aws": "AKIA" + "ABCD1234EFGH5678",
                "jwt": "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12,
                "slack": "xoxb-" + "1234567890-abcdef"}

    def test_known_secret_shapes_are_masked(self):
        for name, secret in self.secrets().items():
            out = run_node(f"redact({json.dumps('found ' + secret + ' in file')})")
            self.assertNotIn(secret, out, name)
            self.assertIn("[hidden]", out, name)

    def test_assignments_private_keys_and_url_credentials_are_masked(self):
        cases = {"password=hunter2hunter2": "hunter2hunter2", "api_key: 'abc123secretvalue'": "abc123secretvalue",
                 "DB_TOKEN=\"zzzz1111zzzz\"": "zzzz1111zzzz",
                 "postgres://admin:s3cretpass@db.local/x": "s3cretpass",
                 "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEabc\n-----END RSA " + "PRIVATE KEY-----": "MIIEabc",
                 "Authorization: Bearer abcdef1234567890": "abcdef1234567890"}
        for text, secret in cases.items():
            self.assertNotIn(secret, run_node(f"redact({json.dumps(text)})"), text)

    def test_ordinary_text_is_not_mangled(self):
        for text in ("OpenAI API key in plaintext", "recently written unsigned executable",
                     "WMI event subscription", "C:/Program Files/App/app.exe listening on 443"):
            self.assertEqual(run_node(f"redact({json.dumps(text)})"), text)

    def test_every_displayed_string_passes_through_the_mask(self):
        # esc() is the one door for untrusted text in innerHTML; it must mask.
        self.assertRegex(HTML, r"const esc = s => redact\(brand\(s\)\)")

    def test_a_secret_in_a_finding_never_reaches_the_plain_summary(self):
        secret = "sk-" + "Q7w8E9r0" * 4
        f = {"job": "secrets", "category": "data at rest", "severity": "critical", "title": "OpenAI API key in plaintext",
             "detail": "token=" + secret + " in C:/dev/.env", "where": "C:/dev/.env"}
        out = run_node("(()=>{const g=groupFindings([%s]); return clip(g[0].sample.detail, 200)})()" % json.dumps(f))
        self.assertNotIn(secret, out)


@unittest.skipUnless(NODE, "node is not installed")
class ClassificationTests(unittest.TestCase):
    def state(self, **f):
        base = {"job": "x", "category": "persistence", "severity": "high", "title": "t", "detail": "d"}
        return run_node("stateOf(%s).key" % json.dumps({**base, **f}))

    def test_monitoring_problems_are_not_security_findings(self):
        self.assertEqual(self.state(category="daemon", job="watchdogs", severity="high"), "monitoring")
        self.assertEqual(self.state(category="visibility", job="posture", severity="low"), "monitoring")

    def test_settings_read_directly_are_confirmed_and_behaviour_is_suspicious(self):
        self.assertEqual(self.state(category="rules", severity="medium"), "confirmed")
        self.assertEqual(self.state(category="persistence", severity="high"), "suspicious")
        self.assertEqual(self.state(category="injected code", severity="high"), "suspicious")

    def test_low_severity_is_information_never_alarm(self):
        self.assertEqual(self.state(category="persistence", severity="low"), "info")

    def test_nothing_is_ever_called_a_confirmed_attack(self):
        words = run_node("['critical','high','medium','low'].flatMap(s=>['persistence','rules','daemon','x']"
                         ".map(c=>stateOf({job:'j',category:c,severity:s}).label+' '+stateOf({job:'j',category:c,severity:s}).note))")
        for line in words:
            self.assertNotRegex(line.lower(), r"confirmed (attack|malware|compromise|intrusion)|you (are|have been) (hacked|attacked)")

    def test_unknown_categories_get_honest_generic_guidance(self):
        g = run_node("guideFor({job:'j',category:'never-heard-of-it',severity:'high',title:'x'})")
        self.assertTrue(g["general"])
        self.assertIn("thinks this is serious", g["why"])
        self.assertNotIn("attack", g["means"].lower())

    def test_duplicate_titles_collapse_with_a_count(self):
        out = run_node("groupFindings([{job:'a',title:'t',severity:'high'},{job:'a',title:'t',severity:'high'},"
                       "{job:'a',title:'u',severity:'critical'}]).map(g=>[g.sample.title,g.count])")
        self.assertEqual(out, [["u", 1], ["t", 2]])


def det(state, label="Check", coverage="blind", **kw):
    return {"id": label.lower(), "label": label, "state": state, "coverage": coverage,
            "reason": "r", "impact": "i", "next_action": "n", "error": "", **kw}


def model(findings=(), detectors=(), score=12, grade="at risk", **extra):
    ds = list(detectors)
    healthy = extra.pop("healthy", 0)
    ds += [det("healthy", f"ok{i}", "verified") for i in range(healthy)]
    verified = sum(1 for d in ds if d["state"] == "healthy")
    partial = sum(1 for d in ds if d["coverage"] == "partial" and d["state"] != "healthy")
    scored = [d for d in ds if d["state"] != "not_applicable"]
    return {"security": {"score": score, "grade": grade, **extra.pop("security", {})}, "findings": list(findings),
            "jobs": [], "questions": extra.pop("questions", []), "checks": [],
            "detector_health": {"detectors": ds, "total": len(scored),
                                "counts": {"verified": verified, "partial": partial,
                                           "blind": len(scored) - verified - partial}}}


F_CRIT = {"job": "control", "category": "persistence", "severity": "critical", "title": "WMI event subscription",
          "detail": "x", "where": "w", "host": "win", "id": "ab12cd34"}


@unittest.skipUnless(NODE, "node is not installed")
class OverviewStatusTests(unittest.TestCase):
    def m(self, state):
        return run_node("overviewModel(%s)" % json.dumps(state))

    def test_a_low_score_with_failing_checks_is_explained_not_called_protected(self):
        out = self.m(model(detectors=[det("failing", "Posture"), det("never_ran", "Memory")], healthy=3, score=12))
        self.assertEqual(out["level"], "incomplete")
        self.assertEqual(out["headline"], "Monitoring issue")
        self.assertNotIn("No issues found", out["headline"])
        self.assertIn("3 of 5 checks are reporting", out["detail"])
        self.assertIn("does not mean those areas are fine", out["detail"])
        self.assertIn("12%", out["scoreLine"])
        self.assertIn("not reporting", out["scoreLine"])

    def test_serious_findings_need_attention_and_are_not_called_confirmed_attacks(self):
        out = self.m(model(findings=[F_CRIT], detectors=[det("failing")], healthy=2))
        self.assertEqual(out["level"], "attention")
        self.assertIn("observations, not confirmed attacks", out["detail"])
        self.assertIn("also not reporting", out["detail"])

    def test_the_reassuring_headline_requires_every_check_to_be_reporting(self):
        ok = self.m(model(healthy=4, score=96, grade="secure"))
        self.assertEqual(ok["level"], "ok")
        self.assertIn("No issues found in the checks performed", ok["headline"])
        self.assertIn("only what ARGUS-INSTINCT can check", ok["detail"])
        for bad in ("never_ran", "stale", "failing", "malformed", "permission_restricted", "missing_dependency", "unsupported"):
            self.assertNotEqual(self.m(model(detectors=[det(bad)], healthy=9, score=99))["level"], "ok", bad)

    def test_partial_coverage_also_blocks_the_reassuring_headline(self):
        out = self.m(model(detectors=[det("late", coverage="partial")], healthy=5))
        self.assertEqual(out["level"], "incomplete")

    def test_not_applicable_checks_are_neither_failures_nor_successes(self):
        out = self.m(model(detectors=[det("not_applicable", "Linux only", "not_applicable")], healthy=3, score=90, grade="good"))
        self.assertEqual(out["level"], "ok")
        self.assertEqual(out["totals"]["total"], 3)
        self.assertEqual(out["totals"]["notApplicable"], 1)

    def test_no_data_says_so_instead_of_guessing(self):
        out = self.m({"security": None, "findings": [], "jobs": [], "questions": [], "checks": []})
        self.assertEqual(out["level"], "unknown")
        self.assertIn("not available", out["headline"])

    def test_rechecking_after_a_gap_keeps_the_last_verified_score_wording(self):
        out = self.m(model(healthy=1, security={"state": "verifying", "progress": {"checked": 2, "total": 9}}))
        self.assertEqual(out["level"], "info")
        self.assertIn("2 of 9", out["detail"])

    def test_kinds_are_counted_separately(self):
        rules = {"job": "firewall", "category": "rules", "severity": "medium", "title": "permissive inbound rule", "detail": "d"}
        info = {"job": "asep", "category": "history", "severity": "low", "title": "program launched", "detail": "d"}
        mon = {"job": "watchdogs", "category": "daemon", "severity": "high", "title": "monitor stopped", "detail": "d"}
        out = self.m(model(findings=[F_CRIT, rules, info, mon], detectors=[det("never_ran"), det("failing", "B")], healthy=1,
                           security={"acknowledged": 2}))
        c = out["counts"]
        self.assertEqual((c["suspicious"], c["confirmed"], c["expected"]), (1, 1, 2))
        self.assertEqual(c["monitoring"], 2 + 1)          # two detectors plus the monitoring finding
        self.assertEqual(c["unverified"], 1)               # only the check that never ran
        self.assertEqual(len(out["secGroups"]), 2)         # the low-severity item is not a "needs attention" row

    def test_monitoring_failures_are_never_counted_as_checked(self):
        out = self.m(model(detectors=[det("failing")], healthy=2))
        self.assertEqual(out["totals"]["verified"], 2)
        self.assertEqual(out["totals"]["blind"], 1)


@unittest.skipUnless(NODE, "node is not installed")
class AttentionAndNextStepTests(unittest.TestCase):
    def test_serious_findings_lead_then_monitoring_and_the_list_is_short(self):
        rules = [{"job": "firewall", "category": "rules", "severity": "medium", "title": f"rule {i}", "detail": "d"} for i in range(9)]
        out = run_node("(()=>{const a=attentionItems(%s,5); return {n:a.items.length,total:a.total,first:a.items[0].kind,"
                       "kinds:a.items.map(i=>i.kind)}})()" % json.dumps(model(findings=[F_CRIT] + rules, detectors=[det("failing")], healthy=1)))
        self.assertEqual(out["n"], 5)
        self.assertEqual(out["first"], "finding")
        self.assertIn("monitor", out["kinds"])
        self.assertGreater(out["total"], 5)

    def test_next_step_points_at_a_real_destination_in_every_situation(self):
        valid = set(VIEWS) | {"reviewqueue"}
        cases = [model(findings=[F_CRIT], healthy=2), model(detectors=[det("failing")], healthy=2),
                 model(healthy=3, questions=[{"id": 1}]), model(healthy=3)]
        for st in cases:
            step = run_node("nextStep(%s)" % json.dumps(st))
            self.assertIn(step["go"], valid, step)
            self.assertTrue(step["label"] and step["text"])

    def test_next_step_matches_the_situation(self):
        self.assertEqual(run_node("nextStep(%s)" % json.dumps(model(findings=[F_CRIT], healthy=2)))["go"], "security")
        mon = run_node("nextStep(%s)" % json.dumps(model(detectors=[det("failing")], healthy=2)))
        self.assertEqual(mon["go"], "monitoring")
        self.assertIn("Open Monitoring", mon["text"])
        self.assertEqual(run_node("nextStep(%s)" % json.dumps(model(healthy=3)))["go"], "assistant")

    def test_the_next_step_never_names_a_secret(self):
        secret = "sk-" + "Z1x2C3v4" * 4
        f = dict(F_CRIT, title=f"key {secret} exposed")
        self.assertNotIn(secret, run_node("nextStep(%s).text" % json.dumps(model(findings=[f], healthy=2))))

    def test_monitoring_problems_use_the_detector_reason_not_an_attack_claim(self):
        out = run_node("monitoringProblems(%s)" % json.dumps(model(detectors=[det("missing_dependency", "Sysmon")], healthy=1)))
        self.assertEqual(out[0]["state"], "missing_dependency")
        card = run_node("DETECTOR_WORDS['missing_dependency']")
        self.assertIn("missing", card)


class StateWiringTests(unittest.TestCase):
    def test_state_findings_carry_the_id_the_explain_button_sends(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "s.db")
            store = Store(path)
            finding = {"category": "persistence", "severity": "high", "title": "WMI event subscription",
                       "detail": "d", "where": "w", "host": "win"}
            store.save_snapshot("control", [finding], 0.1, "")
            store.close()
            sched = Scheduler(path, ("wsl",))
            state = build_state(path, sched)
        found = [f for f in state["findings"] if f["title"] == "WMI event subscription"]
        self.assertTrue(found)
        self.assertEqual(found[0]["id"], acknowledge.finding_id(finding, "control"))
        self.assertRegex(found[0]["id"], r"^[0-9a-f]{8}$")
        self.assertIn("detector_health", state)

    def test_state_carries_open_proposals_recent_activity_and_the_changes_summary(self):
        from jarvis.response import advisor
        from jarvis.service.schedule import JOBS
        job = next(iter(JOBS))
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "s.db")
            store = Store(path)
            store.save_snapshot(job, [], 0.1, "")
            advisor.handle_action(store, JOBS, "propose", "rerun_monitor", {"job": job}, runner=lambda j: True)
            store.close()
            state = build_state(path, Scheduler(path, ("wsl",)))
        a = state["assistant"]
        self.assertEqual(len(a["pending"]), 1)
        self.assertEqual(a["pending"][0]["target"]["id"], job)
        self.assertTrue(a["pending"][0]["token"])
        self.assertEqual([e["outcome"] for e in a["audit"]], ["proposed"])
        self.assertEqual(a["changes"]["assistant_executed"], 0)        # a proposal is not a change

    def test_state_without_any_assistant_activity_is_still_well_formed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "s.db")
            Store(path).close()
            state = build_state(path, Scheduler(path, ("wsl",)))
        self.assertEqual(state["assistant"]["pending"], [])
        self.assertEqual(state["assistant"]["audit"], [])
        self.assertIn("text", state["assistant"]["changes"] or {"text": ""})


if __name__ == "__main__":
    unittest.main()
