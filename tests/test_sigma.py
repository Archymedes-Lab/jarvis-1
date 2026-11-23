"""Community (Sigma) rules: exact evaluation, bounded input, per-install judgement.

Invariants under test
  1. Evaluation is exact for what is compiled: case-insensitive equals, contains,
     starts-with, ends-with, `*`, `all`, null, and / or / not, 1-of / all-of.
  2. What cannot be evaluated exactly is not compiled (never approximated).
  3. The candidate index never changes a result: indexed matching equals
     evaluating every rule.
  4. The rule file is validated and bounded; a bad file is an error, not "no rules".
  5. Every rule names an author, and every finding built from a rule carries it.
  6. Per-install judgement: shapes are learned only during the burn-in and are
     reported when learned; afterwards a new shape alerts and nothing is learned;
     without a store every match is returned; an unfinished pass says so.
  7. Severity from a community rule is never critical.
"""
import json
import os
import random
import tempfile
import unittest

from jarvis.collectors.telemetry import community, sysmon
from jarvis.core import sigma
from jarvis.core.store import Store

try:
    import yaml  # noqa: F401

    from scripts.security import sigma_compile
except ImportError:                                  # PyYAML is a development-only dependency
    sigma_compile = None

SRC = {"repo": "https://example.invalid/rules", "commit": "0" * 40, "license": "DRL"}


def rule(rid="r1", cat=sigma.WIN_PROC, level="high", author="Ann Author", sels=None, cond=None, tids=("T1059",)):
    sels = sels or {"selection": [[["cmdline", "contains", False, [["mimikatz"]]]]]}
    return {"id": rid, "title": f"Title {rid}", "level": level, "author": author, "tids": list(tids),
            "cat": cat, "sels": sels, "cond": cond or ["sel", next(iter(sels))]}


def parsed(*rules):
    return sigma.parse(json.dumps({"schema": sigma.SCHEMA, "source": SRC, "rules": list(rules)}).encode())


def one(sels, cond=None, cat=sigma.WIN_PROC):
    return parsed(rule(sels=sels, cond=cond, cat=cat))["rules"][cat][0]


def hit(r, **row):
    return bool(sigma.match([r], sigma.prepare(r.category, row)))


class Evaluation(unittest.TestCase):
    def test_operators_are_case_insensitive_and_anchored(self):
        img = "C:\\Windows\\System32\\PowerShell.exe"
        self.assertTrue(hit(one({"s": [[["image", "endswith", False, [["\\powershell.exe"]]]]]}), image=img))
        self.assertFalse(hit(one({"s": [[["image", "endswith", False, [["\\powershell"]]]]]}), image=img))
        self.assertTrue(hit(one({"s": [[["image", "startswith", False, [["c:\\windows\\"]]]]]}), image=img))
        self.assertFalse(hit(one({"s": [[["image", "startswith", False, [["windows\\"]]]]]}), image=img))
        self.assertTrue(hit(one({"s": [[["image", "eq", False, [[img.lower()]]]]]}), image=img))
        self.assertFalse(hit(one({"s": [[["image", "eq", False, [["powershell.exe"]]]]]}), image=img))

    def test_wildcard_segments_must_appear_in_order_without_overlap(self):
        r = one({"s": [[["cmdline", "contains", False, [["net", "user", "/add"]]]]]})
        self.assertTrue(hit(r, cmdline="net.exe user bob /add"))
        self.assertFalse(hit(r, cmdline="/add user net"))
        eq = one({"s": [[["cmdline", "eq", False, [["ab", "ba"]]]]]})          # ab*ba
        self.assertTrue(hit(eq, cmdline="abba"))
        self.assertFalse(hit(eq, cmdline="aba"))                              # the two ends may not share a letter
        self.assertFalse(hit(eq, cmdline="xabba"))

    def test_all_needs_every_value_and_any_needs_one(self):
        every = one({"s": [[["cmdline", "contains", True, [["-enc"], ["hidden"]]]]]})
        self.assertTrue(hit(every, cmdline="powershell -w HIDDEN -Enc AAAA"))
        self.assertFalse(hit(every, cmdline="powershell -enc AAAA"))
        some = one({"s": [[["cmdline", "contains", False, [["-enc"], ["hidden"]]]]]})
        self.assertTrue(hit(some, cmdline="powershell -enc AAAA"))

    def test_null_matches_only_an_absent_or_empty_field(self):
        r = one({"s": [[["parent_cmdline", "null", False, []]]]})
        self.assertTrue(hit(r, cmdline="x"))
        self.assertFalse(hit(r, cmdline="x", parent_cmdline="cmd.exe /c x"))

    def test_maps_are_alternatives_and_tests_in_a_map_are_all_required(self):
        r = one({"s": [[["image", "endswith", False, [["\\a.exe"]]], ["cmdline", "contains", False, [["x"]]]],
                       [["original_name", "eq", False, [["a.exe"]]]]]})
        self.assertTrue(hit(r, image="C:\\a.exe", cmdline="a x"))
        self.assertFalse(hit(r, image="C:\\a.exe", cmdline="a y"))
        self.assertTrue(hit(r, image="C:\\renamed.exe", cmdline="y", original_name="A.EXE"))

    def test_conditions(self):
        sels = {"a": [[["cmdline", "contains", False, [["aa"]]]]], "b": [[["cmdline", "contains", False, [["bb"]]]]],
                "f": [[["image", "endswith", False, [["\\ok.exe"]]]]]}
        self.assertTrue(hit(one(sels, ["and", ["sel", "a"], ["not", ["sel", "f"]]]), cmdline="aa", image="C:\\x.exe"))
        self.assertFalse(hit(one(sels, ["and", ["sel", "a"], ["not", ["sel", "f"]]]), cmdline="aa", image="C:\\ok.exe"))
        self.assertTrue(hit(one(sels, ["or", ["sel", "a"], ["sel", "b"]]), cmdline="bb"))
        self.assertTrue(hit(one(sels, ["any", ["a", "b"]]), cmdline="bb"))
        self.assertFalse(hit(one(sels, ["all", ["a", "b"]]), cmdline="bb"))
        self.assertTrue(hit(one(sels, ["all", ["a", "b"]]), cmdline="aa bb"))

    def test_a_rule_sees_only_its_categorys_fields_capped(self):
        event = sigma.prepare(sigma.WIN_PROC, {"cmdline": "A" * 9000, "secret": "x", "image": None})
        self.assertEqual(set(event), set(sigma.FIELDS[sigma.WIN_PROC].values()))
        self.assertEqual(len(event["cmdline"]), sigma.MAX_TEXT)
        self.assertEqual(event["image"], "")


class CandidateIndex(unittest.TestCase):
    """A rule the index cannot summarise by a literal is always evaluated."""

    def both(self, r, **row):
        event = sigma.prepare(r.category, row)
        return bool(sigma.match([r], event)), bool(sigma.Index([r]).match(event))

    def test_a_branch_without_a_literal_keeps_the_rule_a_candidate(self):
        sels = {"a": [[["cmdline", "contains", False, [["aaaa"]]]]], "b": [[["cmdline", "contains", False, [["bbbb"]]]]],
                "n": [[["parent_cmdline", "null", False, []]]]}
        cases = [
            (["or", ["sel", "a"], ["not", ["sel", "b"]]], {"cmdline": "zzzz"}),        # true through `not`
            (["or", ["sel", "a"], ["sel", "n"]], {"cmdline": "zzzz"}),                 # true through a null test
            (["any", ["a", "n"]], {"cmdline": "zzzz"}),
            (["not", ["sel", "a"]], {"cmdline": "zzzz"}),
            (["and", ["sel", "a"], ["not", ["sel", "b"]]], {"cmdline": "aaaa"}),
            (["all", ["a", "b"]], {"cmdline": "aaaa bbbb"}),
        ]
        for cond, row in cases:
            self.assertEqual(self.both(one(sels, cond), **row), (True, True), cond)

    def test_alternative_maps_where_one_has_no_literal(self):
        r = one({"s": [[["cmdline", "contains", False, [["aaaa"]]]], [["parent_cmdline", "null", False, []]]]})
        self.assertEqual(self.both(r, cmdline="zzzz"), (True, True))
        self.assertEqual(self.both(r, cmdline="zzzz", parent_cmdline="p"), (False, False))


class Validation(unittest.TestCase):
    def bad(self, **change):
        r = rule()
        r.update(change)
        with self.assertRaises(sigma.SigmaError):
            parsed(r)

    def test_malformed_rules_are_refused(self):
        self.bad(author="  ")                                   # the licence needs an author in every alert
        self.bad(level="informational")
        self.bad(cat="mac_proc")
        self.bad(cond=["sel", "missing"])
        self.bad(cond=["xor", ["sel", "selection"], ["sel", "selection"]])
        self.bad(sels={"selection": [[["user", "contains", False, [["x"]]]]]})          # not a recorded field
        self.bad(sels={"selection": [[["cmdline", "re", False, [["x"]]]]]})             # no regular expressions
        self.bad(sels={"selection": [[["cmdline", "contains", False, [["UPPER"]]]]]})   # stored lower-case
        self.bad(sels={"selection": [[["cmdline", "contains", False, [["x"]] * (sigma.MAX_VALUES + 1)]]]})
        self.bad(sels={"selection": [[["cmdline", "contains", False, [["x" * (sigma.MAX_SEGMENT + 1)]]]]]})
        self.bad(sels={"selection": [[["cmdline", "null", False, [["x"]]]]]})

    def test_condition_depth_is_bounded(self):
        cond = ["sel", "selection"]
        for _ in range(sigma.MAX_DEPTH + 2):
            cond = ["not", cond]
        self.bad(cond=cond)

    def test_file_level_refusals(self):
        for data in (b"", b"{not json", json.dumps({"schema": "other", "source": SRC, "rules": []}).encode(),
                     json.dumps({"schema": sigma.SCHEMA, "rules": []}).encode(),
                     json.dumps({"schema": sigma.SCHEMA, "source": SRC, "rules": [rule(), rule()]}).encode(),
                     b" " * (sigma.MAX_BYTES + 1)):
            with self.assertRaises(sigma.SigmaError):
                sigma.parse(data)

    def test_a_bad_file_is_an_error_and_a_missing_file_is_no_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "none.json")
            from pathlib import Path
            rules, source, error = sigma.load(Path(missing))
            self.assertEqual((sum(map(len, rules.values())), source, error), (0, None, ""))
            broken = Path(tmp) / "broken.json"
            broken.write_text("{")
            rules, source, error = sigma.load(broken)
            self.assertEqual(sum(map(len, rules.values())), 0)
            self.assertTrue(error)

    def test_severity_is_never_critical(self):
        self.assertNotIn("critical", sigma.LEVEL.values())
        self.assertEqual(one(None).severity, "medium")                      # level high
        self.assertEqual(parsed(rule(level="critical"))["rules"][sigma.WIN_PROC][0].severity, "high")


class Shipped(unittest.TestCase):
    """The rule file in the tree is the one the program accepts."""

    @classmethod
    def setUpClass(cls):
        cls.doc = sigma.parse(sigma.DATA.read_bytes())

    def test_it_validates_names_its_source_and_every_rule_has_an_author(self):
        self.assertRegex(self.doc["source"]["commit"], r"^[0-9a-f]{40}$")
        self.assertIn("SigmaHQ/sigma", self.doc["source"]["repo"])
        rules = [r for rs in self.doc["rules"].values() for r in rs]
        self.assertGreater(len(rules), 500)
        for r in rules:
            self.assertTrue(r.author.strip())
            self.assertIn(r.author, sigma.attribution(r))
            self.assertIn(sigma.LICENSE, sigma.attribution(r))

    def test_the_index_never_changes_a_result(self):
        rng = random.Random(20261110)
        for category, rules in self.doc["rules"].items():
            idx = sigma.Index(rules)
            literals = [seg for r in rules for maps in r.selections.values() for m in maps
                        for _f, _o, _e, values in m for v in values for seg in v if seg]
            fields = list(sigma.FIELDS[category].values())
            for _ in range(400):
                event = {f: "" for f in fields}
                for f in rng.sample(fields, k=rng.randint(1, len(fields))):
                    event[f] = " ".join(rng.choice(literals) for _ in range(rng.randint(1, 4)))
                want = sorted(r.id for r in sigma.match(rules, event))
                self.assertEqual(sorted(r.id for r in idx.match(event)), want)

    def test_a_known_attack_command_matches_and_an_ordinary_one_does_not(self):
        idx, error = sigma.index(sigma.WIN_PROC)
        self.assertEqual(error, "")
        bad = sigma.prepare(sigma.WIN_PROC, {"image": "C:\\Windows\\System32\\vssadmin.exe",
                                             "cmdline": "vssadmin.exe delete shadows /all /quiet",
                                             "parent": "C:\\Windows\\System32\\cmd.exe"})
        self.assertTrue(idx.match(bad))
        ok = sigma.prepare(sigma.WIN_PROC, {"image": "C:\\Windows\\System32\\notepad.exe",
                                            "cmdline": "notepad.exe notes.txt",
                                            "parent": "C:\\Windows\\explorer.exe"})
        self.assertEqual(idx.match(ok), [])


@unittest.skipIf(sigma_compile is None, "PyYAML (development only) is not installed")
class Compiler(unittest.TestCase):
    BASE = {"id": "11111111-1111-1111-1111-111111111111", "title": "T", "status": "test", "level": "high",
            "author": "Ann Author", "tags": ["attack.execution", "attack.t1059.001"],
            "logsource": {"category": "process_creation", "product": "windows"}}

    def compile(self, detection, **change):
        doc = dict(self.BASE, detection=detection, **change)
        return sigma_compile.compile_rule(doc, sigma.WIN_PROC)

    def run_rule(self, detection, **row):
        compiled = self.compile(detection)
        r = parsed(compiled)["rules"][sigma.WIN_PROC][0]
        return hit(r, **row)

    def test_a_typical_rule_means_what_its_source_means(self):
        det = {"selection_img": [{"Image|endswith": ["\\powershell.exe", "\\pwsh.exe"]},
                                 {"OriginalFileName": "PowerShell.EXE"}],
               "selection_cli": {"CommandLine|contains|all": ["-ComObject", "InstallProduct("]},
               "filter_main": {"ParentImage|endswith": "\\trusted.exe"},
               "condition": "all of selection_* and not 1 of filter_*"}
        self.assertEqual(self.compile(det)["tids"], ["T1059.001"])
        cmd = "powershell -c New-Object -ComObject X; $i.InstallProduct('u')"
        self.assertTrue(self.run_rule(det, image="C:\\x\\PWSH.exe", cmdline=cmd))
        self.assertTrue(self.run_rule(det, image="C:\\x\\r.exe", original_name="powershell.exe", cmdline=cmd))
        self.assertFalse(self.run_rule(det, image="C:\\x\\pwsh.exe", cmdline="powershell -ComObject X"))
        self.assertFalse(self.run_rule(det, image="C:\\x\\pwsh.exe", cmdline=cmd, parent="C:\\a\\trusted.exe"))

    def test_wildcards_escapes_and_dashes(self):
        self.assertEqual(sigma_compile.segments("a*b"), ["a", "b"])
        self.assertEqual(sigma_compile.segments("a\\*b"), ["a*b"])
        self.assertEqual(sigma_compile.segments("C:\\\\Temp\\x"), ["c:\\temp\\x"])
        self.assertEqual(sigma_compile.segments("\\powershell.exe"), ["\\powershell.exe"])
        det = {"selection": {"CommandLine|contains|windash": " -enc "}, "condition": "selection"}
        self.assertTrue(self.run_rule(det, cmdline="powershell /enc AAAA"))
        self.assertTrue(self.run_rule(det, cmdline="powershell -enc AAAA"))
        self.assertFalse(self.run_rule(det, cmdline="powershell enc AAAA"))
        # Sigma: a wildcard after a path separator is written `\\\\*` (an escaped backslash, then `*`);
        # `\\*` alone is a literal asterisk.
        star = {"selection": {"CommandLine": "*\\Users\\\\*\\evil.exe"}, "condition": "selection"}
        literal = {"selection": {"CommandLine|contains": "dir \\*"}, "condition": "selection"}
        self.assertTrue(self.run_rule(literal, cmdline="cmd /c dir *"))
        self.assertFalse(self.run_rule(literal, cmdline="cmd /c dir x"))
        self.assertTrue(self.run_rule(star, cmdline="C:\\Users\\bob\\evil.exe"))
        self.assertFalse(self.run_rule(star, cmdline="C:\\Users\\bob\\evil.exe --x"))

    def test_what_cannot_be_evaluated_exactly_is_left_out(self):
        cases = [
            ({"selection": {"CommandLine|re": "a.*b"}, "condition": "selection"}, {}),
            ({"selection": {"IntegrityLevel": "System"}, "condition": "selection"}, {}),
            ({"selection": ["mimikatz", "sekurlsa"], "condition": "selection"}, {}),
            ({"selection": {"CommandLine|contains": "a?b"}, "condition": "selection"}, {}),
            ({"selection": {"CommandLine|contains": "a"}, "condition": "selection | count() > 5"}, {}),
            ({"selection": {"CommandLine|contains": "a"}, "condition": "selection and missing"}, {}),
            ({"selection": {"CommandLine|contains": "a"}, "condition": "selection"}, {"status": "experimental"}),
            ({"selection": {"CommandLine|contains": "a"}, "condition": "selection"}, {"level": "low"}),
            ({"selection": {"CommandLine|contains": "a"}, "condition": "selection"}, {"author": ""}),
            ({"selection": {"CommandLine|contains": "a"}, "condition": "selection"},
             {"logsource": {"category": "process_creation", "product": "macos"}}),
        ]
        for detection, change in cases:
            with self.assertRaises(sigma_compile.Unsupported, msg=str((detection, change))):
                self.compile(detection, **change)

    def test_condition_grammar(self):
        names = ["selection_a", "selection_b", "filter_x"]
        c = sigma_compile.compile_condition
        self.assertEqual(c("1 of selection_* and not filter_x", names),
                         ["and", ["any", ["selection_a", "selection_b"]], ["not", ["sel", "filter_x"]]])
        self.assertEqual(c("selection_a or (selection_b and not 1 of filter_*)", names),
                         ["or", ["sel", "selection_a"], ["and", ["sel", "selection_b"], ["not", ["any", ["filter_x"]]]]])
        self.assertEqual(c("all of them", names), ["all", names])
        for bad in ("selection_a and", "(selection_a", "selection_a selection_b", "1 of nothing_*"):
            with self.assertRaises(sigma_compile.Unsupported):
                c(bad, names)


class Judgement(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.addCleanup(self.store.close)
        self.rule = one(None)

    def m(self, image="C:\\a\\tool.exe", parent="C:\\Windows\\explorer.exe", text="tool mimikatz"):
        return (self.rule, image, parent, "2026-11-10T12:00:00Z", text)

    def test_without_a_store_every_match_is_an_alert_and_nothing_is_learned(self):
        alerts, learned = community.judge(None, [self.m(), self.m()], now=1000)
        self.assertEqual((len(alerts), learned), (1, []))
        self.assertEqual(next(iter(alerts.values()))[3], 2)

    def test_burn_in_learns_and_reports_once_then_only_counts(self):
        alerts, learned = community.judge(self.store, [self.m()], now=1000)
        self.assertEqual((alerts, len(learned)), ({}, 1))
        alerts, learned = community.judge(self.store, [self.m()], now=2000)
        self.assertEqual((alerts, learned), ({}, []))

    def test_after_burn_in_a_new_shape_alerts_and_is_never_learned(self):
        community.judge(self.store, [self.m()], now=1000)
        later = 1000 + community.BURN_IN_S + 1
        new = self.m(parent="C:\\Users\\x\\dropper.exe")
        for _ in range(3):                                   # repeating it does not teach it
            alerts, learned = community.judge(self.store, [new], now=later)
            self.assertEqual((len(alerts), learned), (1, []))
        alerts, _ = community.judge(self.store, [self.m()], now=later)
        self.assertEqual(alerts, {})                         # the learned shape still only counts

    def test_the_shape_table_is_bounded(self):
        matches = [self.m(image=f"C:\\a\\t{i}.exe") for i in range(community.MAX_SHAPES + 5)]
        alerts, learned = community.judge(self.store, matches, now=1000)
        self.assertEqual((len(learned), len(alerts)), (community.MAX_SHAPES, 5))

    def test_a_corrupt_state_restarts_learning_visibly(self):
        self.store.set_meta(community.META, "{broken")
        alerts, learned = community.judge(self.store, [self.m()], now=1000)
        self.assertEqual((alerts, len(learned)), ({}, 1))    # reported as inventory again, not dropped


class Review(Judgement):
    """Learning demotes, it never hides: learned shapes stay listed until reviewed."""

    def passes(self, rows, now):
        make = lambda s, t, d, i: {"severity": s, "title": t, "detail": d}      # noqa: E731
        return community.findings(sigma.WIN_PROC, rows, lambda e: (e["image"], e["parent"], "", e["cmdline"]),
                                  make, store=self.store, now=now)

    ROW = {"image": "C:\\a\\tool.exe", "parent": "C:\\Windows\\explorer.exe", "cmdline": "tool mimikatz"}

    def test_a_learned_shape_is_a_standing_low_finding_until_reviewed(self):
        with self.swap_rules():
            first = self.passes([self.ROW], now=1000)
            again = self.passes([], now=2000)                       # nothing new happened; still listed
            self.assertEqual([f["severity"] for f in first], ["low"])
            self.assertEqual(len(again), 1)
            self.assertIn("has not been reviewed", again[0]["title"])
            self.assertIn("Ann Author", again[0]["detail"])         # the author stays with the listing
            self.assertEqual(community.review(self.store), 1)
            self.assertEqual(self.passes([], now=3000), [])
            self.assertEqual(self.passes([self.ROW], now=4000), [])  # reviewed and known: only counted

    def test_forgetting_a_shape_makes_it_alert_after_the_burn_in(self):
        with self.swap_rules():
            self.passes([self.ROW], now=1000)
            key = community.unreviewed(community.load_state(self.store))[0][0]
            self.assertTrue(community.forget(self.store, key))
            self.assertFalse(community.forget(self.store, key))
            later = self.passes([self.ROW], now=1000 + community.BURN_IN_S + 1)
            self.assertEqual([f["severity"] for f in later], ["medium"])
            self.assertIn("(community rule)", later[0]["title"])

    def test_the_registry_pass_does_not_repeat_the_standing_finding(self):
        with self.swap_rules():
            self.passes([self.ROW], now=1000)
            make = lambda s, t, d, i: {"severity": s, "title": t, "detail": d}  # noqa: E731
            self.assertEqual(community.findings(sigma.WIN_REG, [], lambda e: ("", "", "", ""), make,
                                                store=self.store, now=1500), [])

    def swap_rules(self):
        from unittest import mock
        return mock.patch.object(sigma, "index", side_effect=lambda category, path=None: (
            sigma.Index([self.rule] if category == sigma.WIN_PROC else []), ""))

    def test_cli_lists_and_review_needs_a_terminal(self):
        import argparse
        import contextlib
        import io
        from unittest import mock

        from jarvis.cli import output
        from jarvis.cli.commands import rules as rules_cli
        with self.swap_rules():
            self.passes([self.ROW], now=1000)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(rules_cli.cmd_rules(argparse.Namespace(action=None, key=None), self.store), 0)
        self.assertIn("1 not yet reviewed", out.getvalue())
        self.assertIn("Ann Author", out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):               # a pipe cannot review
            self.assertEqual(rules_cli.cmd_rules(argparse.Namespace(action="reviewed", key=None), self.store), 2)
        self.assertEqual(len(community.unreviewed(community.load_state(self.store))), 1)

        class Tty(io.StringIO):
            def isatty(self):
                return True
        with mock.patch.object(output.sys, "stdin", Tty("reviewed\n")), \
                mock.patch.object(output.sys, "stdout", Tty()):
            self.assertEqual(rules_cli.cmd_rules(argparse.Namespace(action="reviewed", key=None), self.store), 0)
        self.assertEqual(community.unreviewed(community.load_state(self.store)), [])


class Detector(unittest.TestCase):
    """Through the real Windows detector entry point (a replay: no store)."""

    def audit(self, cmdline, image="C:\\Windows\\System32\\vssadmin.exe"):
        rows = sysmon.rows_from_events([{
            "source": "sysmon", "source_event": 1, "seq": 1, "record": 1, "time": "2026-11-10T12:00:00.000Z",
            "process": {"image": image, "cmdline": cmdline, "guid": "{1}", "pid": 1},
            "parent": {"image": "C:\\Windows\\System32\\cmd.exe", "guid": "{2}"}}])
        self.assertEqual([f for f in sysmon.audit(events=rows, volumes={"C": ("Fixed", "")})
                          if f.get("origin") == "sigma"], [])          # a replay is built-in only unless asked
        return [f for f in sysmon.audit(events=rows, volumes={"C": ("Fixed", "")}, community_rules=True)
                if f.get("origin") == "sigma"]

    def test_findings_carry_author_licence_capped_severity_and_technique(self):
        found = self.audit("vssadmin.exe delete shadows /all /quiet")
        self.assertTrue(found)
        for f in found:
            self.assertIn(f["severity"], ("high", "medium", "low"))
            self.assertIn("Sigma rule", f["detail"])
            self.assertIn(" by ", f["detail"])
            self.assertIn(sigma.LICENSE, f["detail"])
            self.assertIn("(community rule)", f["title"])
            self.assertNotIn("delete shadows", f["detail"])          # the command line is never quoted
        self.assertTrue(any(f.get("techniques") for f in found))

    def test_an_ordinary_command_raises_nothing(self):
        self.assertEqual(self.audit("notepad.exe notes.txt", image="C:\\Windows\\System32\\notepad.exe"), [])

    def test_a_rule_file_that_does_not_validate_is_reported(self):
        from unittest import mock
        with mock.patch.object(sigma, "index", return_value=(sigma.Index(()), "the rule file is UTF-8 JSON")):
            found = self.audit("vssadmin.exe delete shadows /all /quiet")
        self.assertEqual(len(found), 2)                      # one per category pass, never silence
        self.assertTrue(all("could not be loaded" in f["title"] for f in found))

    def test_an_unfinished_pass_says_so(self):
        from unittest import mock
        with mock.patch.object(community, "MAX_DISTINCT", 1):
            rows = [{"image": f"C:\\a\\{i}.exe", "cmdline": f"x {i}"} for i in range(4)]
            got = community.findings(sigma.WIN_PROC, rows, lambda e: (e["image"], "", "", e["cmdline"]),
                                     lambda s, t, d, i: {"severity": s, "title": t, "detail": d})
        self.assertTrue(any("did not finish" in f["title"] and "3 events" in f["detail"] for f in got))


if __name__ == "__main__":
    unittest.main()


try:
    from scripts.security import atomic_bench
except ImportError:
    atomic_bench = None


@unittest.skipIf(atomic_bench is None, "PyYAML (development only) is not installed")
class DetectionGate(unittest.TestCase):
    FLOOR = {"index_sha256": "a" * 64, "tests": 100, "any_finding": 50, "win": 40, "linux": 10, "benign_findings": 0}
    GOOD = {"tests": 100, "any_finding": 50, "win": 40, "linux": 10, "benign_findings": 0, "crashes": 0}

    def problems(self, **change):
        return atomic_bench.check_floor(dict(self.GOOD, **change), self.FLOOR, change.pop("sha", "a" * 64))

    def test_at_or_above_the_floor_passes(self):
        self.assertEqual(self.problems(), [])
        self.assertEqual(self.problems(any_finding=60, win=45, linux=15), [])

    def test_each_way_of_getting_worse_fails(self):
        for change in ({"any_finding": 49}, {"win": 39}, {"linux": 9}, {"benign_findings": 1},
                       {"crashes": 1}, {"tests": 99}):
            self.assertTrue(self.problems(**change), change)

    def test_a_different_index_is_not_compared(self):
        got = atomic_bench.check_floor(self.GOOD, self.FLOOR, "b" * 64)
        self.assertEqual(len(got), 1)
        self.assertIn("not the one", got[0])

    def test_the_committed_floor_names_its_index_and_is_consistent(self):
        from jarvis.core.paths import REPO_ROOT
        floor = json.loads((REPO_ROOT / "scripts" / "security" / "atomic_floor.json").read_text())
        self.assertRegex(floor["index_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(floor["index_commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(floor["any_finding"], floor["win"] + floor["linux"])
        self.assertEqual(floor["benign_findings"], 0)
        ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn(floor["index_sha256"], ci)
        self.assertIn(floor["index_commit"], ci)


class Authority(unittest.TestCase):
    """Rule content is evidence, never authority, and that survives storage."""

    def test_content_origin_reads_the_key_or_the_title(self):
        from jarvis.core.finding import content_origin
        self.assertEqual(content_origin({"origin": "sigma", "title": "x"}), "sigma")
        self.assertEqual(content_origin({"title": "Shadow copies deleted (community rule)"}), "sigma")
        self.assertEqual(content_origin({"title": "Download to shm (T1105) [rule pack AR-0001]"}), "rulepack")
        self.assertEqual(content_origin({"title": "vssadmin.exe attempted to disable Windows recovery"}), "")
        self.assertEqual(content_origin(None), "")

    def test_a_stored_and_reread_community_finding_is_still_known_as_content(self):
        from jarvis.core.finding import content_origin
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "t.db"))
            try:
                f = sysmon._finding("technique", "medium", "Shadow Copies Deletion (community rule)",
                                    "detail", "C:\\Windows\\System32\\vssadmin.exe")
                f["origin"] = "sigma"
                back = [x for x in sysmon._remember(store, [f], 24) if "community rule" in x["title"]]
            finally:
                store.close()
        self.assertEqual(len(back), 1)
        self.assertNotIn("origin", back[0])                 # the key does not survive storage ...
        self.assertEqual(content_origin(back[0]), "sigma")  # ... the mark in the title does

    def test_no_automatic_action_on_a_content_finding_even_when_reread_without_its_key(self):
        from unittest import mock

        from jarvis.response import defense

        class Action:
            autonomy = defense.base.AUTO
            enable_flag = "auto_x"

            def match(self, f, job):
                return "target"

            def permitted(self, target, conf):
                return (True, "")

            def auto_eligible(self, f, job, target):
                return True

        conf = {"autonomous_defense": True, "auto_x": True}
        plain = {"severity": "high", "title": "vssadmin.exe attempted to disable Windows recovery"}
        with mock.patch.object(defense.base, "registry", return_value={"x": Action()}):
            self.assertEqual(defense.decide(plain, "sysmon", conf, {})[0], defense.AUTO)   # the control
            for title in ("Shadow Copies Deletion (community rule)", "Download (T1105) [rule pack AR-0001]"):
                self.assertEqual(defense.decide({"severity": "high", "title": title}, "sysmon", conf, {})[0],
                                 defense.PROPOSE, title)
            self.assertEqual(defense.decide(dict(plain, origin="sigma"), "sysmon", conf, {})[0], defense.PROPOSE)
