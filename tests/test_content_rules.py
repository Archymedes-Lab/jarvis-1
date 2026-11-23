"""File-content rules: exact subset of YARA, bounded reading, private findings.

Invariants
  1. Evaluation is exact for what is compiled (ascii, wide, nocase, fullword, plain hex,
     and/or/not, N-of, file size, bytes at an offset); the rest is never compiled.
  2. The rule file is validated and bounded; a bad file is reported, not "no rules".
  3. The collector reads without following links, within caps, newest first; what a cap
     cut is said; unchanged files are not read again and keep their verdict.
  4. Findings never contain file content, name the author, are below critical and carry
     the community-rule mark.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.host import content
from jarvis.core import patterns
from jarvis.core.finding import content_origin
from jarvis.core.store import Store

try:
    from scripts.security import yara_compile
except ImportError:
    yara_compile = None

SRC = {"repo": "r", "commit": "0" * 40, "license": "DRL"}
MARK = b"evilshell_marker_v1"


def s(text, nocase=False, fullword=False, wide=False, ascii_=True):
    data = text.lower() if nocase else text
    return {"b": data.hex(), "nocase": nocase, "fullword": fullword, "wide": wide, "ascii": ascii_}


def rule(rid="R1", strings=None, cond=None, score=80, author="Ann Author"):
    strings = strings or {"$a": s(MARK)}
    return {"id": rid, "title": f"Title {rid}", "author": author, "ref": "", "score": score,
            "strings": strings, "cond": cond or ["str", next(iter(strings))]}


def parsed(*rules):
    return patterns.parse(json.dumps({"schema": patterns.SCHEMA, "source": SRC, "rules": list(rules)}).encode())["rules"]


def hit(r, data, size=None):
    return bool(patterns.match(parsed(r), data, size))


class Evaluation(unittest.TestCase):
    def test_ascii_wide_and_nocase(self):
        self.assertTrue(hit(rule(), b"xx" + MARK + b"yy"))
        self.assertFalse(hit(rule(), MARK.upper()))
        self.assertTrue(hit(rule(strings={"$a": s(MARK, nocase=True)}), MARK.upper()))
        wide = b"".join(bytes((c, 0)) for c in MARK)
        self.assertFalse(hit(rule(), wide))
        self.assertTrue(hit(rule(strings={"$a": s(MARK, wide=True, ascii_=False)}), b"\x01" + wide))
        self.assertTrue(hit(rule(strings={"$a": s(MARK, wide=True)}), MARK))          # ascii or wide

    def test_fullword_needs_non_alphanumeric_neighbours(self):
        r = rule(strings={"$a": s(b"evil", fullword=True)})
        self.assertTrue(hit(r, b"run evil now"))
        self.assertTrue(hit(r, b"evil"))
        self.assertFalse(hit(r, b"devils"))
        self.assertTrue(hit(r, b"devils and evil!"))                                # a later occurrence counts

    def test_conditions(self):
        strings = {"$a": s(b"aaaa"), "$b": s(b"bbbb"), "$c": s(b"cccc")}
        self.assertTrue(hit(rule(strings=strings, cond=["of", 2, ["$a", "$b", "$c"]]), b"aaaa cccc"))
        self.assertFalse(hit(rule(strings=strings, cond=["of", 2, ["$a", "$b", "$c"]]), b"aaaa"))
        self.assertFalse(hit(rule(strings=strings, cond=["of", "all", ["$a", "$b"]]), b"aaaa"))
        self.assertTrue(hit(rule(strings=strings, cond=["of", "any", ["$a", "$b"]]), b"bbbb"))
        self.assertTrue(hit(rule(strings=strings, cond=["and", ["str", "$a"], ["not", ["str", "$b"]]]), b"aaaa"))
        self.assertFalse(hit(rule(strings=strings, cond=["and", ["str", "$a"], ["not", ["str", "$b"]]]), b"aaaabbbb"))
        self.assertTrue(hit(rule(strings=strings, cond=["or", ["str", "$a"], ["str", "$b"]]), b"bbbb"))

    def test_size_judges_the_file_not_the_bytes_read_and_magic_gates_the_rule(self):
        small = rule(cond=["and", ["size", "<", 100], ["str", "$a"]])
        self.assertTrue(hit(small, MARK))
        self.assertFalse(hit(small, MARK, size=5000))                 # only the start was read
        mz = rule(cond=["and", ["bytes", 0, "4d5a"], ["str", "$a"]])
        self.assertTrue(hit(mz, b"MZ" + MARK))
        self.assertFalse(hit(mz, b"#!" + MARK))
        self.assertEqual(len(parsed(mz)[0].gate), 1)

    def test_severity_follows_score_and_is_never_critical(self):
        self.assertEqual(parsed(rule(score=80))[0].severity, "medium")
        self.assertEqual(parsed(rule(score=100))[0].severity, "high")


class Validation(unittest.TestCase):
    def test_malformed_rules_are_refused(self):
        bad = [rule(author=" "), rule(score=101), rule(cond=["str", "$zz"]), rule(cond=["xor", ["str", "$a"]]),
               rule(strings={"$a": s(b"abc")}),                                    # too short to search for
               rule(strings={"$a": dict(s(MARK), ascii=False)}),                   # neither ascii nor wide
               rule(strings={"$a": dict(s(MARK), nocase=True, b=MARK.upper().hex())}),
               rule(cond=["of", 3, ["$a"]]), rule(cond=["bytes", 99999, "4d5a"]), rule(cond=["size", "==", 5]),
               rule(strings={"$a": {"b": "zz", "nocase": False, "fullword": False, "wide": False, "ascii": True}})]
        for r in bad:
            with self.assertRaises(patterns.PatternError, msg=str(r)[:80]):
                parsed(r)
        with self.assertRaises(patterns.PatternError):
            parsed(rule(), rule())                                                 # duplicate id
        for data in (b"", b"{", json.dumps({"schema": "x", "source": SRC, "rules": []}).encode()):
            with self.assertRaises(patterns.PatternError):
                patterns.parse(data)

    def test_the_shipped_file_validates_and_every_rule_names_an_author(self):
        doc = patterns.parse(patterns.DATA.read_bytes())
        self.assertIn("signature-base", doc["source"]["repo"])
        self.assertGreater(len(doc["rules"]), 100)
        for r in doc["rules"]:
            self.assertIn(r.author, patterns.attribution(r))
            self.assertIn(r.severity, ("medium", "high"))

    def test_shipped_rules_fire_on_content_built_from_their_own_strings_and_not_on_plain_text(self):
        rules = patterns.load()[0]
        fired = 0
        for r in rules:
            blob = b"MZ" + b"\n".join(st[0][0][0] for st in r.strings.values())
            fired += bool(patterns.match([r], blob, size=len(blob)))
        self.assertGreater(fired, len(rules) // 3)          # the rest need a magic or size this blob lacks
        self.assertEqual(patterns.match(rules, b"#!/bin/sh\necho hello world\n" * 50), [])


@unittest.skipIf(yara_compile is None, "compiler not importable")
class Compiler(unittest.TestCase):
    RULE = '''
        strings:
            $s1 = "evil_marker_one" ascii wide
            $s2 = "Second\\\\Marker" nocase fullword
            $h = { 4d 5a 90 00 }
        condition:
            uint16(0) == 0x5a4d and filesize < 300KB and ( 2 of ($s*) or $h )
    '''
    META = 'meta:\n description = "Test rule"\n author = "Ann Author"\n score = 85\n'

    def compile(self, body=None, meta=None):
        return yara_compile.compile_rule("Test_Rule", (self.META if meta is None else meta) + (body or self.RULE))

    def test_a_typical_rule_means_what_its_source_means(self):
        r = parsed(self.compile())[0]
        self.assertTrue(patterns.match([r], b"MZ evil_marker_one  second\\marker "))
        self.assertTrue(patterns.match([r], b"MZ\x90\x00 nothing else"))
        self.assertFalse(patterns.match([r], b"MZ evil_marker_one only"))
        self.assertFalse(patterns.match([r], b"#! evil_marker_one  second\\marker "))
        self.assertFalse(patterns.match([r], b"MZ evil_marker_one  second\\marker ", size=400 * 1024))

    def test_what_cannot_be_evaluated_exactly_is_left_out(self):
        cases = [
            'strings:\n $a = /ev[il]+/\n condition:\n $a',
            'strings:\n $a = { 4d 5a ?? 00 }\n condition:\n $a',
            'strings:\n $a = "evil_marker" xor\n condition:\n $a',
            'strings:\n $a = "evil_marker"\n condition:\n #a > 3',
            'strings:\n $a = "evil_marker"\n condition:\n $a at 0',
            'strings:\n $a = "evil_marker"\n condition:\n pe.imphash() == "x" and $a',
            'strings:\n $a = "evil_marker"\n condition:\n $a and Other_Rule',
            'strings:\n $a = "abc"\n condition:\n $a',
        ]
        for body in cases:
            with self.assertRaises(yara_compile.Unsupported, msg=body):
                self.compile(body)
        for meta in ('meta:\n author = "A"\n score = 60\n', 'meta:\n score = 90\n',
                     'meta:\n author = "A"\n score = 90\n license = "CC-BY-NC 4.0"\n'):
            with self.assertRaises(yara_compile.Unsupported, msg=meta):
                self.compile(meta=meta)

    def test_comments_are_removed_but_not_inside_strings(self):
        text = yara_compile.strip_comments('$a = "http://x//y" // gone\n/* gone\n too */ $b = "k"')
        self.assertIn('"http://x//y"', text)
        self.assertNotIn("gone", text)


class Collector(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.join(self.tmp.name, "drop")
        os.makedirs(self.root)
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.addCleanup(self.store.close)
        patch = mock.patch.object(patterns, "load", return_value=(parsed(rule()), SRC, ""))
        patch.start()
        self.addCleanup(patch.stop)

    def write(self, name, data):
        path = os.path.join(self.root, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def run_pass(self, **kw):
        return content.audit(self.store, root_dirs=[self.root], **kw)

    def test_a_matching_file_is_reported_without_its_content(self):
        secret = b"password=Hunter2 " + MARK
        path = self.write("shell.php", secret)
        self.write("notes.txt", b"just some ordinary notes, nothing here")
        out = self.run_pass()
        self.assertEqual(len(out), 1)
        f = out[0]
        self.assertEqual((f["severity"], f["where"]), ("medium", path))
        self.assertIn("(community rule)", f["title"])
        self.assertTrue(content_origin(f))                      # never acted on automatically
        self.assertIn("Ann Author", f["detail"])
        self.assertIn("SHA-256", f["detail"])
        everything = json.dumps(out) + (self.store.get_meta(content.META, "") or "")
        self.assertNotIn("Hunter2", everything)
        self.assertNotIn(MARK.decode(), everything)

    def test_an_unchanged_file_is_not_read_again_and_keeps_its_verdict(self):
        self.write("shell.php", MARK)
        self.run_pass()
        with mock.patch.object(content, "read_start", side_effect=AssertionError("read again")):
            again = self.run_pass()
        self.assertEqual(len(again), 1)

    def test_a_changed_or_removed_file_is_judged_afresh(self):
        path = self.write("shell.php", MARK)
        self.assertEqual(len(self.run_pass()), 1)
        with open(path, "wb") as fh:
            fh.write(b"cleaned up, nothing left in this file now")
        os.utime(path, ns=(1, 2_000_000_000_000_000_000))
        self.assertEqual(self.run_pass(), [])
        self.write("b.php", MARK)
        self.assertEqual(len(self.run_pass()), 1)
        os.unlink(os.path.join(self.root, "b.php"))
        self.assertEqual(self.run_pass(), [])

    def test_links_and_special_files_are_never_followed(self):
        outside = os.path.join(self.tmp.name, "outside.txt")
        with open(outside, "wb") as fh:
            fh.write(MARK)
        os.symlink(outside, os.path.join(self.root, "link.php"))
        os.mkfifo(os.path.join(self.root, "pipe"))
        self.assertEqual(self.run_pass(), [])
        self.assertIsNone(content.read_start(os.path.join(self.root, "link.php")))

    def test_caps_are_enforced_newest_first_and_said(self):
        old = self.write("old.php", MARK)
        os.utime(old, ns=(1, 1_000_000_000_000_000_000))
        self.write("new.php", MARK + b" newer")
        with mock.patch.object(content, "MAX_FILES", 1):
            out = self.run_pass()
        titles = [f["title"] for f in out]
        self.assertIn("File-content check did not finish this pass", titles)
        self.assertEqual([f["where"] for f in out if "(community rule)" in f["title"]],
                         [os.path.join(self.root, "new.php")])
        self.assertEqual(len([f for f in self.run_pass() if "(community rule)" in f["title"]]), 2)   # next pass

    def test_the_time_budget_stops_the_pass(self):
        for i in range(5):
            self.write(f"f{i}.txt", b"ordinary file number %d padding padding" % i)
        ticks = iter([0.0] + [content.MAX_SECONDS + 1] * 50)
        out = self.run_pass(clock=lambda: next(ticks))
        self.assertTrue(any("did not finish" in f["title"] for f in out))

    def test_only_the_start_of_a_large_file_is_read(self):
        path = self.write("big.bin", b"A" * 5000 + MARK)
        with mock.patch.object(content, "MAX_FILE_BYTES", 1000):
            self.assertEqual(len(content.read_start(path, 1000)), 1000)

    def test_a_rule_file_that_does_not_validate_is_reported(self):
        with mock.patch.object(patterns, "load", return_value=((), None, "the rule file is UTF-8 JSON")):
            out = self.run_pass()
        self.assertEqual([f["title"] for f in out], ["File-content rules could not be loaded"])


if __name__ == "__main__":
    unittest.main()

class ContinuationSafety(Collector):
    def test_ancestor_symlink_is_rejected(self):
        self.write('payload', MARK)
        link = os.path.join(self.tmp.name, 'alias')
        os.symlink(self.root, link)
        self.assertIsNone(content.read_start(os.path.join(link, 'payload')))
        self.assertEqual(content.candidates([link])[0], [])

    def test_same_size_and_mtime_replacement_invalidates_cache(self):
        path = self.write('payload', b'A' * len(MARK))
        old = os.stat(path)
        self.run_pass()
        replacement = self.write('replacement', MARK)
        os.utime(replacement, ns=(old.st_atime_ns, old.st_mtime_ns))
        os.replace(replacement, path)
        self.assertTrue(any('(community rule)' in f['title'] for f in self.run_pass()))

    def test_rule_change_invalidates_cache(self):
        self.write('payload', MARK)
        with mock.patch.object(patterns, 'load', return_value=(parsed(rule(strings={'$a': s(b'nevermatch')})), SRC, '')):
            self.assertEqual(self.run_pass(), [])
        self.assertTrue(self.run_pass())

    def test_oversized_negative_condition_is_not_matched_on_a_prefix(self):
        self.write('payload', MARK + b'X' * 100 + b'absent_marker')
        rules = parsed(rule(strings={'$a': s(MARK), '$b': s(b'absent_marker')},
                            cond=['and', ['str', '$a'], ['not', ['str', '$b']]]))
        with mock.patch.object(patterns, 'load', return_value=(rules, SRC, '')), \
                mock.patch.object(content, 'MAX_FILE_BYTES', 50):
            out = self.run_pass()
        self.assertFalse(any('(community rule)' in f['title'] for f in out))
        self.assertTrue(any('oversized files: 1' in f['detail'] for f in out))

    def test_discovery_counts_empty_directories_and_reports_exhaustion(self):
        for n in range(20):
            os.mkdir(os.path.join(self.root, str(n)))
        rows, cut, _unread = content.candidates([self.root], limit=5)
        self.assertEqual(rows, [])
        self.assertTrue(cut)

    def test_failed_refresh_preserves_prior_positive_as_stale(self):
        path = self.write('payload', MARK)
        self.run_pass()
        os.utime(path, ns=(1, 2_000_000_000_000_000_000))
        with mock.patch.object(content, 'read_start', return_value=None):
            out = self.run_pass()
        self.assertTrue(any('could not refresh' in f['detail'] for f in out))

    def test_open_rejects_identity_race(self):
        path = self.write('payload', MARK)
        ident = content.identity(os.stat(path))
        os.replace(self.write('replacement', b'Z' * len(MARK)), path)
        self.assertIsNone(content.read_start(path, expected=ident))

    def test_missing_rules_report_visibility(self):
        with mock.patch.object(patterns, 'load', return_value=((), None, '')):
            self.assertIn('missing', self.run_pass()[0]['title'])

class CompilerFailures(unittest.TestCase):
    def test_incomplete_condition_is_rejected_without_crashing(self):
        for text in ('not', '(', '$a and', 'uint16(', 'any of ($a,'):
            with self.assertRaises(yara_compile.Unsupported):
                yara_compile.compile_condition(text, ['$a'])

    def test_nonapproved_licence_is_not_accepted_by_substring(self):
        meta = Compiler.META + ' license = "DRL custom noncommercial"\n'
        with self.assertRaises(yara_compile.Unsupported):
            yara_compile.compile_rule('X', meta + Compiler.RULE)

    def test_global_gate_is_never_dropped_from_file(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / 'yara'
            directory.mkdir()
            (directory / 'rules.yar').write_text('global rule Gate {\ncondition:\nfalse\n}\n'
                                               'rule Ungated {\n' + Compiler.META + Compiler.RULE + '\n}\n')
            doc, skipped = yara_compile.compile_tree(tmp, '0' * 40)
        self.assertEqual(doc['rules'], [])
        self.assertGreater(skipped['file contains global rule'], 0)

class CompleteEvidence(unittest.TestCase):
    def test_partial_read_cannot_satisfy_absence(self):
        r = rule(cond=['not', ['str', '$a']])
        self.assertFalse(hit(r, b'prefix only', size=1000))

    def test_out_of_range_integer_is_unknown_even_under_negation(self):
        r = rule(cond=['and', ['str', '$a'], ['not', ['bytes', 100, '4d5a']]])
        self.assertFalse(hit(r, MARK))
