"""The event log's shared parse cache (core/eventlog.py _parsed_lines).

Invariant: every open returns exactly what a fresh parse of the current bytes
returns. The cache only saves the work of re-parsing a prefix whose SHA-256
still matches; it never trusts size or mtime.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from jarvis.core import eventlog
from jarvis.core.eventlog import EventLog


def fresh(path):
    out = []
    with open(path, "rb") as fh:
        for line in fh:
            if not line.endswith(b"\n"):
                break
            try:
                out.append(json.loads(line))
            except ValueError:
                break
    return out


class ParseCacheTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "chain.jsonl")
        eventlog._PARSE_CACHE.clear()

    def write(self, text, mode="w"):
        with open(self.path, mode, encoding="utf-8") as fh:
            fh.write(text)

    def test_append_parses_only_the_new_lines(self):
        self.write("".join(json.dumps({"n": i}) + "\n" for i in range(50)))
        self.assertEqual(eventlog._jsonl(self.path), fresh(self.path))
        self.write(json.dumps({"n": 50}) + "\n", "a")
        with mock.patch.object(eventlog.json, "loads", wraps=json.loads) as loads:
            got = eventlog._jsonl(self.path)
        self.assertEqual(got, fresh(self.path))
        self.assertEqual(loads.call_count, 1)          # only the appended line

    def test_a_rewritten_prefix_is_parsed_afresh_even_with_same_size_and_mtime(self):
        self.write(json.dumps({"hash": "aaaa"}) + "\n" + json.dumps({"hash": "bbbb"}) + "\n")
        st = os.stat(self.path)
        eventlog._jsonl(self.path)
        self.write(json.dumps({"hash": "XXXX"}) + "\n" + json.dumps({"hash": "bbbb"}) + "\n")
        os.utime(self.path, ns=(st.st_atime_ns, st.st_mtime_ns))          # same size, same mtime
        self.assertEqual(eventlog._jsonl(self.path)[0]["hash"], "XXXX")

    def test_truncation_torn_and_invalid_tails_match_a_fresh_parse(self):
        good = "".join(json.dumps({"n": i}) + "\n" for i in range(5))
        self.write(good + '{"n": 5')                                     # torn
        self.assertEqual(eventlog._jsonl(self.path), fresh(self.path))
        self.write('}\n{"n": 6}\n', "a")                                 # torn line completed
        self.assertEqual(eventlog._jsonl(self.path), fresh(self.path))
        self.write(good + "not json\n" + json.dumps({"n": 9}) + "\n")    # invalid stops the parse
        self.assertEqual(eventlog._jsonl(self.path), fresh(self.path))
        self.write(good[: len(good) // 2].rsplit("\n", 1)[0] + "\n")     # truncated
        self.assertEqual(eventlog._jsonl(self.path), fresh(self.path))
        os.remove(self.path)
        self.assertEqual(eventlog._jsonl(self.path), [])

    def test_the_cache_is_bounded(self):
        for i in range(eventlog._PARSE_CACHE_FILES + 5):
            p = os.path.join(self._tmp.name, f"f{i}.jsonl")
            with open(p, "w") as fh:
                fh.write("{}\n")
            eventlog._jsonl(p)
        self.assertLessEqual(len(eventlog._PARSE_CACHE), eventlog._PARSE_CACHE_FILES)


class EventLogOpenTests(unittest.TestCase):
    def test_reopened_logs_see_new_batches_and_keep_private_cursors(self):
        from tests.test_historybook import sample
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "log")
            with EventLog(root, writer=True) as log:
                log.append([sample(1)], {"sensor": "s", "channel": "c", "n": 1})
            with EventLog(root) as a:
                seq_a = a.last_seq
                a.cursor("s", "c")["n"] = "mutated by a caller"
            with EventLog(root, writer=True) as log:
                self.assertEqual(log.cursor("s", "c")["n"], 1)          # the cache was not mutated
                log.append([sample(2)], {"sensor": "s", "channel": "c", "n": 2})
                log.seal(force=True)
                log.append([sample(3)], {"sensor": "s", "channel": "c", "n": 3})
            with EventLog(root) as b:
                self.assertEqual(b.last_seq, seq_a + 2)
                self.assertEqual(b.cursor("s", "c")["n"], 3)
                self.assertEqual(len(list(b.iter_events())), 3)
                self.assertEqual(len(b.chain), 1)
                self.assertGreater(b.sealed_bytes, 0)
                cached = (b.last_seq, b.sealed_bytes, b.head_hash, b.cursors)
            # A fresh process view (empty caches) agrees with the cached one.
            eventlog._PARSE_CACHE.clear()
            eventlog._SEALED_CACHE.clear()
            with EventLog(root) as c:
                self.assertEqual((c.last_seq, c.sealed_bytes, c.head_hash, c.cursors), cached)


if __name__ == "__main__":
    unittest.main()
