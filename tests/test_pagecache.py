import gzip
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.core import eventlog, pagecache
from jarvis.core.eventlog import EventLog
from tests.test_inflate import ev


class DropTests(unittest.TestCase):
    def test_advises_dontneed_on_the_whole_file(self):
        with tempfile.TemporaryFile() as fh, mock.patch.object(os, "posix_fadvise") as advise:
            self.assertTrue(pagecache.drop(fh))
            advise.assert_called_once_with(fh.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)

    def test_missing_or_failing_fadvise_is_a_quiet_no_op(self):
        with tempfile.TemporaryFile() as fh:
            with mock.patch.object(pagecache.os, "posix_fadvise", side_effect=OSError("EINVAL")):
                self.assertFalse(pagecache.drop(fh))
            with mock.patch.object(pagecache, "os", mock.Mock(spec=[])):
                self.assertFalse(pagecache.drop(fh))


class VerifyReleasesSegmentsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.log = EventLog(Path(tmp.name) / "eventlog", writer=True)
        self.addCleanup(self.log.close)
        for first in (1, 4):
            self.log.append([ev(n) for n in range(first, first + 3)],
                            {"sensor": "sensor", "channel": "c"})
            self.log.seal(force=True)

    def test_every_sealed_segment_is_released_after_verification(self):
        with mock.patch.object(eventlog.pagecache, "drop") as drop:
            self.assertEqual(self.log.verify()["problems"], [])
        self.assertEqual(drop.call_count, len(self.log.chain))

    def test_released_even_when_a_segment_is_a_bomb(self):
        seg = self.log._segment_path(self.log.chain[0]["segment"])
        with gzip.open(seg, "rb") as fh:
            header = fh.readline()
        with gzip.open(seg, "wb") as fh:
            fh.write(header + b"\n" * (2 * 1024 * 1024))
        with mock.patch.object(eventlog, "MAX_SEGMENT_PLAIN", 1024 * 1024), \
                mock.patch.object(eventlog.pagecache, "drop") as drop:
            problems = self.log.verify()["problems"]
        self.assertTrue(problems)
        self.assertEqual(drop.call_count, len(self.log.chain))


if __name__ == "__main__":
    unittest.main()
