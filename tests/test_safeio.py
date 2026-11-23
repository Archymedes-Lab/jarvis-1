"""jarvis/core/safeio.py: reads of files other users control never block,
never follow a refused link, and never read past the limit."""

import os
import shutil
import tempfile
import unittest

from jarvis.core import safeio


class ReadRegularTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="safeio-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def path(self, name):
        return os.path.join(self.dir, name)

    def test_regular_file_is_read_up_to_limit_plus_one(self):
        with open(self.path("f"), "wb") as fh:
            fh.write(b"x" * 100)
        self.assertEqual(safeio.read_regular(self.path("f"), 1000), b"x" * 100)
        self.assertEqual(len(safeio.read_regular(self.path("f"), 10)), 11)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no FIFOs here")
    def test_fifo_is_refused_without_waiting_for_a_writer(self):
        os.mkfifo(self.path("p"))
        with self.assertRaises(safeio.NotRegular):
            safeio.read_regular(self.path("p"), 10)

    @unittest.skipUnless(os.path.exists("/dev/zero"), "no /dev/zero")
    def test_link_to_a_device_is_refused_followed_or_not(self):
        os.symlink("/dev/zero", self.path("z"))
        for follow in (True, False):
            with self.assertRaises(safeio.NotRegular):
                safeio.read_regular(self.path("z"), 10, follow=follow)

    def test_link_to_a_regular_file_is_refused_only_when_links_are(self):
        with open(self.path("target"), "wb") as fh:
            fh.write(b"secret")
        os.symlink(self.path("target"), self.path("l"))
        self.assertEqual(safeio.read_regular(self.path("l"), 100), b"secret")
        with self.assertRaises(safeio.NotRegular):
            safeio.read_regular(self.path("l"), 100, follow=False)

    def test_missing_and_directory(self):
        with self.assertRaises(FileNotFoundError):
            safeio.read_regular(self.path("nope"), 10)
        with self.assertRaises(OSError):
            safeio.read_regular(self.dir, 10)


if __name__ == "__main__":
    unittest.main()
