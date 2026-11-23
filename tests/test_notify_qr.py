"""The pairing QR encoder (jarvis/response/notify/qr.py): structure, and a real decode with the
phone app's own scanner library (jsQR) when Bun is available."""

import json
import os
import shutil
import subprocess
import unittest

from jarvis.response.notify import qr

HERE = os.path.dirname(os.path.abspath(__file__))
DECODER = os.path.join(HERE, "..", "hosted", "notify-cloudflare", "tests", "decode_qr.mjs")
LINK = "https://argus.archymedes.xyz/#/pair?c=7KQ3M9X2PT&k=AAECAwQFBgcICQoLDA0ODw&mb=Zm9vYmFyYmF6cXV4MTIzNA"


def decode(text):
    bun = shutil.which("bun") or shutil.which("bun.exe")
    if not bun:
        for base in os.environ.get("PATH", "").split(os.pathsep):
            cand = os.path.join(base, "node_modules", "bun", "bin", "bun.exe")
            if os.path.exists(cand):
                bun = cand
    if not bun:
        raise unittest.SkipTest("bun is not installed")
    rows = [[1 if v else 0 for v in r] for r in qr.encode(text)]
    out = subprocess.run([bun, DECODER], input=json.dumps(rows), capture_output=True, text=True, encoding="utf-8", timeout=60)
    return out.stdout.strip(), out.stderr


class QrTests(unittest.TestCase):
    def test_size_follows_the_version_and_finders_are_drawn(self):
        for text, size in (("hi", 21), (LINK, 41), ("x" * 120, 45)):
            m = qr.encode(text)
            self.assertEqual((len(m), len(m[0])), (size, size), text[:10])
            for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):          # the three finder patterns
                self.assertTrue(m[cy][cx] and not m[cy][cx + 2] and m[cy][cx + 3], "finder pattern")
            self.assertTrue(all(m[6][i] == (i % 2 == 0) for i in range(8, size - 8)), "timing row")

    def test_too_long_is_refused(self):
        with self.assertRaises(qr.TooLong):
            qr.encode("x" * 300)

    def test_ansi_rendering_has_a_quiet_zone_and_resets_colours(self):
        text = qr.render_ansi(qr.encode("hi"))
        lines = text.split("\n")
        self.assertEqual(len(lines), (21 + 4 + 1) // 2)
        self.assertTrue(all(line.endswith("\x1b[0m") for line in lines))

    def test_scanner_library_reads_what_we_make(self):
        samples = ["hi", "https://argus.archymedes.xyz/", LINK, "x" * 150, "é✓ non-ASCII", "A" * 200]
        for text in samples:
            with self.subTest(text[:24]):
                got, err = decode(text)
                self.assertEqual(got, text, err)


if __name__ == "__main__":
    unittest.main()
