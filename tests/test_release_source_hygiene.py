"""The release tooling is reviewed as text: no invisible characters may hide in it.

Found 2026-11-04: a shell heredoc turned `b"PK\\x01\\x02"` in release/gate.py into the raw
control bytes, so the content gate's own source showed `b"PK"` to a reviewer while behaving
differently from what the diff displayed. Escapes must be written out, never embedded.
"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {9, 10, 13}   # tab, line feed, carriage return
SUFFIXES = {".py", ".json", ".md", ".nsi", ".yml", ".txt", ".sh"}


def tracked_release_files():
    for folder in ("release", ".github"):
        for path in sorted((ROOT / folder).rglob("*")):
            if path.is_file() and path.suffix in SUFFIXES:
                yield path


class SourceHygieneTest(unittest.TestCase):
    def test_no_raw_control_characters_in_the_release_tooling(self):
        bad = {}
        for path in tracked_release_files():
            n = sum(1 for b in path.read_bytes() if b < 32 and b not in ALLOWED)
            if n:
                bad[path.relative_to(ROOT).as_posix()] = n
        self.assertEqual(bad, {}, "write escapes such as \\x01 as text, not as the raw byte")

    def test_no_zero_width_or_bidirectional_control_characters(self):
        # By number, so this file cannot itself hold an invisible character.
        hidden = {chr(c) for c in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x202A, 0x202B,
                                    0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)}
        bad = []
        for path in tracked_release_files():
            text = path.read_text(encoding="utf-8", errors="replace")
            body = text[1:] if text[:1] == chr(0xFEFF) else text   # a leading byte-order mark is fine
            if any(ch in hidden for ch in body):
                bad.append(path.relative_to(ROOT).as_posix())
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
