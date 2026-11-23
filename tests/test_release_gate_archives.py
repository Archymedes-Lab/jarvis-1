"""The gate finds a zip hidden in a binary, and does not mistake a Python runtime for one.

A Python runtime (python3*.dll) carries the zip signatures as constants in its built-in
zipimport code. Reading what follows them as archive members refused every Windows
installer (CI dry run #5) and printed binary garbage into the log. Detection now needs a
central directory that is consistent with its end record.
"""

import io
import struct
import sys
import sysconfig
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
import gate  # noqa: E402

MZ = b"MZ" + b"\x90" * 400
NAMES = ("src/core/main.py", "ok/readme.txt")


def make_zip(names=NAMES):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n in names:
            z.writestr(n, b"content of " + n.encode())
    return buf.getvalue()


def make_zip64(names=NAMES):
    """The same archive in zip64 layout: central directory, zip64 end record, locator,
    then a classic end record whose size fields are all 0xFFFF / 0xFFFFFFFF."""
    plain = make_zip(names)
    end = plain.rfind(b"PK\x05\x06")
    entries = struct.unpack("<H", plain[end + 10:end + 12])[0]
    cd_size, cd_offset = struct.unpack("<II", plain[end + 12:end + 20])
    body, directory = plain[:cd_offset], plain[cd_offset:cd_offset + cd_size]
    record_at = len(body) + len(directory)
    record = b"PK\x06\x06" + struct.pack("<QHHIIQQQQ", 44, 45, 45, 0, 0, entries, entries, cd_size, cd_offset)
    locator = b"PK\x06\x07" + struct.pack("<IQI", 0, record_at, 1)
    classic = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    return body + directory + record + locator + classic


class EmbeddedArchiveTest(unittest.TestCase):
    def setUp(self):
        self.policy = gate.load_policy()

    def refused(self, data):
        return [p for p in gate.scan_bytes("Argus-Setup.exe:thing.exe", data, self.policy)
                if "embedded archive" in p]

    def test_a_zip_appended_to_a_binary_is_still_refused(self):
        self.assertTrue(self.refused(MZ + make_zip()))

    def test_a_zip_in_the_middle_of_a_binary_is_still_refused(self):
        self.assertTrue(self.refused(MZ + make_zip() + b"signature block " * 100))

    def test_a_zip64_archive_is_still_refused(self):
        data = MZ + make_zip64()
        self.assertIn(b"PK\x06\x06", data, "the fixture must really be zip64")
        self.assertEqual(zipfile.ZipFile(io.BytesIO(make_zip64())).namelist(), list(NAMES),
                         "and a real zip reader must accept it")
        self.assertTrue(self.refused(data))
        self.assertIn("src/core/main.py", gate.embedded_zip_names(data))

    def test_an_archive_with_nothing_denied_in_it_is_not_refused(self):
        self.assertEqual(self.refused(MZ + make_zip(names=("ok/a.txt", "ok/b.txt"))), [])

    def test_the_signatures_as_bare_constants_are_not_an_archive(self):
        constants = b"\x00PK\x01\x02 zipimport PK\x05\x06 PK\x06\x06 PK\x06\x07 more code " * 30
        self.assertEqual(gate.embedded_zip_names(MZ + constants), [])
        self.assertEqual(self.refused(MZ + constants), [])

    def test_a_truncated_or_inconsistent_directory_is_not_reported_as_names(self):
        data = make_zip()
        self.assertEqual(gate.embedded_zip_names(data[:-30]), [])          # end record cut off
        broken = bytearray(data)
        i = broken.rfind(b"PK\x05\x06")
        broken[i + 12:i + 16] = (999999).to_bytes(4, "little")             # directory size lies
        self.assertEqual(gate.embedded_zip_names(bytes(broken)), [])

    def test_the_log_never_carries_binary_garbage(self):
        constants = b"PK\x01\x02" + bytes(range(256)) * 4 + b"PK\x05\x06" + bytes(range(256))
        for line in gate.scan_bytes("x:y", MZ + constants, self.policy):
            self.assertTrue(line.isprintable(), repr(line)[:80])

    def test_a_real_python_runtime_dll_is_not_mistaken_for_an_archive(self):
        dlls = sorted(Path(sys.base_prefix).glob("python3*.dll"))
        if not dlls or not sysconfig.get_platform().startswith("win"):
            self.skipTest("no Windows Python runtime DLL here")
        data = dlls[-1].read_bytes()
        self.assertIn(b"PK\x01\x02", data, "this runtime does carry the constants the old check tripped on")
        self.assertEqual(gate.embedded_zip_names(data), [])


if __name__ == "__main__":
    unittest.main()
