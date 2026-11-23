"""Package data ships the same whatever Python builds it (ported from the
windows-installer branch): on 3.12 `glob("dir/**")` returns no files, and the
2026.11.03-0 release shipped no dashboard file because of it."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
import build_server  # noqa: E402


class DataFilesTest(unittest.TestCase):
    """The package data that ships must not depend on the Python version that builds it."""

    def make_tree(self):
        tree = Path(tempfile.mkdtemp(prefix="argus-data-"))
        static = tree / "argus" / "web" / "static"
        (static / "vendor" / "leaflet").mkdir(parents=True)
        (static / "index.html").write_text("<html></html>")
        (static / "vendor" / "leaflet" / "leaflet.js").write_text(
            "var L = {};\nL.x = 1;\n//# sourceMappingURL=leaflet-src.js.map\n")
        (tree / "argus" / "web" / "styles").mkdir(parents=True)
        (tree / "argus" / "web" / "styles" / "shell.css").write_text("a{}")
        return tree

    def test_nested_static_files_are_included_not_just_directories(self):
        tree = self.make_tree()
        rels = {rel for _src, rel in build_server.data_files(tree, Path(tempfile.mkdtemp()))}
        self.assertIn("argus/web/static/index.html", rels)
        self.assertIn("argus/web/static/vendor/leaflet/leaflet.js", rels)
        self.assertIn("argus/web/styles/shell.css", rels)

    def test_a_source_map_comment_is_removed_from_a_copy_not_the_source(self):
        tree = self.make_tree()
        clean = Path(tempfile.mkdtemp())
        got = dict((rel, src) for src, rel in build_server.data_files(tree, clean))
        shipped = got["argus/web/static/vendor/leaflet/leaflet.js"].read_bytes()
        self.assertNotIn(b"sourceMappingURL", shipped)
        self.assertIn(b"L.x = 1;", shipped, "only the comment goes, never the code")
        original = (tree / "argus/web/static/vendor/leaflet/leaflet.js").read_bytes()
        self.assertIn(b"sourceMappingURL", original)

    def test_the_real_dashboard_files_are_all_found_and_none_carry_a_source_map(self):
        import rename
        tree = Path(tempfile.mkdtemp(prefix="argus-export-"))
        rename.export(ROOT, "HEAD", tree)   # the same renamed export the build compiles
        pairs = build_server.data_files(tree, Path(tempfile.mkdtemp()))
        rels = [rel for _s, rel in pairs]
        self.assertGreater(len([r for r in rels if r.startswith("argus/web/static/")]), 10)
        self.assertIn("argus/web/static/vendor/leaflet/leaflet.js", rels)
        for src, rel in pairs:
            self.assertNotIn(b"sourceMappingURL=", Path(src).read_bytes(), rel)


class ShippedDataIsAllowed(unittest.TestCase):
    """Every data file the builds ship must be allowed, path by path, in each
    artifact that carries the engine: run 41744195602 found world-50m.json
    refused only after a 10-minute compile, once dashboard files began to ship."""

    PREFIXES = {
        "argus-server-linux-x86_64.tar.gz": "argus-server/bin/",
        "argus-server_*_amd64.deb": "usr/share/argus-server/bin/",
        "argus-instinct-windows-x64.zip": "ARGUS-INSTINCT/engine/",
        "ARGUS-INSTINCT-Setup-windows-x64.exe": "engine/",
    }

    def test_every_shipped_data_file_is_allowed_and_not_denied(self):
        import gate
        import rename
        tree = Path(tempfile.mkdtemp(prefix="argus-export-"))
        rename.export(ROOT, "HEAD", tree)
        rels = [rel for _s, rel in build_server.data_files(tree, Path(tempfile.mkdtemp()))]
        policy = gate.load_policy()
        rules = {r["name"]: r for r in policy["artifacts"]}
        for name, prefix in self.PREFIXES.items():
            for rel in rels:
                path = prefix + rel
                with self.subTest(artifact=name, file=rel):
                    self.assertIsNone(gate.denied_path(path, policy))
                    self.assertTrue(any(gate.glob_match(path, p) for p in rules[name]["allow"]),
                                    f"{path} is not in the allow list of {name}")


class FileCountGrowth(unittest.TestCase):
    """The growth check compares versioned names too, and an explanation covers
    one pinned jump only (run 41746357384)."""

    def _check(self, prev_counts, counts, policy):
        import json as _json

        import gate
        prev = Path(tempfile.mkdtemp()) / "manifest.json"
        prev.write_text(_json.dumps({"member_counts": prev_counts}))
        with mock.patch.object(gate, "members_of", side_effect=lambda path, kind: []), \
             mock.patch.object(gate, "check_artifact", side_effect=lambda path, rule, pol: ([], counts[path.name])):
            folder = Path(tempfile.mkdtemp())
            for name in counts:
                (folder / name).write_bytes(b"x")
            problems, _ = gate.check_release(folder, policy, prev)
        return [p for p in problems if "up from" in p]

    def test_a_versioned_deb_is_compared_and_explanations_are_pinned(self):
        import gate
        policy = dict(gate.load_policy(), explained_growth=[])
        prev = {"argus-server_2026.11.03.0_amd64.deb": 83}
        new = {"argus-server_2026.11.04.9_amd64.deb": 110}
        self.assertEqual(len(self._check(prev, new, policy)), 1, "the versioned .deb must be compared")
        policy["explained_growth"] = [{"artifact": "argus-server_*_amd64.deb", "previous": 83, "max": 110,
                                       "reason": "test"}]
        self.assertEqual(self._check(prev, new, policy), [])
        self.assertEqual(len(self._check(prev, {"argus-server_2026.11.04.9_amd64.deb": 111}, policy)), 1)
        self.assertEqual(len(self._check({"argus-server_2026.11.03.0_amd64.deb": 90},
                                         {"argus-server_2026.11.04.9_amd64.deb": 120}, policy)), 1,
                         "an explanation pinned to 83 does not cover a later jump")


if __name__ == "__main__":
    unittest.main()
