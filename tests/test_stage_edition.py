import importlib.util
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "stage_argus_edition.py"
spec = importlib.util.spec_from_file_location("stage_argus_edition", SCRIPT)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class StageTests(unittest.TestCase):
    def test_rename_follows_the_installed_editions_rule(self):
        self.assertEqual(stage.rename("from jarvis.core import x  # JARVIS_HOME, Jarvis"),
                         "from argus.core import x  # ARGUS_HOME, Argus")

    def test_code_is_renamed_but_the_built_interface_and_vendor_files_are_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = pathlib.Path(tmp, "jarvis"), pathlib.Path(tmp, "out")
            for rel, body in {"core/a.py": "import jarvis\n", "web/ui/assets/app.js": "localStorage['jarvis.theme']",
                              "web/static/vendor/pinned.json": '{"jarvis": 1}', "web/static/page.html": "<b>jarvis</b>"}.items():
                path = src / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8")
            (src / "core" / "__pycache__").mkdir()
            (src / "core" / "__pycache__" / "a.cpython-312.pyc").write_bytes(b"x")
            n = stage.copy_package(str(src), str(dst))
            self.assertEqual(n, 4)
            self.assertEqual((dst / "core" / "a.py").read_text(encoding="utf-8"), "import argus\n")
            self.assertEqual((dst / "web" / "static" / "page.html").read_text(encoding="utf-8"), "<b>argus</b>")
            self.assertIn("jarvis", (dst / "web" / "ui" / "assets" / "app.js").read_text(encoding="utf-8"))
            self.assertIn("jarvis", (dst / "web" / "static" / "vendor" / "pinned.json").read_text(encoding="utf-8"))
            self.assertFalse((dst / "core" / "__pycache__").exists())


if __name__ == "__main__":
    unittest.main()
