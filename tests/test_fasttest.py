"""The fast runner may skip a module only when nothing it depends on changed."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parents[1] / "scripts" / "dev" / "fasttest.py"


def load():
    spec = importlib.util.spec_from_file_location("fasttest_under_test", HERE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class KeyInvalidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for rel, text in {
            "jarvis/__init__.py": "",
            "jarvis/a.py": "from jarvis import b\n",
            "jarvis/b.py": "PATH = 'jarvis/data/rules.json'\n",
            "jarvis/c.py": "X = 1\n",
            "jarvis/data/rules.json": "{}",
            "jarvis/data/other.ps1": "# payload",
            "tests/__init__.py": "",
            "tests/test_a.py": "from jarvis import a\n",
        }.items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)

    def tearDown(self):
        self.tmp.cleanup()

    def key(self):
        ft = load()
        ft.ROOT_S = str(self.root) + os.sep
        ft.CACHE_DIR = self.root / ".cache"
        ft.INDEX = ft.CACHE_DIR / "index.json"
        # Ignore this fixture's cache, not every file when a parent temporary
        # directory itself lives beneath the developer's .cache.
        files = [str(p.relative_to(self.root)) for p in self.root.rglob("*")
                 if p.is_file() and ".cache" not in p.relative_to(self.root).parts]
        with mock.patch.object(ft, "tracked_files", return_value=files):
            ft.load_index()
            ft.ALL_FILES.extend(files)
            for f in files:
                ft.BY_NAME.setdefault(f.rsplit("/", 1)[-1], set()).add(f)
            key, _ = ft.module_key("tests/test_a.py", ft.payload_digest())
            ft.save_index()
        return key

    def touch(self, rel, text):
        p = self.root / rel
        p.write_text(text)
        st = p.stat()
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))

    def test_unchanged_inputs_give_the_same_key(self):
        self.assertEqual(self.key(), self.key())

    def test_any_dependency_change_changes_the_key(self):
        base = self.key()
        for rel, text in (("jarvis/b.py", "PATH = 'jarvis/data/rules.json'\nY = 2\n"),   # transitive import
                          ("jarvis/data/rules.json", '{"x": 1}'),                       # named by path
                          ("jarvis/data/other.ps1", "# changed payload"),              # payload under jarvis/
                          ("tests/test_a.py", "from jarvis import a\nZ = 3\n")):        # the test itself
            with self.subTest(rel=rel):
                self.touch(rel, text)
                new = self.key()
                self.assertNotEqual(new, base)
                base = new

    def test_an_unrelated_module_does_not_invalidate(self):
        base = self.key()
        self.touch("jarvis/c.py", "X = 2\n")
        self.assertEqual(self.key(), base)


class FailuresAreNotCached(unittest.TestCase):
    def test_a_failing_module_is_rerun_next_time(self):
        ft = load()
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            ft.CACHE_DIR, ft.CACHE, ft.INDEX = d, d / "results.json", d / "index.json"
            ft.TESTS = d / "tests"
            ft.TESTS.mkdir()
            for m in ("test_good", "test_bad"):
                (ft.TESTS / f"{m}.py").write_text("X = 1\n")
            calls = []

            def fake_run(name, timeout):
                calls.append(name)
                return name, name != "test_bad", 0.1, "Ran 1 test in 0.1s\nOK"
            with mock.patch.object(ft, "run_module", fake_run), \
                    mock.patch.object(ft, "module_key", lambda rel, p: (rel + "-k", 1)), \
                    mock.patch("builtins.print"):
                self.assertEqual(ft.main(["--jobs", "1"]), 1)
                calls.clear()
                self.assertEqual(ft.main(["--jobs", "1"]), 1)
            self.assertEqual(calls, ["test_bad"])     # the pass was cached, the failure was not


if __name__ == "__main__":
    unittest.main()
