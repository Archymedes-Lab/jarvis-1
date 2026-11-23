"""The publish job checks exactly the release assets, nothing from the checkout.

2026-10-30: run 41138145511 downloaded v2026.10.30-2 into release/, the
checkout's own tooling folder, so the gate saw publish.py, policy.json and
__pycache__/ beside the four artifacts and refused the release. The gate was
right; the folder was wrong. These cases pin the folder and replay the refusal.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_release_gate import GOOD_SERVER, SERVER, GateCase, tar_bytes  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"


def download_dir(text):
    m = re.search(r'gh release download\b[^\n]*\s-D\s+("[^"]+"|\S+)', text)
    return m.group(1).strip('"') if m else None


def release_arg(text):
    m = re.search(r'release/publish\.py\b[^\n]*--release\s+("[^"]+"|\S+)', text)
    return m.group(1).strip('"') if m else None


class PublishWorkflow(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text()

    def test_assets_download_outside_the_checkout(self):
        d = download_dir(self.text)
        self.assertIsNotNone(d, "publish.yml no longer downloads with -D")
        self.assertTrue(d.startswith("$RUNNER_TEMP/"), f"{d} is inside the checkout")

    def test_the_checked_folder_is_the_downloaded_one(self):
        self.assertEqual(release_arg(self.text), download_dir(self.text))

    def test_github_source_archives_are_never_fetched(self):
        commands = [ln for ln in self.text.splitlines() if "gh release download" in ln and not ln.lstrip().startswith("#")]
        self.assertTrue(commands)
        self.assertFalse(any("--archive" in ln for ln in commands), commands)

    def test_the_old_folder_collides_with_the_tooling(self):
        # Why the folder matters: a relative -D release lands in this repo's
        # own release/ folder, which holds Python source.
        self.assertTrue((ROOT / "release" / "publish.py").is_file())


class CheckoutFilesAreRefused(GateCase):
    def test_tooling_beside_the_assets_is_refused(self):
        self.publish({SERVER: tar_bytes(GOOD_SERVER)})
        (self.dir / "publish.py").write_text("print('tooling')\n")
        (self.dir / "__pycache__").mkdir()
        found = self.problems()
        self.assertTrue(any(p.startswith("publish.py:") for p in found), found)
        self.assertTrue(any(p.startswith("__pycache__/:") for p in found), found)

    def test_github_source_archive_is_refused(self):
        self.publish({SERVER: tar_bytes(GOOD_SERVER),
                      "Argus-1-2026.10.30-2.tar.gz": tar_bytes([("Argus-1/release/gate.py", b"x", 0o644)])})
        self.assertTrue(any(p.startswith("Argus-1-2026.10.30-2.tar.gz:") for p in self.problems()))

    def test_assets_alone_pass(self):
        self.publish({SERVER: tar_bytes(GOOD_SERVER)})
        self.assertEqual(self.problems(), [])


if __name__ == "__main__":
    unittest.main()
