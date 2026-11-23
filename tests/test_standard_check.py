"""scripts/dev/standard_check.py enforces the machine-checkable rules of
docs/security/ARCHYMEDES-SECURITY-STANDARD.md (§23). Each case builds a small git
repository in a temp folder, so refusals and passes are tested on real files."""

import datetime
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "dev"))
import standard_check as sc  # noqa: E402

PINNED = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
GOOD_WF = f"""name: ok
on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - uses: {PINNED}
        with:
          persist-credentials: false
      - run: echo "$TITLE"
        env:
          TITLE: ${{{{ github.event.pull_request.title }}}}
"""


class Repo:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)

    def write(self, rel, text, mode="w"):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if mode == "wb":
            p.write_bytes(text)
        else:
            p.write_text(text)
        subprocess.run(["git", "-C", str(self.root), "add", rel], check=True)

    def checks(self, today=None):
        return sc.run(self.root, today)

    def close(self):
        self.tmp.cleanup()


class Case(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()

    def tearDown(self):
        self.repo.close()

    def ids(self, today=None):
        return sorted({c for c, _w, _m in self.repo.checks(today)})


class Workflows(Case):
    def test_a_hardened_workflow_passes(self):
        self.repo.write(".github/workflows/ok.yml", GOOD_WF)
        self.assertEqual(self.repo.checks(), [])

    def test_missing_permissions_and_write_all(self):
        self.repo.write(".github/workflows/a.yml", GOOD_WF.replace("permissions:\n  contents: read\n", ""))
        self.assertIn("SC-1", self.ids())
        self.repo.write(".github/workflows/a.yml", GOOD_WF.replace("permissions:\n  contents: read", "permissions: write-all"))
        self.assertIn("SC-1", self.ids())

    def test_tags_and_branches_are_not_pins(self):
        for ref in ("actions/checkout@v4", "actions/checkout@main", "actions/checkout@3d3c42e"):
            with self.subTest(ref=ref):
                self.repo.write(".github/workflows/a.yml", GOOD_WF.replace(PINNED, ref))
                self.assertIn("SC-4", self.ids())

    def test_local_actions_need_no_pin(self):
        self.repo.write(".github/workflows/a.yml", GOOD_WF + "      - uses: ./.github/actions/local\n")
        self.assertEqual(self.ids(), [])

    def test_pull_request_target_is_refused(self):
        self.repo.write(".github/workflows/a.yml", GOOD_WF.replace("on: push", "on: pull_request_target"))
        self.assertIn("SC-5", self.ids())

    def test_checkout_must_drop_credentials_unless_justified(self):
        bare = GOOD_WF.replace("        with:\n          persist-credentials: false\n", "")
        self.repo.write(".github/workflows/a.yml", bare)
        self.assertIn("SC-6", self.ids())
        justified = bare.replace(f"      - uses: {PINNED}", f"      # ases: push - this job tags the release\n      - uses: {PINNED}")
        self.repo.write(".github/workflows/a.yml", justified)
        self.assertNotIn("SC-6", self.ids())

    def test_untrusted_event_text_in_run_is_refused(self):
        inj = GOOD_WF + '      - run: echo "${{ github.event.pull_request.title }}"\n'
        self.repo.write(".github/workflows/a.yml", inj)
        self.assertIn("SC-7", self.ids())
        multi = GOOD_WF + "      - run: |\n          git checkout ${{ github.head_ref }}\n"
        self.repo.write(".github/workflows/a.yml", multi)
        self.assertIn("SC-7", self.ids())

    def test_trusted_context_in_run_passes(self):
        ok = GOOD_WF + '      - run: echo "${{ github.sha }} ${{ inputs.tag }}"\n'
        self.repo.write(".github/workflows/a.yml", ok)
        self.assertNotIn("SC-7", self.ids())


class Secrets(Case):
    def test_tokens_and_keys_in_code_are_refused(self):
        self.repo.write("app/config.py", 'TOKEN = "ghp_' + "a1B2" * 9 + '"\n')
        self.repo.write("app/key.pem", "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "b3Bl" * 20 + "\n")
        self.repo.write("app/aws.txt", "AKIA" + "ABCDEFGHIJKLMNOP\n")
        found = {(c, w.split(":")[0]) for c, w, _m in self.repo.checks()}
        self.assertEqual(found, {("SC-10", "app/config.py"), ("SC-10", "app/key.pem"), ("SC-10", "app/aws.txt")})

    def test_key_headers_without_material_and_docs_pass(self):
        # A scanner's own rules name key headers; docs and tests describe formats.
        self.repo.write("app/rules.py", 'RX = r"-----BEGIN ((?:RSA )?PRIVATE KEY)-----"\n')
        self.repo.write("docs/secrets.md", "ghp_" + "x" * 36 + "\n")
        self.assertEqual(self.ids(), [])


class Locks(Case):
    def test_manifest_without_lockfile(self):
        self.repo.write("ui/package.json", "{}")
        self.assertIn("SC-20", self.ids())
        self.repo.write("ui/bun.lock", "{}")
        self.assertEqual(self.ids(), [])

    def test_cargo_workspace_member_uses_the_workspace_lock(self):
        self.repo.write("Cargo.toml", "[workspace]\nmembers = ['a']\n")
        self.repo.write("Cargo.lock", "")
        self.repo.write("a/Cargo.toml", "[package]\nname='a'\n")
        self.assertEqual(self.ids(), [])

    def test_release_requirements_must_be_hash_pinned(self):
        self.repo.write("release/requirements-x.txt", "nuitka==4.3\n")
        self.assertIn("SC-20", self.ids())
        self.repo.write("release/requirements-x.txt",
                        "nuitka==4.3 --hash=sha256:" + "0" * 64 + "\nfoo==1.0 \\\n    --hash=sha256:" + "1" * 64 + "\n")
        self.assertEqual(self.ids(), [])
        self.repo.write("release/requirements-x.txt", "nuitka>=4\n")
        self.assertIn("SC-20", self.ids())


class Waivers(Case):
    def test_active_waiver_suppresses_and_expired_one_is_a_finding(self):
        self.repo.write("ui/package.json", "{}")
        today = datetime.date(2026, 11, 1)
        self.repo.write("docs/security/exceptions.md", "- SC-20 ui/package.json  owner: x  expires: 2026-12-01\n")
        self.assertEqual(self.ids(today), [])
        self.repo.write("docs/security/exceptions.md", "- SC-20 ui/package.json  owner: x  expires: 2026-10-01\n")
        self.assertEqual(self.ids(today), ["EXC", "SC-20"])


class ThisRepository(unittest.TestCase):
    def test_the_repository_meets_the_standard(self):
        self.assertEqual(sc.run(ROOT), [])


if __name__ == "__main__":
    unittest.main()
