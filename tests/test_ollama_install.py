"""Installing Ollama with the user's approval (jarvis/platform/ollama.py and
`jarvis model`).

Invariants under test:
  * only a published, non-prerelease release at least MIN_AGE_DAYS old is
    chosen, and the plan says which and why;
  * the file installed is the one GitHub and Ollama's own sha256sum.txt agree
    on, and the bytes on disk match it; any disagreement refuses before
    anything runs, and a mismatched download is deleted;
  * downloads go over HTTPS to GitHub's release hosts only, redirects included,
    and never past the published size;
  * nothing is downloaded or installed without a person approving the exact
    plan: a typed word on a terminal, or an explicit --yes; a non-interactive
    caller without --yes is refused;
  * on Windows the installer runs only with a valid Authenticode signature by
    Ollama; on Linux the install is per user and listens on loopback only.
"""

import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.cli.commands import model as model_cli
from jarvis.platform import ollama

DAY = 86400
NOW = 1_800_000_000


def release(tag, days_old, *, prerelease=False, draft=False, assets=None):
    stamp = __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime(NOW - days_old * DAY))
    return {"tag_name": tag, "published_at": stamp, "prerelease": prerelease, "draft": draft,
            "assets": assets if assets is not None else [
                asset("OllamaSetup.exe", b"win"), asset("ollama-linux-amd64.tar.zst", b"lin"),
                asset("ollama-linux-arm64.tar.zst", b"arm"), asset("sha256sum.txt", b"sums")]}


def asset(name, body):
    return {"name": name, "size": len(body), "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
            "browser_download_url": f"https://github.com/ollama/ollama/releases/download/vX/{name}"}


def sums(*pairs):
    return "".join(f"{hashlib.sha256(b).hexdigest()}  ./{n}\n" for n, b in pairs)


class ChooseRelease(unittest.TestCase):
    def test_newest_release_old_enough_is_chosen(self):
        rels = [release("v0.40.13", 2), release("v0.40.12", 9), release("v0.40.11", 20)]
        self.assertEqual(ollama.choose_release(rels, NOW)["tag_name"], "v0.40.12")

    def test_prereleases_drafts_and_young_releases_are_skipped(self):
        rels = [release("v0.41.0-rc1", 30, prerelease=True), release("v0.40.14", 30, draft=True),
                release("v0.40.13", 1)]
        self.assertIsNone(ollama.choose_release(rels, NOW))
        self.assertEqual(ollama.choose_release(rels, NOW, min_age_days=0)["tag_name"], "v0.40.13")

    def test_asset_for_each_platform(self):
        self.assertEqual(ollama.asset_name("windows", "AMD64"), "OllamaSetup.exe")
        self.assertEqual(ollama.asset_name("linux", "x86_64"), "ollama-linux-amd64.tar.zst")
        self.assertEqual(ollama.asset_name("linux", "aarch64"), "ollama-linux-arm64.tar.zst")
        self.assertIsNone(ollama.asset_name("linux", "riscv64"))


class Plan(unittest.TestCase):
    def test_plan_names_version_file_size_and_hash_when_sources_agree(self):
        rel = release("v0.40.12", 9)
        p = ollama.make_plan(rel, sums(("OllamaSetup.exe", b"win")), "windows", "AMD64")
        self.assertEqual(p.problems, [])
        self.assertEqual((p.version, p.asset, p.size), ("v0.40.12", "OllamaSetup.exe", 3))
        self.assertEqual(p.sha256, hashlib.sha256(b"win").hexdigest())
        text = p.describe()
        for part in ("v0.40.12", "OllamaSetup.exe", p.sha256, "github.com"):
            self.assertIn(part, text)

    def test_disagreeing_or_missing_checksums_refuse(self):
        rel = release("v0.40.12", 9)
        bad = ollama.make_plan(rel, sums(("OllamaSetup.exe", b"something else")), "windows", "AMD64")
        self.assertTrue(any("disagree" in p for p in bad.problems), bad.problems)
        missing = ollama.make_plan(rel, sums(("other.zip", b"x")), "windows", "AMD64")
        self.assertTrue(any("sha256sum.txt" in p for p in missing.problems), missing.problems)
        no_digest = dict(rel, assets=[dict(a, digest="") for a in rel["assets"]])
        nd = ollama.make_plan(no_digest, sums(("OllamaSetup.exe", b"win")), "windows", "AMD64")
        self.assertTrue(any("digest" in p for p in nd.problems), nd.problems)

    def test_an_asset_url_off_github_is_refused(self):
        rel = release("v0.40.12", 9)
        rel["assets"][0]["browser_download_url"] = "http://example.com/OllamaSetup.exe"
        p = ollama.make_plan(rel, sums(("OllamaSetup.exe", b"win")), "windows", "AMD64")
        self.assertTrue(any("github" in x.lower() for x in p.problems), p.problems)


class Download(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ollama-dl-"))
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)

    def test_hosts_are_github_release_hosts_over_https_only(self):
        ok = ("https://github.com/ollama/ollama/releases/download/v1/x",
              "https://objects.githubusercontent.com/a", "https://release-assets.githubusercontent.com/b")
        for url in ok:
            self.assertTrue(ollama.allowed_url(url), url)
        for url in ("http://github.com/x", "https://github.com.evil.test/x", "https://evil.test/x",
                    "https://user@github.com/x", "file:///etc/passwd"):
            self.assertFalse(ollama.allowed_url(url), url)

    def test_matching_bytes_are_kept_and_a_mismatch_is_deleted(self):
        body = b"installer bytes"
        dest = self.tmp / "OllamaSetup.exe"
        opener = mock.Mock(return_value=io.BytesIO(body))
        ollama.download("https://github.com/x", dest, len(body), hashlib.sha256(body).hexdigest(), opener=opener)
        self.assertEqual(dest.read_bytes(), body)
        with self.assertRaises(ollama.InstallError):
            ollama.download("https://github.com/x", dest, len(body), "0" * 64,
                            opener=mock.Mock(return_value=io.BytesIO(body)))
        self.assertFalse(dest.exists(), "a file that failed its hash must not stay on disk")

    def test_a_download_past_its_published_size_is_refused(self):
        dest = self.tmp / "big"
        with self.assertRaises(ollama.InstallError):
            ollama.download("https://github.com/x", dest, 4, hashlib.sha256(b"12345678").hexdigest(),
                            opener=mock.Mock(return_value=io.BytesIO(b"12345678")))
        self.assertFalse(dest.exists())


class WindowsInstall(unittest.TestCase):
    def test_installer_runs_only_after_a_valid_ollama_signature(self):
        self.assertEqual(ollama.signature_problem({"status": "Valid", "subject": "CN=Ollama Inc., O=Ollama Inc."}), "")
        for sig in ({"status": "NotSigned", "subject": ""}, {"status": "HashMismatch", "subject": "CN=Ollama Inc."},
                    {"status": "Valid", "subject": "CN=Someone Else"}, None):
            with self.subTest(sig=sig):
                self.assertTrue(ollama.signature_problem(sig))

    def test_install_script_passes_the_path_as_data(self):
        script = ollama.windows_install_script(r"C:\Users\O'Brien\AppData\Local\Temp\argus-ollama\OllamaSetup.exe")
        self.assertIn(r"'C:\Users\O''Brien\AppData\Local\Temp\argus-ollama\OllamaSetup.exe'", script)
        self.assertIn("Get-AuthenticodeSignature", script)
        self.assertLess(script.index("Get-AuthenticodeSignature"), script.index("Start-Process"))
        self.assertIn("/VERYSILENT", script)


class LinuxInstall(unittest.TestCase):
    def test_user_service_listens_on_loopback_only(self):
        unit = ollama.linux_unit(Path("/home/u/.local/share/argus/ollama/current"))
        self.assertIn("ExecStart=/home/u/.local/share/argus/ollama/current/bin/ollama serve", unit)
        self.assertIn("Environment=OLLAMA_HOST=127.0.0.1:11434", unit)
        self.assertNotIn("0.0.0.0", unit)

    def test_layout_is_per_user(self):
        home = Path("/home/u")
        paths = ollama.linux_paths(home, "v0.40.12")
        for p in paths.values():
            self.assertTrue(str(p).startswith(str(home)), p)


class Approval(unittest.TestCase):
    def plan(self):
        p = ollama.make_plan(release("v0.40.12", 9), sums(("OllamaSetup.exe", b"win")), "windows", "AMD64")
        self.assertEqual(p.problems, [])
        return p

    def test_typed_word_on_a_terminal_approves(self):
        with mock.patch("sys.stdin.isatty", return_value=True), mock.patch("builtins.input", return_value="install"):
            self.assertTrue(model_cli.approve(self.plan(), yes=False))
        for answer in ("y", "yes", "", "Install now"):
            with self.subTest(answer=answer), mock.patch("sys.stdin.isatty", return_value=True), \
                    mock.patch("builtins.input", return_value=answer):
                self.assertFalse(model_cli.approve(self.plan(), yes=False))

    def test_non_interactive_without_yes_is_refused_and_yes_approves(self):
        with mock.patch("sys.stdin.isatty", return_value=False):
            self.assertFalse(model_cli.approve(self.plan(), yes=False))
            self.assertTrue(model_cli.approve(self.plan(), yes=True))

    def test_a_plan_with_problems_is_never_approved(self):
        bad = ollama.make_plan(release("v0.40.12", 9), sums(("other", b"x")), "windows", "AMD64")
        with mock.patch("sys.stdin.isatty", return_value=True), mock.patch("builtins.input", return_value="install"):
            self.assertFalse(model_cli.approve(bad, yes=True))

    def test_install_downloads_nothing_without_approval(self):
        with mock.patch.object(model_cli, "current_plan", return_value=self.plan()), \
                mock.patch.object(model_cli, "approve", return_value=False), \
                mock.patch.object(ollama, "download") as dl, mock.patch.object(ollama, "install") as inst:
            code = model_cli.cmd_model(mock.Mock(action="install", yes=False, min_age_days=7), store=None)
        self.assertNotEqual(code, 0)
        dl.assert_not_called()
        inst.assert_not_called()


if __name__ == "__main__":
    unittest.main()
