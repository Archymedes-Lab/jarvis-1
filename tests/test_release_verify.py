"""verify_release: manifest, checksums and URLs must agree with the real files."""

import hashlib
import http.server
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
import verify_release as vr  # noqa: E402

FILES = {"Argus-Setup.exe": b"MZ installer", "argus-server-linux-x86_64.tar.gz": b"tar",
         "argus-server_2026.11.3_amd64.deb": b"deb"}


def release(files=FILES, version="2026.11.3", tweak=None):
    d = Path(tempfile.mkdtemp(prefix="argus-rel-"))
    meta = {}
    for n, b in files.items():
        (d / n).write_bytes(b)
        meta[n] = {"bytes": len(b), "sha256": hashlib.sha256(b).hexdigest()}
    (d / "manifest.json").write_text(json.dumps({"version": version, "files": meta}))
    sums = "".join(f"{m['sha256']}  {n}\n" for n, m in meta.items())
    (d / "SHA256SUMS").write_text(sums)
    (d / "SHA256SUMS.txt").write_text(sums)
    if tweak:
        tweak(d)
    return d


class FolderTest(unittest.TestCase):
    def test_a_consistent_release_passes(self):
        self.assertEqual(vr.check_folder(release()), [])

    def test_a_changed_artifact_is_caught(self):
        d = release(tweak=lambda d: (d / "Argus-Setup.exe").write_bytes(b"MZ tampered with"))
        text = " ".join(vr.check_folder(d))
        self.assertIn("size", text)
        self.assertIn("SHA-256 differs", text)

    def test_missing_and_extra_files_are_caught(self):
        def tweak(d):
            (d / "argus-server_2026.11.3_amd64.deb").unlink()
            (d / "extra.bin").write_bytes(b"x")
        text = " ".join(vr.check_folder(release(tweak=tweak)))
        self.assertIn("in the manifest but not in the folder", text)
        self.assertIn("extra.bin is in the folder but not in the manifest", text)

    def test_checksum_files_must_match_the_manifest(self):
        d = release(tweak=lambda d: (d / "SHA256SUMS").write_text("0" * 64 + "  Argus-Setup.exe\n"))
        self.assertIn("SHA256SUMS does not list exactly", " ".join(vr.check_folder(d)))

    def test_a_wrong_version_in_a_file_name_is_caught(self):
        files = {k: v for k, v in FILES.items() if "deb" not in k}
        files["argus-server_2026.10.30_amd64.deb"] = b"old"
        self.assertIn("carries version 2026.10.30", " ".join(vr.check_folder(release(files))))

    def test_a_release_without_the_windows_installer_is_refused(self):
        files = {k: v for k, v in FILES.items() if k != "Argus-Setup.exe"}
        self.assertIn("the release has no Argus-Setup.exe", " ".join(vr.check_folder(release(files))))


class UrlTest(unittest.TestCase):
    def serve(self, directory, hide=()):
        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **k):
                super().__init__(*a, directory=str(directory), **k)

            def do_GET(self):
                if self.path.lstrip("/") in hide:
                    self.send_error(404)
                else:
                    super().do_GET()

            def log_message(self, *a):
                pass
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_address[1]}/"

    def test_urls_that_serve_the_manifests_bytes_pass(self):
        d = release()
        self.assertEqual(vr.check_urls(d, self.serve(d)), [])

    def test_a_404_and_a_different_file_are_caught(self):
        d = release()
        live = release(files={**FILES, "Argus-Setup.exe": b"MZ something else"})
        text = " ".join(vr.check_urls(d, self.serve(live, hide=("argus-server-linux-x86_64.tar.gz",))))
        self.assertIn("HTTP 404", text)
        self.assertIn("serves different bytes", text)

    def test_an_unreachable_site_is_a_problem_not_a_pass(self):
        self.assertTrue(vr.check_urls(release(), "http://127.0.0.1:9/"))


if __name__ == "__main__":
    unittest.main()
