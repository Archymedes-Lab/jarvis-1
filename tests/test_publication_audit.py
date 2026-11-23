"""Publication audit failure paths use isolated synthetic Git histories."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1] / "scripts" / "dev"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location("publication_audit", TOOLS / "publication_audit.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class PublicationAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic")
        self.git("config", "user.email", "synthetic@example.invalid")
        (self.root / "README").write_text("synthetic clean source")
        self.commit()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True,
                              capture_output=True).stdout

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "synthetic fixture")

    def test_clean_scan_cannot_authorize_publication(self):
        report = audit.scan(self.root)
        self.assertTrue(report["scan_complete"])
        self.assertEqual(report["detections"], {})
        self.assertFalse(report["publication_authorized"])

    def test_deleted_secret_in_docs_is_detected_without_disclosure(self):
        docs = self.root / "docs"
        docs.mkdir()
        secret = "ghp_" + "A" * 36
        path = docs / "private-example.txt"
        path.write_text(secret)
        self.commit()
        path.unlink()
        self.commit()
        report = audit.scan(self.root)
        self.assertTrue(report["scan_complete"])
        self.assertEqual(report["detections"]["github-token"], 1)
        self.assertNotIn(secret, json.dumps(report))
        self.assertNotIn(path.name, json.dumps(report))

    def test_budget_exhaustion_and_oversize_are_incomplete(self):
        for kwargs in ({"max_bytes": 0}, {"max_seconds": 0}):
            self.assertFalse(audit.scan(self.root, **kwargs)["scan_complete"])
        with mock.patch.object(audit, "MAX_OBJECT", 0):
            report = audit.scan(self.root)
        self.assertFalse(report["scan_complete"])
        self.assertGreater(report["oversize_objects_skipped"], 0)

    def test_interrupt_and_timeout_are_incomplete_without_retry(self):
        for error in (KeyboardInterrupt(), subprocess.TimeoutExpired("synthetic", 1)):
            with mock.patch.object(audit, "git", side_effect=error) as call:
                report = audit.scan(self.root)
            self.assertFalse(report["scan_complete"])
            self.assertEqual(call.call_count, 1)

    def test_changed_refs_invalidate_completed_scan(self):
        real = audit.git
        calls = 0

        def changed(root, *args, **kwargs):
            nonlocal calls
            data = real(root, *args, **kwargs)
            if args == ("show-ref",):
                calls += 1
                if calls == 2:
                    return data + b"changed"
            return data

        with mock.patch.object(audit, "git", side_effect=changed):
            self.assertFalse(audit.scan(self.root)["scan_complete"])
