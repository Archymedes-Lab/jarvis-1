"""Isolated release staging and runtime integrity failures."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.stage_mesh_publisher import stage


class MeshReleaseTests(unittest.TestCase):
    def test_sealed_release_runs_without_checkout_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            release = stage(Path(__file__).resolve().parents[1], Path(directory) / 'releases')
            self.assertFalse((release / 'jarvis/core/store.py').exists())
            result = subprocess.run(['python3', '-I', str(release / 'launch.py'), '--help'],
                                    cwd='/', capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b'--peer', result.stdout)
            self.assertEqual((release / 'launch.py').stat().st_mode & 0o777, 0o444)
            with self.assertRaises(FileExistsError):
                stage(Path(__file__).resolve().parents[1], Path(directory) / 'releases')
            self.unseal(release)

    def test_changed_dependency_refuses_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            release = stage(Path(__file__).resolve().parents[1], Path(directory) / 'releases')
            target = release / 'jarvis/platform/peerledger/publisher.py'
            target.chmod(0o600)
            target.write_text('raise RuntimeError("tampered")')
            result = subprocess.run(['python3', '-I', str(release / 'launch.py'), '--help'],
                                    capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'integrity failure', result.stderr)
            self.unseal(release)

    @staticmethod
    def unseal(release):
        for directory, _, _ in os.walk(release):
            Path(directory).chmod(0o700)
