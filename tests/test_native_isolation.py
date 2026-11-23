"""Independent native channel receipts must fail closed during migration and outages."""

import hashlib
import json
import shutil
import subprocess
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jarvis.core import telemetry
from jarvis.core.eventlog import EventLog
from jarvis.platform.native import ingest


class IsolatedHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.spool = Path(self.temp.name)
        (self.spool / "mode.json").write_text('{"mode":"isolated","schema":1}')

    def receipt(self, channel, *, age=0, sensor="sensor", status="complete", sequence=1):
        directory = self.spool / hashlib.sha256(channel.encode()).hexdigest()[:16]
        directory.mkdir(exist_ok=True)
        (directory / "health.json").write_text(json.dumps({
            "schema": 2, "sensor_id": sensor, "device_id": "device",
            "service": ingest.ISOLATED_SERVICES[channel],
            "time": datetime.fromtimestamp(time.time() - age, timezone.utc).isoformat(),
            "channels": {channel: {"status": status, "last_sequence": sequence}},
            "spool_bytes": 100, "spool_capacity": 1000,
        }))

    def test_three_fresh_receipts_compose_without_rewriting_spool(self):
        for channel in ingest.ISOLATED_CHANNELS:
            self.receipt(channel)
        health = ingest.read_health(self.spool)
        self.assertEqual(health["status"], "complete")
        self.assertEqual(set(health["channels"]), set(ingest.ISOLATED_CHANNELS))
        self.assertEqual(health["spool_bytes"], 300)

    def test_missing_and_stale_channels_cannot_become_complete(self):
        first, second, third = ingest.ISOLATED_CHANNELS
        self.receipt(first)
        self.receipt(second, age=ingest.HEALTH_STALE + 60)
        health = ingest.read_health(self.spool)
        self.assertEqual(health["status"], "unavailable")
        self.assertEqual(health["channels"][first]["status"], "complete")
        self.assertEqual(health["channels"][second]["status"], "unavailable")
        self.assertEqual(health["channels"][third]["status"], "unavailable")

    def test_identity_disagreement_does_not_fall_back_to_untrusted_scan(self):
        for index, channel in enumerate(ingest.ISOLATED_CHANNELS):
            self.receipt(channel, sensor="other" if index == 2 else "sensor")
        health = ingest.read_health(self.spool)
        self.assertEqual(health["status"], "unavailable")
        with EventLog(self.spool / "history", writer=True) as log:
            self.assertEqual(ingest._manifest_channels(log, self.spool, health, 10), [])

    def test_invalid_mode_receipt_blocks_legacy_health(self):
        (self.spool / "mode.json").write_text('{"mode":"unknown"}')
        (self.spool / "health.json").write_text(json.dumps({"status": "complete"}))
        self.assertEqual(ingest.read_health(self.spool)["status"], "unreadable")

    def test_monitor_channel_hashes_match_ingestion_directories(self):
        script = (Path(__file__).resolve().parents[1] / "windows-sensor" /
                  "monitor-isolated.ps1").read_text()
        for channel, service in ingest.ISOLATED_SERVICES.items():
            digest = hashlib.sha256(channel.encode()).hexdigest()[:16]
            self.assertIn(f"Name='{service}'; Hash='{digest}'", script)

    def test_telemetry_keeps_successful_channels_visible_during_one_failure(self):
        first, second, third = ingest.ISOLATED_CHANNELS
        for channel in (first, second):
            self.receipt(channel)
        health = ingest.read_health(self.spool)
        report = {"health": health, "channels": [
            {"channel": first, "events": 3, "backlog": 0, "gaps": [], "error": None},
            {"channel": second, "events": 0, "backlog": 0, "gaps": [], "error": None}],
            "events": 3, "batches": 1, "installed": True}
        chain = telemetry.collect(report, verify_at=time.time(), freshness_limit=180)
        self.assertEqual(chain["channels"][first]["fresh"]["state"], "ok")
        self.assertEqual(chain["channels"][second]["fresh"]["state"], "ok")
        self.assertEqual(chain["channels"][third]["fresh"]["state"], "down")



class InstallerHandoffTests(unittest.TestCase):
    INSTALLER = Path(__file__).resolve().parents[1] / "windows-sensor" / "install-isolated.ps1"

    def test_stopped_publisher_handoff_self_test(self):
        # Stopping the legacy service mid-pass leaves a sparse aggregate
        # receipt; the handoff must continue from each channel's immutable
        # head and still reject a foreign sensor or a cursor rewind. Rollback
        # must also move isolated health.json receipts out of the channel
        # directories, where the legacy binary would read one as its cursor.
        powershell, wslpath = shutil.which("powershell.exe"), shutil.which("wslpath")
        if not powershell or not wslpath:
            self.skipTest("Windows PowerShell unavailable")
        script = subprocess.run([wslpath, "-w", str(self.INSTALLER)], capture_output=True,
                                text=True, check=True).stdout.strip()
        done = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                               "Bypass", "-File", script, "-SelfTest"], cwd="/",
                              capture_output=True, text=True, timeout=90)
        self.assertEqual(done.returncode, 0, done.stderr[-500:])
        self.assertIn("stopped cursor continuity self-test passed", done.stdout)

    def test_service_account_command_avoids_dropped_empty_password(self):
        # Windows PowerShell 5.1 drops an empty native argument, so sc.exe
        # rejected `password= ""` and the first cutover rolled back.
        commands = [line.strip() for line in self.INSTALLER.read_text().splitlines()
                    if line.strip().startswith("& (Join-Path $Sys32 'sc.exe') config")]
        self.assertIn("& (Join-Path $Sys32 'sc.exe') config $name obj= $account | Out-Null", commands)
        self.assertEqual([line for line in commands if "password=" in line], [])

    def test_monitor_task_is_not_registered_through_native_quoting(self):
        # `schtasks /tr "...-File \"C:\Program Files\...\""` was split at the
        # space by Windows PowerShell 5.1 and the third cutover rolled back.
        lines = [line.strip() for line in self.INSTALLER.read_text().splitlines()]
        self.assertEqual([line for line in lines if line.startswith("& schtasks.exe")], [])
        self.assertTrue(any(line.startswith("Register-ScheduledTask") for line in lines))

if __name__ == "__main__":
    unittest.main()
