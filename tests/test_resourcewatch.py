import json
import os
import tempfile
import unittest
from unittest.mock import patch

from jarvis.collectors.process import resourcewatch
from jarvis.core.store import Store


class ResourceWatchTests(unittest.TestCase):
    def test_resource_owners_separate_jarvis_ollama_and_browser(self):
        self.assertEqual(resourcewatch._owner({
            "name": "python3", "cmdline": "python3 -m jarvis serve"}),
            "jarvis engine")
        self.assertEqual(resourcewatch._owner({"name": "ollama.exe"}), "ollama")
        self.assertEqual(resourcewatch._owner({"name": "msedge.exe"}), "browser")

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tempdir.name, "jarvis.db"))
        # These tests cover process, guest-memory and disk checks; the Windows
        # commit read has its own tests and must never reach a live bridge here.
        self._host = [patch("jarvis.collectors.process.resourcewatch._host_memory_findings",
                            return_value=([], None)),
                      patch("jarvis.collectors.process.resourcewatch._host_memory",
                            return_value=None),
                      patch("jarvis.collectors.process.resourcewatch._swap_findings",
                            return_value=[])]
        for p in self._host:
            p.start()

    def tearDown(self):
        for p in self._host:
            p.stop()
        self.store.close()
        self.tempdir.cleanup()

    def test_sustained_cpu_is_calculated_from_two_samples(self):
        key = "wsl:42:fp"
        self.store.set_meta(resourcewatch._META, json.dumps({
            "ts": 700.0, "processes": {key: {"cpu": 100.0}}
        }))
        proc = {"host": "wsl", "pid": 42, "fp": "fp", "name": "worker",
                "exe": "/opt/worker", "rss_bytes": 100, "cpu_seconds": 400.0}
        with patch("jarvis.collectors.process.resourcewatch.time.time", return_value=1000.0), \
             patch("jarvis.collectors.process.resourcewatch.monitor.collect_all", return_value=[proc]), \
             patch("jarvis.collectors.process.resourcewatch.os.cpu_count", return_value=4), \
             patch("jarvis.collectors.process.resourcewatch._memory_pressure", return_value=(100, 100)), \
             patch("jarvis.collectors.process.resourcewatch.os.path.exists", return_value=False):
            findings = resourcewatch.audit(self.store, hosts=("wsl",))

        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("25.0%", findings[0]["detail"])
        self.assertNotIn("command", findings[0]["detail"])

    def sample(self, proc, previous_cpu=100.0, previous_ts=700.0):
        key = f"{proc['host']}:{proc['pid']}:fp"
        self.store.set_meta(resourcewatch._META, json.dumps({
            'ts': previous_ts, 'processes': {key: {'cpu': previous_cpu}}}))
        with patch('jarvis.collectors.process.resourcewatch.time.time', return_value=1000.0), \
             patch('jarvis.collectors.process.resourcewatch.monitor.collect_all', return_value=[proc]), \
             patch('jarvis.collectors.process.resourcewatch.os.cpu_count', return_value=4), \
             patch('jarvis.collectors.process.resourcewatch._memory_pressure', return_value=(100, 100)), \
             patch('jarvis.collectors.process.resourcewatch.os.path.exists', return_value=False):
            return resourcewatch.audit(self.store)

    def windows_process(self, **changes):
        return dict({'host': 'win', 'pid': 42, 'fp': 'fp', 'name': 'worker',
                     'exe': '', 'rss_bytes': 100, 'cpu_seconds': 2020.0,
                     'logical_cpus': 16}, **changes)

    def test_idle_counter_is_not_consumption_or_a_saved_baseline(self):
        findings = self.sample(self.windows_process(pid=0, name='(unattributed)',
                                                    cpu_seconds=100000.0))
        self.assertEqual(findings[0]['severity'], 'ok')
        self.assertEqual(json.loads(self.store.get_meta(resourcewatch._META))['processes'], {})

    def test_windows_uses_host_capacity_not_wsl_capacity(self):
        findings = self.sample(self.windows_process())
        self.assertEqual(findings[0]['severity'], 'medium')
        self.assertIn('40.0% of total CPU', findings[0]['detail'])

    def test_real_windows_high_cpu_still_alerts(self):
        findings = self.sample(self.windows_process(cpu_seconds=2980.0))
        self.assertEqual(findings[0]['severity'], 'high')
        self.assertIn('60.0%', findings[0]['detail'])

    def test_impossible_counter_or_clock_jump_is_visibility_not_pressure(self):
        for cpu, timestamp in ((10000, 700), (1, 700), (2020, 1100)):
            with self.subTest(cpu=cpu, timestamp=timestamp):
                findings = self.sample(self.windows_process(cpu_seconds=cpu), previous_ts=timestamp)
                self.assertEqual([f['title'] for f in findings],
                                 ['process CPU measurement unavailable'])

    def test_missing_windows_capacity_preserves_high_memory_alert(self):
        findings = self.sample(self.windows_process(logical_cpus=0, rss_bytes=5 * 1024**3))
        self.assertEqual(findings[0]['severity'], 'high')
        self.assertIn('CPU usage unavailable', findings[0]['detail'])
        self.assertTrue(any(f['title'] == 'process CPU measurement unavailable' for f in findings))


if __name__ == "__main__":
    unittest.main()


GIB = 1024 ** 3


class HostCommitTests(unittest.TestCase):
    """Windows commit is what runs out before WSL dies (2026-10-11 panics)."""

    NOW = 2_000_000_000.0

    def reading(self, committed, limit=25 * GIB, **extra):
        return dict({"committed": committed, "limit": limit, "vm": 9.7 * GIB,
                     "apps": [{"name": "firefox", "bytes": 2 * GIB}],
                     "panics": []}, **extra)

    def findings(self, data, cache=5.7 * GIB):
        return resourcewatch._host_memory_findings(data, cache, self.NOW)

    def test_commit_at_crash_level_is_high_and_attributes_wsl_cache(self):
        findings, profile = self.findings(self.reading(24.5 * GIB, 24.9 * GIB))
        self.assertEqual([f["severity"] for f in findings], ["high"])
        detail = findings[0]["detail"]
        self.assertIn("98%", detail)
        self.assertIn("WSL VM holds 9.7 GiB", detail)
        self.assertIn("5.7 GiB is Linux file cache", detail)
        self.assertIn("firefox 2.0 GiB", detail)
        self.assertEqual(findings[0]["host"], "win")
        self.assertEqual(profile["status"], "measured")

    def test_thresholds_medium_then_quiet(self):
        medium, _ = self.findings(self.reading(22 * GIB))     # 88%
        quiet, profile = self.findings(self.reading(15 * GIB))  # 60%
        self.assertEqual([f["severity"] for f in medium], ["medium"])
        self.assertEqual(quiet, [])
        self.assertEqual(profile["pct"], 60.0)

    def test_cache_share_never_exceeds_the_vm(self):
        findings, _ = self.findings(self.reading(24 * GIB, vm=2 * GIB), cache=7 * GIB)
        self.assertIn("about 2.0 GiB is Linux file cache", findings[0]["detail"])

    def test_bridge_failure_is_unmeasured_never_healthy(self):
        findings, profile = self.findings(None)
        self.assertEqual(profile, {"status": "unmeasured"})
        self.assertEqual(findings[0]["title"], "host memory commit unmeasured")
        self.assertIn("unknown, not healthy", findings[0]["detail"])

    def test_implausible_counters_are_unmeasured_not_clamped(self):
        for bad in ({"committed": 30 * GIB, "limit": 25 * GIB},
                    {"committed": 1 * GIB, "limit": 0},
                    {"committed": "n/a", "limit": 25 * GIB},
                    {"committed": float("nan"), "limit": 25 * GIB},
                    {"error": "Access denied"}):
            findings, profile = self.findings(bad)
            self.assertEqual(profile["status"], "unmeasured", bad)
            self.assertEqual([f["title"] for f in findings],
                             ["host memory commit unmeasured"], bad)
            self.assertNotIn("high", [f["severity"] for f in findings])

    def test_recent_guest_panic_is_reported_with_memory_signature(self):
        data = self.reading(15 * GIB, panics=[
            {"at": self.NOW - 3600, "mce": True},
            {"at": self.NOW - 30 * 3600, "mce": False},   # outside 24 h
            {"at": "garbage"}])
        findings, profile = self.findings(data)
        self.assertEqual(profile["guest_panics_24h"], 1)
        self.assertEqual([f["title"] for f in findings], ["WSL VM crashed"])
        self.assertIn("Fatal machine check", findings[0]["detail"])
        self.assertIn("60m ago", findings[0]["detail"])

    def test_panic_without_signature_does_not_claim_a_memory_cause(self):
        findings, _ = self.findings(self.reading(15 * GIB, panics=[
            {"at": self.NOW - 60, "mce": False}]))
        self.assertIn("does not name a memory cause", findings[0]["detail"])

    def test_guest_cache_excludes_shared_memory(self):
        meminfo = ("MemTotal: 100 kB\nCached: 4000 kB\nSReclaimable: 1000 kB\n"
                   "Shmem: 500 kB\n")
        with patch("builtins.open", unittest.mock.mock_open(read_data=meminfo)):
            self.assertEqual(resourcewatch._guest_cache(), 4500 * 1024)
        with patch("builtins.open", side_effect=OSError):
            self.assertIsNone(resourcewatch._guest_cache())

    def test_audit_wires_commit_into_findings_and_profile(self):
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        store = Store(os.path.join(tempdir.name, "jarvis.db"))
        self.addCleanup(store.close)
        mod = "jarvis.collectors.process.resourcewatch"
        with patch(f"{mod}.monitor.collect_all", return_value=[]), \
             patch(f"{mod}._memory_pressure", return_value=(100, 100)), \
             patch(f"{mod}.os.path.exists", return_value=False), \
             patch(f"{mod}.machine.has_windows", return_value=True), \
             patch(f"{mod}.machine.on_wsl", return_value=True), \
             patch(f"{mod}._guest_cache", return_value=5 * GIB), \
             patch(f"{mod}._host_memory", return_value=self.reading(24.5 * GIB, 24.9 * GIB)), \
             patch(f"{mod}._swap_findings", return_value=[]):
            findings = resourcewatch.audit(store)
        self.assertEqual(findings[0]["title"], "host memory commit pressure")
        profile = json.loads(store.get_meta(resourcewatch.PROFILE_META))
        self.assertEqual(profile["host_memory"]["status"], "measured")
        self.assertNotIn("system resource headroom is healthy",
                         [f["title"] for f in findings])

    def test_audit_without_windows_host_skips_the_read(self):
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        store = Store(os.path.join(tempdir.name, "jarvis.db"))
        self.addCleanup(store.close)
        mod = "jarvis.collectors.process.resourcewatch"
        with patch(f"{mod}.monitor.collect_all", return_value=[]), \
             patch(f"{mod}._memory_pressure", return_value=(100, 100)), \
             patch(f"{mod}.os.path.exists", return_value=False), \
             patch(f"{mod}._host_memory") as read:
            findings = resourcewatch.audit(store, hosts=("wsl",))
        read.assert_not_called()
        self.assertEqual(findings[0]["severity"], "ok")


class SwapHealthTests(unittest.TestCase):
    """2026-10-11: C: full -> swap disk offline -> daemon killed with SIGBUS."""

    NOW = 2_000_000_000.0

    class Meta(dict):
        def get_meta(self, key, default=""):
            return self.get(key, default)

        def set_meta(self, key, value):
            self[key] = value

    def run_checks(self, data=None, errors=(0, 0), swap=(8 * GIB, 1.5 * GIB), offline=()):
        store = self.Meta()
        return resourcewatch._swap_findings(store, data, self.NOW, errors=errors,
                                            swap=swap, offline=list(offline)), store

    def test_full_system_drive_is_critical_and_names_the_measured_crash(self):
        findings, _ = self.run_checks(data={"sys_drive_free": 0.1 * GIB})
        hit = [f for f in findings if f["title"].startswith("Windows system drive nearly full")]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "critical")
        self.assertIn("2026-10-23", hit[0]["detail"])
        self.assertIn("set-sparse", hit[0]["detail"])
        # Low but not yet fatal is high; comfortable headroom is silent.
        findings, _ = self.run_checks(data={"sys_drive_free": 5 * GIB})
        self.assertEqual([f["severity"] for f in findings
                          if f["title"].startswith("Windows system drive")], ["high"])
        findings, _ = self.run_checks(data={"sys_drive_free": 40 * GIB})
        self.assertEqual([f for f in findings if f["title"].startswith("Windows system drive")], [])
        findings, _ = self.run_checks(data={"sys_drive_free": "n/a"})
        self.assertEqual([f for f in findings if f["title"].startswith("Windows system drive")], [])

    def test_offline_swap_device_is_high_and_names_the_fix(self):
        findings, _ = self.run_checks(offline=["sdc"])
        self.assertEqual([(f["severity"], f["title"]) for f in findings],
                         [("high", "WSL swap device is offline")])
        self.assertIn("sdc", findings[0]["detail"])
        self.assertIn("wsl --shutdown", findings[0]["detail"])

    def test_swap_errors_since_last_check_are_high(self):
        findings, store = self.run_checks(errors=(530, 0))
        self.assertEqual([f["title"] for f in findings], ["WSL swap device is failing"])
        self.assertIn("530", findings[0]["detail"])
        self.assertEqual(store[resourcewatch.KERNEL_IO_SINCE_META], str(self.NOW))

    def test_other_block_errors_are_reported_separately(self):
        findings, _ = self.run_checks(errors=(0, 3))
        self.assertEqual([f["title"] for f in findings], ["WSL disk I/O errors"])

    def test_unreadable_journal_is_not_clean_and_keeps_the_window(self):
        with patch("jarvis.collectors.process.resourcewatch._kernel_io_errors",
                   return_value=None):
            store = self.Meta({resourcewatch.KERNEL_IO_SINCE_META: "123"})
            findings = resourcewatch._swap_findings(store, None, self.NOW,
                                                    swap=(8 * GIB, 0), offline=[])
        self.assertEqual(findings, [])
        # The next readable run re-reads from the old point; nothing is skipped.
        self.assertEqual(store[resourcewatch.KERNEL_IO_SINCE_META], "123")

    def test_swap_that_cannot_grow_into_its_drive_is_high(self):
        data = {"swap_file": 0.5 * GIB, "swap_drive_free": 0.2 * GIB}
        findings, _ = self.run_checks(data=data)
        self.assertEqual([f["title"] for f in findings], ["WSL swap cannot grow"])
        self.assertIn("7.5 GiB", findings[0]["detail"])
        self.assertEqual(findings[0]["host"], "win")

    def test_room_to_grow_and_healthy_device_report_nothing(self):
        data = {"swap_file": 0.5 * GIB, "swap_drive_free": 13.6 * GIB}
        findings, _ = self.run_checks(data=data)
        self.assertEqual(findings, [])

    def test_missing_swap_reading_makes_no_growth_claim(self):
        for data in (None, {}, {"swap_file": "x", "swap_drive_free": 1}):
            findings, _ = self.run_checks(data=data)
            self.assertEqual(findings, [], data)

    def test_kernel_parser_separates_swap_device_lines(self):
        log = ("Write-error on swap-device (8:32:3697000)\n"
               "I/O error, dev sdc, sector 3696424 op 0x1:(WRITE) flags 0x0\n"
               "Read-error on swap-device (8:32:1)\n"
               "I/O error, dev sdd, sector 9 op 0x1:(WRITE) flags 0x0\n"
               "unrelated line\n")
        result = unittest.mock.Mock(returncode=0, stdout=log.encode())
        with patch("subprocess.run", return_value=result), \
             patch("builtins.open", unittest.mock.mock_open(
                 read_data="Filename Type Size Used Priority\n/dev/sdc partition 8 1 -2\n")):
            self.assertEqual(resourcewatch._kernel_io_errors(0), (2, 1))
        failed = unittest.mock.Mock(returncode=1, stdout=b"")
        with patch("subprocess.run", return_value=failed):
            self.assertIsNone(resourcewatch._kernel_io_errors(0))
