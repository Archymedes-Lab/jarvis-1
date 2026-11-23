"""Isolation, governor, untrusted-output parsing and cleanup of the disposable-guest lab."""

import base64
import hashlib
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from jarvis.lab import spyware_controls as sc
from jarvis.lab import vmlab


def cfg(root):
    return vmlab.Config(root=Path(root), kvm_gid=993, timeout_s=5)


def serial_for(data, *, tamper=False, noise=True):
    raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
    b64 = base64.b64encode(raw).decode()
    lines = ["boot noise", "\x1b[32m  OK  \x1b[0m started", vmlab.BEGIN]
    lines += [b64[i:i + 76] + ("\r" if noise else "") for i in range(0, len(b64), 76)]
    lines += [vmlab.END, vmlab.SHA + " " + ("0" * 64 if tamper else hashlib.sha256(raw).hexdigest())]
    return "\n".join(lines)


GOOD = {"results": [], "files_sha256": {}, "baseline": {}}


class DockerCommandTests(unittest.TestCase):
    def test_container_is_locked_down(self):
        with tempfile.TemporaryDirectory() as tmp:
            argv = vmlab.docker_command(cfg(tmp), Path(tmp) / "run", "jvlab-x", 993)
        joined = " ".join(argv)
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertIn("no-new-privileges", joined)
        self.assertNotIn("--privileged", argv)
        self.assertEqual([argv[i + 1] for i, a in enumerate(argv) if a == "--device"], ["/dev/kvm"])
        self.assertNotEqual(argv[argv.index("--user") + 1].split(":")[0], "0")
        self.assertIn("--read-only", argv)
        self.assertIn("--pids-limit", argv)
        self.assertIn("--cpu-shares", argv)
        mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]
        self.assertTrue(any(m.endswith("/img:ro") for m in mounts))
        self.assertEqual(len(mounts), 2)                       # image (ro) and the run dir only
        self.assertNotIn("/home", joined.replace("/home/chris/.cache", ""))

    def test_guest_has_no_host_share_audio_passthrough_or_reachable_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            argv = vmlab.docker_command(cfg(tmp), Path(tmp) / "run", "n", 993)
        q = " ".join(argv[argv.index("qemu-system-x86_64"):])
        self.assertIn("restrict=on", q)
        self.assertNotIn("virtfs", q)
        self.assertNotIn("-fsdev", q)
        self.assertIn("audiodev none", q)                       # emulated device, no host backend
        self.assertNotIn("hostfwd", q)
        self.assertIn("readonly=on", q)

    def test_helper_containers_have_the_same_restrictions_and_no_device(self):
        with tempfile.TemporaryDirectory() as tmp:
            argv = vmlab.helper_command(cfg(tmp), Path(tmp), "true")
        self.assertNotIn("--device", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")


class GovernorTests(unittest.TestCase):
    C = vmlab.Config()

    def test_idle_machine_is_not_blocked(self):
        self.assertEqual(vmlab.blockers(self.C, {"cpu_avg60": 5.0, "mem_avail_mb": 6000, "free_gb": 50}), [])

    def test_pressure_memory_and_disk_block(self):
        b = vmlab.blockers(self.C, {"cpu_avg60": 80.0, "mem_avail_mb": 900, "free_gb": 1.0})
        self.assertEqual(len(b), 3)

    def test_unknown_load_blocks_instead_of_assuming_idle(self):
        b = vmlab.blockers(self.C, {"cpu_avg60": None, "mem_avail_mb": None, "free_gb": 50})
        self.assertIn("CPU pressure is unknown", b)
        self.assertIn("available memory is unknown", b)

    def test_missing_prerequisites_are_named(self):
        b = vmlab.blockers(self.C, {"cpu_avg60": 1.0, "mem_avail_mb": 9000, "free_gb": 50},
                           docker_ok=False, image_ok=False, kvm=False, container_ok=False)
        self.assertEqual(len(b), 4)

    def test_pressure_reader_parses_and_tolerates_missing_files(self):
        files = {"/proc/pressure/cpu": "some avg10=1.00 avg60=12.50 avg300=3 total=1\n",
                 "/proc/meminfo": "MemTotal: 1 kB\nMemAvailable:    2097152 kB\n"}

        def read(path):
            if path in files:
                return files[path]
            raise OSError(path)
        p = vmlab.pressure(read)
        self.assertEqual((p["cpu_avg60"], p["mem_avail_mb"]), (12.5, 2048))
        empty = vmlab.pressure(lambda path: (_ for _ in ()).throw(OSError(path)))
        self.assertEqual((empty["cpu_avg60"], empty["mem_avail_mb"]), (None, None))


class ParseSerialTests(unittest.TestCase):
    def test_valid_result_survives_console_noise(self):
        data, problems = vmlab.parse_serial(serial_for(GOOD))
        self.assertEqual((data["results"], problems), ([], []))

    def test_tampered_hash_missing_markers_and_garbage_are_rejected_not_trusted(self):
        for text, why in ((serial_for(GOOD, tamper=True), "hash"), ("nothing here", "markers"),
                          (f"{vmlab.BEGIN}\n!!!not base64!!!\n{vmlab.END}\n{vmlab.SHA} x", "base64")):
            data, problems = vmlab.parse_serial(text)
            self.assertIsNone(data)
            self.assertTrue(any(why in p for p in problems), (why, problems))

    def test_wrong_shape_and_oversize_are_rejected(self):
        data, problems = vmlab.parse_serial(serial_for({"results": "nope"}))
        self.assertIsNone(data)
        big = "A" * (vmlab.MAX_RESULT_BYTES * 2)
        text = f"{vmlab.BEGIN}\n{big}\n{vmlab.END}\n{vmlab.SHA} x"
        data, problems = vmlab.parse_serial(text)
        self.assertIsNone(data)
        self.assertTrue(any("size cap" in p for p in problems))

    def test_guest_running_different_code_is_reported(self):
        payload = {**GOOD, "files_sha256": {"/opt/lab/x.py": "a" * 64}}
        _, problems = vmlab.parse_serial(serial_for(payload), {"/opt/lab/x.py": "b" * 64})
        self.assertTrue(any("differs" in p for p in problems))

    def test_guest_output_is_never_executed(self):
        evil = {"results": [{"id": "__import__('os').system('true')", "status": "ran"}],
                "files_sha256": {}, "baseline": {}}
        data, _ = vmlab.parse_serial(serial_for(evil))
        self.assertEqual(data["results"][0]["id"], "__import__('os').system('true')")


class PayloadTests(unittest.TestCase):
    def test_payload_holds_only_the_code_under_test_and_reports_matching_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            hashes = vmlab.build_payload(tmp, sc.by_platform("linux"))
            with tarfile.open(Path(tmp) / "payload.tar") as tar:
                names = sorted(tar.getnames())
                blob = tar.extractfile("platform_marker") if "platform_marker" in names else None
                scenarios = json.loads(tar.extractfile("scenarios.json").read())
        self.assertIsNone(blob)
        self.assertIn("lab/emu_linux.py", names)
        self.assertIn("jarvis/platform/spy_linux.py", names)
        self.assertNotIn("jarvis/response/reasoning.py", names)     # engine and adapters stay on the host
        self.assertEqual(len(scenarios), len(sc.by_platform("linux")))
        self.assertTrue(all(len(h) == 64 for h in hashes.values()))

    def test_every_payload_source_exists(self):
        base = Path(vmlab.PACKAGE_DIR).parent
        for rel in vmlab.PAYLOAD_FILES:
            self.assertTrue((base / rel).is_file(), rel)


class RunTests(unittest.TestCase):
    """Orchestration with a fake docker: blocked runs, timeouts and cleanup on every path."""

    def fake(self, tmp, *, finish=True, helper_fail=False):
        calls = []
        cfg_ = cfg(tmp)
        (Path(tmp) / "images").mkdir(exist_ok=True)

        def runner(argv, **kw):
            calls.append(list(argv))
            if argv[:3] == ["docker", "run", "--rm"] and helper_fail:
                return subprocess.CompletedProcess(argv, 1, b"", b"boom")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        class Proc:
            def __init__(self, argv, **kw):
                run_dir = Path(argv[argv.index("-v", argv.index("/tmp:rw,size=64m")) + 3].split(":")[0])
                if finish:
                    (run_dir / "serial.log").write_text(serial_for(GOOD))
            def poll(self):
                return 0
        return cfg_, runner, Proc, calls

    def run_it(self, tmp, **kw):
        c, runner, Proc, calls = self.fake(tmp, **{k: v for k, v in kw.items() if k in ("finish", "helper_fail")})
        data, report = vmlab.run_linux(
            sc.by_platform("linux"), c, runner=runner, popen=Proc, sleep=lambda s: None,
            load=kw.get("load", {"cpu_avg60": 1.0, "mem_avail_mb": 9000, "free_gb": 50}),
            verify=lambda cfg_: kw.get("verified", True))
        return data, report, calls

    def test_blocked_run_starts_nothing_and_says_why(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, report, calls = self.run_it(tmp, load={"cpu_avg60": 90.0, "mem_avail_mb": 9000, "free_gb": 50})
        self.assertIsNone(data)
        self.assertTrue(report["blocked"])
        self.assertFalse(any(a[:2] == ["docker", "run"] for a in calls))

    def test_successful_run_removes_container_and_run_dir_and_proves_base_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, report, calls = self.run_it(tmp)
            self.assertEqual(data["results"], [])
            self.assertTrue(report["isolation"]["container_removed"])
            self.assertTrue(report["isolation"]["run_dir_removed"])
            self.assertTrue(report["isolation"]["base_image_unchanged"])
            self.assertFalse(any((Path(tmp) / "runs").iterdir()))
        self.assertTrue(any(a[:3] == ["docker", "rm", "-f"] for a in calls))

    def test_helper_failure_still_cleans_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, report, calls = self.run_it(tmp, helper_fail=True)
            self.assertIsNone(data)
            self.assertTrue(any("helper" in p for p in report["problems"]))
            self.assertTrue(any(a[:3] == ["docker", "rm", "-f"] for a in calls))
            self.assertFalse(any((Path(tmp) / "runs").iterdir()))

    def test_guest_that_never_finishes_is_reported_and_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            c, runner, Proc, calls = self.fake(tmp, finish=False)
            ticks = iter(range(0, 10000, 3))
            data, report = vmlab.run_linux(
                sc.by_platform("linux"), c, runner=runner, popen=Proc, sleep=lambda s: None,
                clock=lambda: next(ticks), load={"cpu_avg60": 1.0, "mem_avail_mb": 9000, "free_gb": 50},
                verify=lambda cfg_: True)
        self.assertIsNone(data)
        self.assertTrue(any("markers not found" in p or "did not finish" in p for p in report["problems"]))
        self.assertTrue(any(a[:3] == ["docker", "rm", "-f"] for a in calls))

    def test_base_image_changing_during_the_run_is_reported(self):
        answers = iter([True, False])           # pre-flight passes, post-run check fails
        with tempfile.TemporaryDirectory() as tmp:
            c, runner, Proc, _ = self.fake(tmp)
            _, report = vmlab.run_linux(
                sc.by_platform("linux"), c, runner=runner, popen=Proc, sleep=lambda s: None,
                load={"cpu_avg60": 1.0, "mem_avail_mb": 9000, "free_gb": 50},
                verify=lambda cfg_: next(answers))
        self.assertFalse(report["isolation"]["base_image_unchanged"])

    def test_a_modified_base_image_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls_ok = self.run_it(tmp, verified=True)[1]["isolation"]["base_image_unchanged"]
        with tempfile.TemporaryDirectory() as tmp:
            # verify() is also the pre-flight check, so a bad image blocks before any guest runs.
            data, report, _ = self.run_it(tmp, verified=False)
        self.assertTrue(calls_ok)
        self.assertIsNone(data)
        self.assertTrue(any("checksum" in b for b in report["blocked"]))


if __name__ == "__main__":
    unittest.main()
