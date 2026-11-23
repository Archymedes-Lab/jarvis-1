"""Process-truth identity, source failure, and coverage-gated contradictions."""

import io
import json
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from jarvis.cli.commands.timeline import cmd_timeline
from jarvis.core.execution.linux_truth import reconcile
from jarvis.platform import linux_truth


def _stat(pid, start, cpu=0, ppid=1):
    fields = ["S", str(ppid)] + ["0"] * 18
    fields[11], fields[12], fields[19] = str(cpu), "2", str(start)
    return f"{pid} (name with ) bracket) " + " ".join(fields) + "\n"


class LinuxTruthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.proc = Path(self.tmp.name) / "proc"
        (self.proc / "sys/kernel/random").mkdir(parents=True)
        (self.proc / "sys/kernel/random/boot_id").write_text("boot-one\n")

    def _task(self, pid=42, start=100, uid=1000, caps="0000000000000000",
              ppid=1):
        base = self.proc / str(pid)
        (base / "task" / str(pid)).mkdir(parents=True)
        (base / "ns").mkdir()
        (base / "fd").mkdir()
        (base / "stat").write_text(_stat(pid, start, ppid=ppid))
        (base / "task" / str(pid) / "stat").write_text(_stat(pid, start, ppid=ppid))
        (base / "status").write_text(
            f"Name:\tworker\nPid:\t{pid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
            f"Threads:\t1\nCapEff:\t{caps}\n")
        (base / "cgroup").write_text("0::/user.slice/example.service\n")
        (base / "ns/pid").symlink_to("pid:[4026531836]")
        exe = Path(self.tmp.name) / "worker"
        exe.write_bytes(b"binary")
        (base / "exe").symlink_to(exe)
        return base

    def test_snapshot_keeps_start_identity_threads_and_explicit_gaps(self):
        base = self._task()
        (base / "fd/3").symlink_to("socket:[12345]")
        (base / "fd/4").symlink_to(Path(self.tmp.name) / "worker")
        result = linux_truth.snapshot(proc=str(self.proc))
        self.assertEqual(result["represented_processes"], 1)
        self.assertEqual(result["represented_threads"], 1)
        self.assertEqual(result["represented_fds"], 2)
        row = result["processes"][0]
        self.assertIn("boot-one:pid:[4026531836]:42:100", row["key"])
        self.assertEqual(row["threads"][0]["tid"], 42)
        self.assertEqual(row["capabilities"]["CapEff"], "0000000000000000")
        self.assertEqual(row["entity_type"], "user_process")
        self.assertEqual(row["fds"][0]["kind"], "socket")
        self.assertEqual(row["fds"][1]["kind"], "file_or_device")
        self.assertEqual(result["event_stream"], "unavailable")
        self.assertEqual(result["status"], "partial")
        self.assertNotIn("binary", json.dumps(result))

    def test_missing_proc_is_unavailable_not_empty_healthy(self):
        result = linux_truth.snapshot(proc=str(self.proc / "missing"))
        self.assertEqual(result["status"], "unavailable")
        self.assertTrue(result["errors"])

    def test_budget_truncation_and_pid_reuse_are_reported(self):
        self._task()
        self._task(pid=43, start=200)
        result = linux_truth.snapshot(proc=str(self.proc), max_processes=1)
        self.assertTrue(result["budget_exhausted"])
        self.assertEqual(result["represented_processes"], 1)
        original = linux_truth._read
        reads = [0]

        def replaced(path):
            value = original(path)
            if path == str(self.proc / "42/stat"):
                reads[0] += 1
                if reads[0] == 2:
                    return _stat(42, 999)
            return value

        with patch.object(linux_truth, "_read", side_effect=replaced):
            result = linux_truth.snapshot(proc=str(self.proc))
        self.assertEqual(result["represented_processes"], 1)
        self.assertTrue(any("pid 42" in e for e in result["errors"]))

    def test_descriptor_budget_and_parent_link_are_explicit(self):
        parent = self._task(pid=42, start=50)
        self._task(pid=43, start=100, ppid=42)
        (parent / "fd/3").symlink_to("pipe:[77]")
        (parent / "fd/4").symlink_to("socket:[88]")
        result = linux_truth.snapshot(proc=str(self.proc), max_fds=1)
        self.assertTrue(result["budget_exhausted"])
        self.assertEqual(result["represented_fds"], 1)
        self.assertTrue(result["processes"][0]["fds_truncated"])
        # Both fixtures report PPid=1, which was not enumerated.
        self.assertIsNone(result["processes"][0]["parent_key"])
        full = linux_truth.snapshot(proc=str(self.proc))
        self.assertEqual(full["processes"][1]["parent_key"],
                         full["processes"][0]["key"])

    def test_executable_mappings_are_instance_guarded_and_bounded(self):
        base = self._task()
        (base / "maps").write_text(
            "00400000-00401000 r-xp 00000000 08:01 20 /usr/bin/worker\n"
            "00500000-00502000 r-xp 00000000 00:00 0\n"
            "00600000-00601000 rw-p 00000000 00:00 0\n")
        result = linux_truth.executable_mappings(42, proc=str(self.proc),
                                                 expected_start_ticks=100)
        self.assertEqual([m["kind"] for m in result["mappings"]],
                         ["file_backed", "anonymous"])
        self.assertNotIn("/usr/bin/worker", json.dumps(result))
        self.assertEqual(linux_truth.executable_mappings(
            42, proc=str(self.proc), expected_start_ticks=200)["status"],
            "identity_changed")
        with self.assertRaises(ValueError):
            linux_truth.executable_mappings(42, proc=str(self.proc))

    def test_lifecycle_contradiction_requires_continuous_matching_receipt(self):
        self._task()
        current = linux_truth.snapshot(proc=str(self.proc))
        key = current["processes"][0]["key"]
        receipt = {"status": "complete", "boot_id": "boot-one",
                   "source_id": "fixture-lifecycle", "receipt_verified": True,
                   "attachment_verified": True, "cursor_continuous": True,
                   "policy_covers_fork": True, "loss_count": 0,
                   "since_start_ticks": 50, "through_start_ticks": 200,
                   "covered_pid_namespaces": ["pid:[4026531836]"],
                   "created_keys": []}
        self.assertEqual(reconcile(current, lifecycle=receipt)["counts"]["unexplained"], 1)
        for override in ({"loss_count": 1}, {"boot_id": "another-boot"},
                         {"status": "stale"}, {"since_start_ticks": 101},
                         {"receipt_verified": False}, {"cursor_continuous": False},
                         {"attachment_verified": False},
                         {"covered_pid_namespaces": []},
                         {"through_start_ticks": 99},
                         {"settle_ticks": 101}):
            self.assertEqual(reconcile(current, lifecycle=receipt | override)
                             ["counts"]["unexplained"], 0)
        self.assertEqual(reconcile(current, lifecycle=receipt | {"created_keys": [key]})
                         ["counts"]["matched_lifecycle"], 1)
        self.assertEqual(reconcile(current | {"errors": ["restricted"]},
                                   lifecycle=receipt)["counts"]["unexplained"], 0)

    def test_privilege_change_is_snapshot_evidence_only(self):
        self._task()
        before = linux_truth.snapshot(proc=str(self.proc))
        (self.proc / "42/status").write_text(
            "Name:\tworker\nPid:\t42\nUid:\t0\t0\t0\t0\nThreads:\t1\nCapEff:\t0000000000200000\n")
        after = linux_truth.snapshot(proc=str(self.proc))
        result = reconcile(after, previous=before)
        self.assertEqual(result["counts"]["privilege_changes"], 1)
        self.assertIn("actor unknown", result["findings"][0]["basis"])
        after["boot_id"] = "boot-two"
        self.assertEqual(reconcile(after, previous=before)["counts"]["privilege_changes"], 0)

    def test_cli_reads_truth_without_requiring_eventlog(self):
        self._task()
        args = Namespace(action="linux-truth", json=True, limit=1, deep_pid=None)
        buf = io.StringIO()
        real_snapshot = linux_truth.snapshot
        with patch("jarvis.platform.linux_truth.snapshot",
                   side_effect=lambda: real_snapshot(proc=str(self.proc))), redirect_stdout(buf):
            code = cmd_timeline(args, None)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buf.getvalue())["snapshot"]["represented_processes"], 1)


if __name__ == "__main__":
    unittest.main()
