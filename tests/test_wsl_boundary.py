"""WSL boundary snapshot, checkpoint chain, and offline drift semantics."""

import io
import json
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path

from jarvis.cli.commands.timeline import cmd_timeline
from jarvis.core.execution import wsl_drift
from jarvis.platform import wsl_boundary

_REAL_SNAPSHOT = wsl_boundary.snapshot
MOUNT = ("80 62 0:51 / /mnt/c rw,noatime - 9p C:\\134 rw,aname=drvfs;path=C:;"
         "uid=1000,cache=0x5\n")


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.write("boot_id", "boot-1\n")
        self.write("osrelease", "6.18.0\n")
        self.write("mountinfo", MOUNT)
        self.write("interop", "enabled\ninterpreter /init\n")
        self.write("wsl.conf", "[boot]\nsystemd=true\n[user]\ndefault=me\n")
        self.write("wslconfig", "[wsl2]\nnetworkingMode=nat\n")

    def write(self, name, text):
        (self.d / name).write_text(text)

    def snap(self, **over):
        real = _REAL_SNAPSHOT
        args = dict(wsl_conf=str(self.d / "wsl.conf"),
                    windows_config=str(self.d / "wslconfig"),
                    mountinfo=str(self.d / "mountinfo"),
                    interop=str(self.d / "interop"),
                    boot_id=str(self.d / "boot_id"),
                    kernel=str(self.d / "osrelease"),
                    sockets=(str(self.d / "docker.sock"),),
                    path_env="/usr/bin:/mnt/c/Windows")
        args.update(over)
        return real(**args)


class SnapshotTests(Fixture):
    def test_reads_boundary_facts_and_ignores_unlisted_keys(self):
        self.write("wsl.conf", "[boot]\nsystemd=true\nsecret=abc\n")
        facts = self.snap()["facts"]
        self.assertEqual(facts["wsl_conf.boot.systemd"], "true")
        self.assertEqual(facts["wslconfig.wsl2.networkingmode"], "nat")
        self.assertEqual(facts["drvfs.mount[/mnt/c]"], "rw")
        self.assertEqual(facts["interop.binfmt"], "enabled")
        self.assertEqual(facts["path.windows_dirs"], "1")
        self.assertEqual(facts["docker.socket"], "absent")
        self.assertNotIn("abc", json.dumps(facts))

    def test_absent_config_is_defined_but_unreadable_is_unknown(self):
        snap = self.snap(wsl_conf=str(self.d / "nope"),
                         mountinfo=str(self.d / "nomount" / "x"))
        self.assertEqual(snap["sources"]["wsl_conf"]["status"], "absent")
        self.assertEqual(snap["sources"]["drvfs"]["status"], "unavailable")

    def test_missing_windows_config_path_is_unavailable(self):
        self.assertEqual(self.snap(windows_config=None)
                         ["sources"]["windows_wslconfig"]["status"], "unavailable")


class DriftTests(Fixture):
    def baseline(self):
        return [wsl_drift.make_entry(self.snap())]

    def test_no_baseline_is_not_clean(self):
        self.assertEqual(wsl_drift.compare([], self.snap())["status"], "no_baseline")

    def test_unchanged_matches(self):
        self.assertEqual(wsl_drift.compare(self.baseline(), self.snap())["status"],
                         "matches_checkpoint")

    def test_offline_change_across_boot_is_offline_drift_and_critical(self):
        entries = self.baseline()
        self.write("boot_id", "boot-2\n")
        self.write("wslconfig", "[wsl2]\nnetworkingMode=nat\nkernel=C:\\\\evil\n")
        result = wsl_drift.compare(entries, self.snap())
        self.assertEqual(result["status"], "drift")
        self.assertTrue(result["offline"])
        f = result["findings"][0]
        self.assertEqual((f["kind"], f["change"], f["critical"]),
                         ("OFFLINE_STATE_DRIFT", "added", True))

    def test_same_boot_change_is_runtime_drift(self):
        entries = self.baseline()
        self.write("interop", "disabled\n")
        f = wsl_drift.compare(entries, self.snap())["findings"][0]
        self.assertEqual(f["kind"], "STATE_DRIFT")

    def test_boot_change_without_difference_is_not_drift(self):
        entries = self.baseline()
        self.write("boot_id", "boot-2\n")
        self.assertEqual(wsl_drift.compare(entries, self.snap())["status"],
                         "matches_checkpoint")

    def test_lost_source_is_evidence_lost_not_removal_or_clean(self):
        entries = self.baseline()
        result = wsl_drift.compare(entries, self.snap(windows_config=None))
        self.assertEqual(result["status"], "evidence_lost")
        self.assertTrue(all(f["kind"] == "EVIDENCE_LOST" for f in result["findings"]))

    def test_new_drvfs_mount_and_docker_socket_reported(self):
        entries = self.baseline()
        self.write("mountinfo", MOUNT + MOUNT.replace("/mnt/c", "/mnt/d"))
        (self.d / "docker.sock").write_text("")
        names = {f["fact"] for f in wsl_drift.compare(entries, self.snap())["findings"]}
        self.assertEqual(names, {"drvfs.mount[/mnt/d]", "docker.socket"})

    def test_tampered_or_reordered_chain_is_invalid(self):
        first = wsl_drift.make_entry(self.snap())
        second = wsl_drift.make_entry(self.snap(), first)
        self.assertTrue(wsl_drift.verify_chain([first, second])[0])
        forged = json.loads(json.dumps(first))
        forged["facts"]["interop.binfmt"] = "disabled"
        for chain in ([forged, second], [second, first], [second]):
            self.assertFalse(wsl_drift.verify_chain(chain)[0])
        self.assertEqual(wsl_drift.compare([forged], self.snap())["status"],
                         "checkpoint_invalid")

    def test_cannot_checkpoint_without_boot_id(self):
        with self.assertRaises(ValueError):
            wsl_drift.make_entry(self.snap(boot_id=str(self.d / "missing")))


class CliTests(Fixture):
    def run_cli(self, ckpt, accept=False):
        from unittest.mock import patch
        args = Namespace(action="wsl-boundary", json=True, limit=10,
                         checkpoint=str(ckpt), wslconfig=str(self.d / "wslconfig"),
                         accept=accept)
        buf = io.StringIO()
        with patch("jarvis.platform.wsl_boundary.snapshot",
                   side_effect=lambda **kw: self.snap(**{k: v for k, v in kw.items()
                                                         if k == "windows_config"})), \
                redirect_stdout(buf):
            code = cmd_timeline(args, None)
        return code, json.loads(buf.getvalue())

    def test_comparison_never_writes_and_accept_appends_private_chain(self):
        ckpt = self.d / "state" / "chain.jsonl"
        code, out = self.run_cli(ckpt)
        self.assertEqual((code, out["status"]), (0, "no_baseline"))
        self.assertFalse(ckpt.exists())
        _, out = self.run_cli(ckpt, accept=True)
        self.assertTrue(out["accepted"])
        self.assertEqual(ckpt.stat().st_mode & 0o777, 0o600)
        self.write("interop", "disabled\n")
        _, out = self.run_cli(ckpt)
        self.assertEqual(out["status"], "drift")
        self.assertEqual(len(ckpt.read_text().splitlines()), 1)  # no silent rebaseline
        self.run_cli(ckpt, accept=True)
        self.assertEqual(len(ckpt.read_text().splitlines()), 2)
        self.assertTrue(wsl_drift.verify_chain(
            [json.loads(x) for x in ckpt.read_text().splitlines()])[0])

    def test_corrupt_checkpoint_file_refuses_accept(self):
        ckpt = self.d / "chain.jsonl"
        ckpt.write_text("{not json\n")
        code, out = self.run_cli(ckpt, accept=True)
        self.assertEqual((code, out["status"], out["accepted"]),
                         (1, "checkpoint_invalid", False))
        self.assertEqual(ckpt.read_text(), "{not json\n")

    def test_non_utf8_checkpoint_is_invalid_not_a_crash(self):
        ckpt = self.d / "chain.jsonl"
        ckpt.write_bytes(b'{"seq": 1}\xff\xfe\n')
        code, out = self.run_cli(ckpt)
        self.assertEqual((code, out["status"]), (1, "checkpoint_invalid"))


if __name__ == "__main__":
    unittest.main()
