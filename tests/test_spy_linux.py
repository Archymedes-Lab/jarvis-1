"""Linux spyware evidence reader against a fabricated /proc and /sys."""

import os
import tempfile
import unittest
from pathlib import Path

from jarvis.core.reasoning import engine
from jarvis.platform import spy_linux


def _stat(pid, start):
    fields = ["S", "1"] + ["0"] * 18
    fields[19] = str(start)
    return f"{pid} (worker) " + " ".join(fields) + "\n"


class LinuxEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.proc, self.sys = self.root / "proc", self.root / "sys"
        (self.proc / "sys/kernel/random").mkdir(parents=True)
        (self.proc / "sys/kernel/random/boot_id").write_text("boot-1\n")
        (self.proc / "net").mkdir()
        (self.proc / "net/tcp").write_text("  sl local rem st\n")
        (self.proc / "net/tcp6").write_text("  sl local rem st\n")

    def task(self, pid, *, exe, fds=(), start=100, ppid=1, readable_fd=True):
        base = self.proc / str(pid)
        (base / "ns").mkdir(parents=True)
        os.symlink("pid:[4026531836]", base / "ns/pid")
        (base / "stat").write_text(_stat(pid, start).replace(" 1 ", f" {ppid} ", 1))
        (base / "comm").write_text("worker\n")
        if exe:
            os.symlink(exe, base / "exe")
        if readable_fd:
            (base / "fd").mkdir()
            for i, target in enumerate(fds):
                os.symlink(target, base / "fd" / str(i))

    def run_all(self):
        subs, cov = spy_linux.subjects(str(self.proc), str(self.sys))
        return {s.label + s.key.split(":")[-2]: s for s in subs}, cov

    def keyboard(self, n, has_a):
        d = self.sys / f"class/input/event{n}/device/capabilities"
        d.mkdir(parents=True)
        # KEY_A is bit 30; a pointer-only device has only button bits.
        (d / "key").write_text("0 40000000" if has_a else "1f0000 0 0 0 0")

    def test_capture_devices_map_to_capabilities_and_key_is_boot_pidns_pid_start(self):
        self.keyboard(3, True)
        self.task(10, exe="/tmp/x/agent", fds=["/dev/input/event3", "/dev/video0",
                                               "/dev/snd/pcmC0D0c", "/dev/snd/pcmC0D0p",
                                               "/dev/uinput", "/dev/null"])
        subs, cov = self.run_all()
        s = subs["worker10"]
        kinds = sorted(o.kind for o in s.observations)
        self.assertEqual(kinds, ["cap.audio.mic", "cap.input.injection", "cap.keyboard.evdev",
                                 "cap.video.camera"])
        self.assertEqual(s.key, "linux:boot-1:pid:[4026531836]:10:100")
        self.assertEqual(s.path_class, "temp")
        self.assertEqual(cov["status"], "complete")

    def test_pointer_only_event_device_is_not_a_keyboard(self):
        self.keyboard(4, False)
        self.task(11, exe="/usr/bin/tool", fds=["/dev/input/event4"])
        s = self.run_all()[0]["worker11"]
        self.assertEqual(s.observations, [])

    def test_playback_pcm_and_ordinary_files_are_ignored(self):
        self.task(12, exe="/usr/bin/player", fds=["/dev/snd/pcmC0D0p", "/home/u/x.txt", "pipe:[1]"])
        self.assertEqual(self.run_all()[0]["worker12"].observations, [])

    def test_deleted_or_memfd_image_is_concealment(self):
        self.task(13, exe="/opt/tool/bin (deleted)")
        self.task(14, exe="/memfd:payload (deleted)")
        subs, _ = self.run_all()
        for name in ("worker13", "worker14"):
            r = engine.assess(subs[name])
            self.assertEqual(r["verdict"], "VISIBILITY_CONTRADICTION", name)

    def test_unreadable_process_is_unknown_never_clean(self):
        self.task(15, exe=None, readable_fd=False)
        subs, cov = self.run_all()
        s = subs["worker15"]
        self.assertEqual(cov["unreadable"], 1)
        self.assertEqual(cov["status"], "partial")
        self.assertEqual(engine.assess(s)["degraded_sources"], ["proc:unreadable"])
        self.assertEqual(engine.assess(s)["verdict"], "NO_SIGNAL")

    def test_external_established_socket_is_egress_and_private_is_not(self):
        # 8.8.8.8:443 (little-endian hex 08080808) and 10.0.0.5 (0500000A)
        (self.proc / "net/tcp").write_text(
            "  sl local rem st tx rx tr tm retr uid timeout inode\n"
            "   0: 0100007F:1F90 08080808:01BB 01 0:0 00:0 0 1000 0 111\n"
            "   1: 0100007F:1F91 0500000A:01BB 01 0:0 00:0 0 1000 0 222\n"
            "   2: 0100007F:1F92 08080808:01BB 06 0:0 00:0 0 1000 0 333\n")
        self.task(16, exe="/usr/bin/a", fds=["socket:[111]"])
        self.task(17, exe="/usr/bin/b", fds=["socket:[222]"])
        self.task(18, exe="/usr/bin/c", fds=["socket:[333]"])
        subs, _ = self.run_all()
        self.assertEqual([o.kind for o in subs["worker16"].observations], ["egress.external"])
        self.assertEqual(subs["worker17"].observations, [])
        self.assertEqual(subs["worker18"].observations, [])   # TIME_WAIT-style state ignored

    def test_kernel_threads_are_skipped_and_scan_is_bounded(self):
        self.task(2, exe=None, readable_fd=False)
        self.task(19, exe="/usr/bin/k", ppid=2)
        for pid in range(100, 110):
            self.task(pid, exe="/usr/bin/z")
        subs, _ = spy_linux.subjects(str(self.proc), str(self.sys), limit=3)
        self.assertLessEqual(len(subs), 3)

    def test_kernel_thread_name_with_a_real_image_and_system_name_from_home_are_masquerade(self):
        self.task(30, exe="/home/u/.cache/x/agent")
        (self.proc / "30/comm").write_text("kworker/0:1\n")
        self.task(31, exe="/home/u/.cache/sshd")
        (self.proc / "31/comm").write_text("sshd\n")
        self.task(32, exe="/usr/sbin/sshd")
        (self.proc / "32/comm").write_text("sshd\n")
        subs = {s.key.split(":")[-2]: s for s in spy_linux.subjects(str(self.proc), str(self.sys))[0]}
        self.assertEqual(engine.assess(subs["30"])["verdict"], "VISIBILITY_CONTRADICTION")
        self.assertEqual(engine.assess(subs["31"])["verdict"], "VISIBILITY_CONTRADICTION")
        self.assertEqual(engine.assess(subs["32"])["verdict"], "NO_SIGNAL")

    def test_missing_proc_is_unavailable(self):
        subs, cov = spy_linux.subjects(str(self.root / "nope"), str(self.sys))
        self.assertEqual((subs, cov["status"]), ([], "unavailable"))

    def test_stat_comm_with_parentheses_does_not_break_identity(self):
        self.task(20, exe="/usr/bin/q")
        (self.proc / "20/stat").write_text("20 (a) b) S 1 " + " ".join(["0"] * 17) + " 777 0\n")
        self.assertTrue(any(s.key.endswith(":777") for s in self.run_all()[0].values()))


if __name__ == "__main__":
    unittest.main()
