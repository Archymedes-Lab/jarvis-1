"""Keyboard readers and hidden staging (jarvis/collectors/host/keyreaders.py):
each test names the invariant it holds. A synthetic /proc, /sys and root stand
in; nothing reads this machine's processes or input devices."""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.host import keyreaders


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="keyreaders-")
        self.proc = os.path.join(self.tmp, "proc")
        self.sys = os.path.join(self.tmp, "sys")
        self.root = os.path.join(self.tmp, "root")
        for d in (self.proc, self.sys, self.root):
            os.makedirs(d)
        # event0 is a keyboard (KEY_A = bit 30), event1 a mouse.
        for n, bits in (("0", "40000000"), ("1", "0")):
            d = os.path.join(self.sys, f"class/input/event{n}/device/capabilities")
            os.makedirs(d)
            with open(os.path.join(d, "key"), "w") as fh:
                fh.write(bits + "\n")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def process(self, pid, comm, exe, devices, readable=True):
        d = os.path.join(self.proc, str(pid))
        os.makedirs(d)
        with open(os.path.join(d, "comm"), "w") as fh:
            fh.write(comm + "\n")
        if exe:
            os.symlink(exe, os.path.join(d, "exe"))
        if readable:
            os.makedirs(os.path.join(d, "fd"))
            for i, dev in enumerate(devices):
                os.symlink(dev, os.path.join(d, "fd", str(i + 3)))

    def run_audit(self, owner=lambda p: True):
        with mock.patch.object(keyreaders, "_root_only", lambda p: not p.startswith(("/home", "/tmp"))):
            return keyreaders.audit(proc=self.proc, sysfs=self.sys, root=self.root, owner=owner)


class Readers(Fixture):
    def test_unpackaged_program_in_home_reading_keyboard_is_high(self):
        self.process(100, "update-notifier", "/home/u/.cache/upd", ["/dev/input/event0"])
        f = [f for f in self.run_audit() if f["category"] == "spyware"]
        self.assertEqual((f[0]["severity"], f[0]["title"]), ("high", "update-notifier reads the keyboard"))

    def test_expected_daemon_needs_its_image_not_its_name(self):  # I2
        self.process(101, "systemd-logind", "/usr/lib/systemd/systemd-logind", ["/dev/input/event0"])
        self.process(102, "systemd-logind", "/tmp/.x/logind", ["/dev/input/event0"])
        out = [f for f in self.run_audit() if f["category"] == "spyware"]
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "high")
        self.assertEqual(out[0]["where"], "/tmp/.x/logind")

    def test_mouse_only_is_quiet_hidraw_and_uinput_are_named(self):
        self.process(103, "mouse-thing", "/home/u/m", ["/dev/input/event1"])
        self.process(104, "fido", "/usr/bin/fido-helper", ["/dev/hidraw0", "/dev/uinput"])
        out = [f for f in self.run_audit() if f["category"] == "spyware"]
        self.assertEqual([f["title"] for f in out], ["fido reads the input injection and raw HID"])
        self.assertEqual(out[0]["severity"], "low")

    def test_packaged_keylogger_is_high(self):
        self.process(105, "logkeys", "/usr/bin/logkeys", ["/dev/input/event0"])
        f = [f for f in self.run_audit() if f["category"] == "spyware"][0]
        self.assertEqual(f["severity"], "high")
        self.assertIn("keylogger", f["detail"])

    def test_deleted_image_is_high(self):
        self.process(106, "Xorg", "/usr/lib/xorg/Xorg (deleted)", ["/dev/input/event0"])
        self.assertEqual([f for f in self.run_audit() if f["category"] == "spyware"][0]["severity"], "high")

    def test_unreadable_image_is_unverified_not_cleared(self):  # I1
        self.process(107, "Xorg", None, ["/dev/input/event0"])
        f = [f for f in self.run_audit() if f["category"] == "spyware"][0]
        self.assertEqual(f["severity"], "medium")
        self.assertIn("unverified", f["detail"])

    def test_unreadable_descriptors_are_said(self):  # I1
        self.process(108, "x", "/usr/bin/x", [], readable=False)
        vis = [f for f in self.run_audit() if f["category"] == "visibility"]
        self.assertTrue(vis and "could not be read" in vis[0]["detail"])

    def test_no_package_tool_is_unknown_not_unowned(self):  # I1
        self.process(109, "kbd-daemon", "/usr/bin/kbd-daemon", ["/dev/input/event0"])
        f = [f for f in self.run_audit(owner=lambda p: None) if f["category"] == "spyware"][0]
        self.assertEqual(f["severity"], "medium")

    def test_one_finding_per_program(self):
        for pid in (110, 111, 112):
            self.process(pid, "spy", "/home/u/spy", ["/dev/input/event0"])
        out = [f for f in self.run_audit() if f["category"] == "spyware"]
        self.assertEqual(len(out), 1)
        self.assertIn("110, 111, 112", out[0]["detail"])


class Staging(Fixture):
    def make(self, rel, data=b"", mode=0o644):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data)
        os.chmod(p, mode)
        return p

    def test_hidden_folder_in_var_log_is_high(self):
        os.makedirs(os.path.join(self.root, "var/log/.ICE-unix"))
        f = [f for f in self.run_audit() if "hidden" in f["title"]]
        self.assertEqual((f[0]["severity"], f[0]["title"]), ("high", "hidden folder in /var/log: .ICE-unix"))

    def test_hidden_executable_in_shm_but_not_data(self):
        self.make("dev/shm/.k", b"\x7fELF\x02\x01")
        self.make("dev/shm/.org.chromium.Chromium.abc", b"shared memory")
        self.make("tmp/.X0-lock", b"  1234\n")
        out = [f["title"] for f in self.run_audit() if "hidden" in f["title"]]
        self.assertEqual(out, ["hidden executable in /dev/shm: .k"])

    def test_allowed_run_entries_are_quiet(self):
        self.make("run/.containerenv", b"")
        self.assertFalse([f for f in self.run_audit() if "hidden" in f["title"]])

    def test_content_is_never_read_beyond_magic(self):  # I3
        p = self.make("tmp/.data", b"SECRET" * 1000)
        reads = []
        real_open = open

        def spy_open(path, mode="r", *a, **k):
            fh = real_open(path, mode, *a, **k)
            if path == p:
                orig = fh.read
                fh.read = lambda n=-1: reads.append(n) or orig(n)
            return fh
        with mock.patch("builtins.open", spy_open):
            keyreaders.staging_findings(self.root)
        self.assertTrue(all(n == 4 for n in reads))

    def test_entry_count_is_bounded(self):  # I4
        for i in range(keyreaders.MAX_ENTRIES + 10):
            self.make(f"var/tmp/f{i}", b"")
        out, problems = keyreaders.staging_findings(self.root)
        self.assertEqual((out, problems), ([], []))


if __name__ == "__main__":
    unittest.main()
