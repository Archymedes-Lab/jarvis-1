"""Boot chain and kernel attack surface (jarvis/collectors/host/bootchain.py):
each test names the invariant it holds. A synthetic root stands in for /boot,
/etc, /proc/sys and the package logs; nothing reads this machine's boot files."""

import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from jarvis.collectors.host import bootchain


class MetaStore:
    def __init__(self):
        self.meta = {}

    def get_meta(self, key, default=""):
        return self.meta.get(key, default)

    def set_meta(self, key, value):
        self.meta[key] = value


class Root(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="bootchain-")
        self.store = MetaStore()
        self.owned = set()
        for rel, text in (("boot/vmlinuz-6.8.0-45-generic", "kernel"), ("boot/initrd.img-6.8.0-45-generic", "initrd"),
                          ("boot/grub/grub.cfg", "menuentry 'Ubuntu'\n"), ("etc/default/grub", "GRUB_TIMEOUT=0\n"),
                          ("etc/grub.d/10_linux", "#!/bin/sh\n"), ("etc/initramfs-tools/hooks/zz-ok", "#!/bin/sh\n")):
            self.write(rel, text)
            self.owned.add(os.path.join(self.root, rel))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, rel, text):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(text)
        return p

    def owner(self, path):
        return path in self.owned

    def run_audit(self, now=None):
        return bootchain.audit(self.store, now=now, root=self.root, owner=self.owner)

    def dpkg_log(self, when):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(when))
        self.write("var/log/dpkg.log", f"{stamp} upgrade linux-image-generic:amd64 6.8.0.45 6.8.0.47\n"
                                       f"{stamp} trigproc initramfs-tools:all 0.142 <none>\n")


class Boot(Root):
    def test_first_run_learns_then_reports_unexplained_change(self):  # I2
        self.assertFalse([f for f in self.run_audit() if f["category"] == "persistence"])
        self.write("boot/initrd.img-6.8.0-45-generic", "initrd with an implant")
        out = self.run_audit()
        f = [f for f in out if f["title"] == f"boot file changed: {self.root}/boot/initrd.img-6.8.0-45-generic"][0]
        self.assertEqual(f["severity"], "high")
        self.assertIn("no package update", f["detail"])

    def test_package_update_lowers_but_never_hides(self):  # I3
        self.run_audit()
        self.write("boot/vmlinuz-6.8.0-47-generic", "new kernel")
        self.dpkg_log(time.time())
        out = self.run_audit()
        f = [f for f in out if "vmlinuz-6.8.0-47" in f["title"]][0]
        self.assertEqual(f["severity"], "low")
        self.assertIn("during a package update", f["detail"])

    def test_unrelated_package_update_does_not_explain(self):  # I3
        self.run_audit()
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.write("var/log/dpkg.log", f"{stamp} upgrade nginx:amd64 1.24.0-1 1.24.0-2\n")
        self.write("boot/initrd.img-6.8.0-45-generic", "initrd with an implant")
        f = [f for f in self.run_audit() if "initrd.img" in f["title"]][0]
        self.assertEqual(f["severity"], "high")

    def test_package_update_long_ago_does_not_explain(self):  # I3
        self.run_audit()
        self.dpkg_log(time.time() - 6 * 3600)
        self.write("etc/default/grub", "GRUB_CMDLINE_LINUX=\"init=/tmp/x\"\n")
        f = [f for f in self.run_audit() if "etc/default/grub" in f["title"]][0]
        self.assertEqual(f["severity"], "medium")

    def test_unowned_hook_reported_on_first_run(self):  # I2
        self.write("etc/initramfs-tools/hooks/zz-persist", "#!/bin/sh\ncp /tmp/x $DESTDIR/sbin\n")
        out = self.run_audit()
        self.assertIn("boot hook no package installed: zz-persist", {f["title"] for f in out})
        self.assertNotIn("boot hook no package installed: zz-ok", {f["title"] for f in out})

    def test_a_newly_watched_pattern_is_learned_not_added(self):
        # State from a release that did not watch udev rules yet.
        self.run_audit()
        st = json.loads(self.store.meta[bootchain.STATE_META])
        st["patterns"] = [p for p, k in bootchain.WATCHED if k != "udev"]
        self.store.meta[bootchain.STATE_META] = json.dumps(st)
        self.write("etc/udev/rules.d/70-snap.rules", 'SUBSYSTEM=="net", RUN+="/usr/lib/snapd/snap-device-helper"\n')
        self.assertFalse([f for f in self.run_audit() if "70-snap.rules" in f["title"]])
        # Once learned, a change to it is reported.
        self.write("etc/udev/rules.d/70-snap.rules", 'SUBSYSTEM=="net", NAME="x"\n')
        self.assertTrue([f for f in self.run_audit() if "70-snap.rules" in f["title"]])

    def test_false_added_events_from_an_old_state_are_dropped(self):
        st = {"learned_at": time.time() - 100, "files": {}, "events": [
            {"ts": time.time(), "path": "/etc/udev/rules.d/70-snap.snapd.rules", "kind": "udev", "how": "added",
             "sev": "medium", "ctime": 1},
            {"ts": time.time(), "path": "/etc/default/grub", "kind": "config", "how": "changed", "sev": "medium",
             "ctime": 1}]}
        self.store.meta[bootchain.STATE_META] = json.dumps(st)
        titles = {f["title"] for f in self.run_audit()}
        self.assertNotIn("boot file added: /etc/udev/rules.d/70-snap.snapd.rules", titles)
        self.assertIn("boot file changed: /etc/default/grub", titles)

    def test_a_newly_watched_risky_file_still_reports_at_once(self):
        self.run_audit()
        st = json.loads(self.store.meta[bootchain.STATE_META])
        st["patterns"] = [p for p, k in bootchain.WATCHED if k != "udev"]
        self.store.meta[bootchain.STATE_META] = json.dumps(st)
        self.write("etc/udev/rules.d/99-x.rules", 'RUN+="/var/tmp/.x"\n')
        self.assertIn("udev rule runs a program from outside the system: 99-x.rules",
                      {f["title"] for f in self.run_audit()})

    def test_unowned_hook_added_later_is_one_finding(self):
        self.run_audit()
        self.write("etc/initramfs-tools/hooks/zz-late", "#!/bin/sh\n")
        hits = [f for f in self.run_audit() if "zz-late" in f["title"]]
        self.assertEqual([f["title"] for f in hits], ["boot hook no package installed: zz-late"])

    def test_unknown_owner_is_not_unowned(self):  # I1
        self.write("etc/grub.d/41_custom", "#!/bin/sh\n")
        out = bootchain.audit(self.store, root=self.root, owner=lambda p: None)
        self.assertFalse([f for f in out if f["title"].startswith("boot hook no package")])

    def test_package_owner_is_unknown_without_a_package_tool(self):  # I1
        with mock.patch("shutil.which", return_value=None):
            self.assertIsNone(bootchain.package_owner("/etc/grub.d/10_linux"))

    def test_backdated_large_image_still_detected(self):  # I4
        with mock.patch.object(bootchain, "HASH_LIMIT", 4):
            self.run_audit()
            p = os.path.join(self.root, "boot/vmlinuz-6.8.0-45-generic")
            st = os.stat(p)
            time.sleep(1.1)
            with open(p, "w") as fh:
                fh.write("kernl")                    # same size
            os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))   # mtime put back; ctime cannot be
            out = self.run_audit()
        self.assertTrue([f for f in out if "vmlinuz-6.8.0-45" in f["title"] and f["severity"] == "high"])

    def test_removed_image_reported(self):
        self.run_audit()
        os.remove(os.path.join(self.root, "boot/initrd.img-6.8.0-45-generic"))
        self.assertTrue([f for f in self.run_audit() if f["title"].startswith("boot file removed")])

    def test_events_kept_a_week_then_dropped(self):
        now = time.time()
        self.run_audit(now=now)
        self.write("etc/default/grub", "changed\n")
        self.assertTrue([f for f in self.run_audit(now=now) if "etc/default/grub" in f["title"]])
        out = self.run_audit(now=now + bootchain.KEEP_S + 60)
        self.assertFalse([f for f in out if "etc/default/grub" in f["title"]])

    def test_file_count_is_bounded(self):  # I4
        for i in range(bootchain.MAX_FILES + 5):
            self.write(f"etc/modprobe.d/m{i}.conf", "")
        files, truncated = bootchain.watched_files(self.root)
        self.assertEqual(len(files), bootchain.MAX_FILES)
        self.assertGreater(truncated, 0)
        vis = [f for f in self.run_audit() if f["category"] == "visibility"]
        self.assertTrue(vis and "limit" in vis[0]["detail"])

    def test_unreadable_file_is_not_observed(self):  # I1
        if os.getuid() == 0:
            self.skipTest("root reads mode 000 files")
        p = os.path.join(self.root, "etc/default/grub")
        os.chmod(p, 0)
        try:
            vis = [f for f in self.run_audit() if f["category"] == "visibility"]
        finally:
            os.chmod(p, 0o644)
        self.assertTrue(vis and "etc/default/grub" in vis[0]["detail"])

    def test_corrupt_state_relearns_and_says_so(self):
        self.store.meta[bootchain.STATE_META] = "{broken"
        vis = [f for f in self.run_audit() if f["category"] == "visibility"]
        self.assertTrue(vis and "learning again" in vis[0]["detail"])

    def test_never_writes_outside_its_state(self):  # I5
        before = {os.path.join(d, f): os.stat(os.path.join(d, f)).st_mtime_ns
                  for d, _, fs in os.walk(self.root) for f in fs}
        self.run_audit()
        self.run_audit()
        after = {os.path.join(d, f): os.stat(os.path.join(d, f)).st_mtime_ns
                 for d, _, fs in os.walk(self.root) for f in fs}
        self.assertEqual(before, after)


class Kernel(Root):
    def sysctl(self, rel, value):
        self.write(rel, value + "\n")

    def test_unprivileged_bpf_is_medium_and_small_items_aggregate(self):
        self.sysctl("proc/sys/kernel/unprivileged_bpf_disabled", "0")
        self.sysctl("proc/sys/kernel/kptr_restrict", "0")
        self.sysctl("proc/sys/kernel/dmesg_restrict", "0")
        self.write("proc/modules", "algif_aead 16384 0 - Live 0x0\next4 1 0 - Live 0x0\n")
        out = self.run_audit()
        by = {f["title"]: f for f in out}
        self.assertEqual(by["any user can load BPF programs"]["severity"], "medium")
        agg = [f for f in out if f["title"].startswith("kernel attack surface")][0]
        self.assertEqual(agg["severity"], "low")
        self.assertIn("kptr_restrict", agg["detail"])
        self.assertIn("algif_aead", agg["detail"])

    def test_hardened_kernel_is_quiet(self):
        for rel, v in (("proc/sys/kernel/unprivileged_bpf_disabled", "2"), ("proc/sys/kernel/kptr_restrict", "1"),
                       ("proc/sys/kernel/dmesg_restrict", "1"), ("proc/sys/kernel/yama/ptrace_scope", "1"),
                       ("proc/sys/kernel/unprivileged_userns_clone", "0"), ("sys/module/module/parameters/sig_enforce", "Y")):
            self.sysctl(rel, v)
        self.write("proc/modules", "ext4 1 0 - Live 0x0\n")
        self.assertEqual(self.run_audit(), [])

    def test_apparmor_userns_restriction_counts_as_restricted(self):
        self.sysctl("proc/sys/kernel/unprivileged_userns_clone", "1")
        self.sysctl("proc/sys/user/max_user_namespaces", "63000")
        self.sysctl("proc/sys/kernel/apparmor_restrict_unprivileged_userns", "1")
        out = self.run_audit()
        self.assertFalse(any("user namespaces" in f["detail"] for f in out))


if __name__ == "__main__":
    unittest.main()


class TaintAndUdev(Root):
    def taint(self, value, boot="b1"):
        self.write("proc/sys/kernel/tainted", f"{value}\n")
        self.write("proc/sys/kernel/random/boot_id", boot + "\n")

    def test_boot_baseline_then_new_unsigned_module_is_high_once(self):
        self.taint(4096 | 8192)                     # DKMS driver at boot: out-of-tree + unsigned
        self.assertFalse([f for f in self.run_audit() if "taint" in f["title"]])
        self.taint(4096 | 8192 | 2)                 # a module force-loaded later this boot
        f = [f for f in self.run_audit() if "taint" in f["title"]]
        self.assertEqual((len(f), f[0]["severity"]), (1, "high"))
        self.assertIn("force-loaded", f[0]["detail"])
        self.assertFalse([f for f in self.run_audit() if "taint" in f["title"]])   # said once

    def test_warning_only_is_medium_and_new_boot_rebaselines(self):
        self.taint(0)
        self.run_audit()
        self.taint(512)
        f = [f for f in self.run_audit() if "taint" in f["title"]]
        self.assertEqual(f[0]["severity"], "medium")
        self.taint(512, boot="b2")
        self.assertFalse([f for f in self.run_audit() if "taint" in f["title"]])

    def test_udev_rule_running_a_program_outside_system_dirs(self):
        self.write("etc/udev/rules.d/99-x.rules",
                   'ACTION=="add", SUBSYSTEM=="usb", RUN+="/bin/sh -c /var/tmp/.u/run"\n')
        self.write("etc/udev/rules.d/70-ok.rules", 'SUBSYSTEM=="net", RUN+="/usr/lib/udev/ifup"\n')
        titles = {f["title"] for f in self.run_audit()}
        self.assertIn("udev rule runs a program from outside the system: 99-x.rules", titles)
        self.assertNotIn("udev rule runs a program from outside the system: 70-ok.rules", titles)

    def test_udev_rule_change_is_tracked(self):
        self.write("etc/udev/rules.d/70-ok.rules", 'SUBSYSTEM=="net", NAME="eth0"\n')
        self.run_audit()
        self.write("etc/udev/rules.d/70-ok.rules", 'SUBSYSTEM=="net", NAME="eth1"\n')
        f = [f for f in self.run_audit() if "70-ok.rules" in f["title"]]
        self.assertEqual(f[0]["severity"], "medium")
