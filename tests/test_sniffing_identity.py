"""Packet-socket holders are judged by identity, not by name (spyware research
2026-10-29: BPFdoor runs under a fixed fake daemon name). A synthetic /proc
stands in; nothing reads this machine's processes."""

import os
import shutil
import sys
import tempfile
import unittest

from jarvis.collectors.network import sniffing


class Identity(unittest.TestCase):
    def setUp(self):
        self.proc = tempfile.mkdtemp(prefix="sniff-")

    def tearDown(self):
        shutil.rmtree(self.proc, ignore_errors=True)

    def pid(self, pid, exe=None, argv=()):
        d = os.path.join(self.proc, str(pid))
        os.makedirs(d)
        if exe:
            os.symlink(exe, os.path.join(d, "exe"))
        with open(os.path.join(d, "cmdline"), "wb") as fh:
            fh.write(b"\0".join(a.encode() for a in argv) + b"\0")
        return str(pid)

    def who(self, pid, name, owner=lambda p: True):
        return sniffing.packet_holder_identity(pid, name, proc=self.proc, owner=owner)

    def test_daemon_name_with_its_real_image_is_verified(self):
        exe = shutil.which("ls") or "/bin/ls"       # a root-owned, package-owned system binary
        if not exe.startswith(sniffing.SYSTEM_DIRS) or os.stat(exe).st_uid != 0:
            self.skipTest("no root-owned system binary to stand in")
        link = os.path.join(self.proc, "NetworkManager")
        os.symlink(exe, link)
        self.assertEqual(self.who(self.pid(10, exe), "NetworkManager"), "unexpected")   # ls is not NetworkManager

    def test_truncated_process_name_is_matched_by_image(self):
        d = tempfile.mkdtemp(prefix="sd-", dir="/tmp")
        try:
            exe = os.path.join(d, "systemd-networkd")
            open(exe, "w").close()
            pid = self.pid(18, exe)
            from unittest import mock
            with mock.patch.object(sniffing, "SYSTEM_DIRS", (d + "/",)), \
                    mock.patch.object(sniffing, "_root_only", lambda p: True):
                self.assertEqual(self.who(pid, "systemd-network"), "verified")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_daemon_name_from_a_writable_place_is_unexpected(self):
        fake = os.path.join(self.proc, "dhclient")
        open(fake, "w").close()
        self.assertEqual(self.who(self.pid(11, fake), "dhclient"), "unexpected")

    def test_daemon_name_not_owned_by_a_package_is_unexpected(self):
        exe = shutil.which("ls") or "/bin/ls"
        self.assertEqual(self.who(self.pid(12, exe), "avahi-daemon", owner=lambda p: False), "unexpected")

    def test_sysmon_for_linux_is_proven_by_its_packaged_twin(self):
        from unittest import mock
        pid = self.pid(20, "/opt/sysmon/sysmon")
        digests = {"/opt/sysmon/sysmon": "a" * 64, "/usr/bin/sysmon": "a" * 64}
        with mock.patch.object(sniffing, "_sha256", lambda p: digests.get(p)):
            self.assertEqual(self.who(pid, "sysmon"), "verified")
            self.assertEqual(self.who(pid, "sysmon", owner=lambda p: False), "unexpected")
            digests["/opt/sysmon/sysmon"] = "b" * 64                    # tampered copy
            self.assertEqual(self.who(pid, "sysmon"), "unexpected")
            digests["/opt/sysmon/sysmon"] = None                        # unreadable here
            self.assertEqual(self.who(pid, "sysmon"), "unverified")

    def test_deleted_image_is_unexpected(self):
        self.assertEqual(self.who(self.pid(13, "/usr/sbin/NetworkManager (deleted)"), "NetworkManager"),
                         "unexpected")

    def test_unreadable_image_is_unverified_never_exempt(self):
        self.assertEqual(self.who(self.pid(14), "systemd-networkd"), "unverified")
        out = sniffing._linux(tools=[], sockets=[("14", "systemd-networkd")], promisc=[],
                              identity=lambda p, n: "unverified")
        self.assertEqual([(f["severity"], "not verified" in f["title"]) for f in out], [("medium", True)])

    def test_own_packet_sensor_needs_the_sealed_launcher(self):
        exe = sys.executable
        if os.stat(os.path.realpath(exe)).st_uid != 0:
            self.skipTest("interpreter not root-owned here")
        launcher = "/opt/jarvis/app/jarvis-release.pyc"
        pid = self.pid(15, exe, (exe, "-I", launcher, "netsensor"))
        real = sniffing._root_only
        sniffing._root_only = lambda p: True if p == launcher else real(p)
        try:
            self.assertEqual(self.who(pid, "python3"), "verified")
            other = self.pid(16, exe, (exe, "-I", "/tmp/jarvis-release.pyc", "netsensor"))
            self.assertEqual(self.who(other, "python3"), "unexpected")
        finally:
            sniffing._root_only = real

    def test_bpfdoor_style_fake_name_is_reported(self):
        out = sniffing._linux(tools=[], sockets=[("17", "dhclient")], promisc=[],
                              identity=lambda p, n: "unexpected")
        self.assertEqual(out[0]["severity"], "high")
        self.assertIn("dhclient (pid 17)", out[0]["title"])


if __name__ == "__main__":
    unittest.main()


class NativeHolders(unittest.TestCase):
    """Packet-socket holders are found from /proc/net/packet and /proc/<pid>/fd,
    not from `ss -p` (which cannot name root holders without capabilities)."""

    def setUp(self):
        self.proc = tempfile.mkdtemp(prefix="pkt-")
        os.makedirs(os.path.join(self.proc, "net"))
        with open(os.path.join(self.proc, "net", "packet"), "w") as fh:
            fh.write("sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n"
                     "ffff8881 3      2    0300   0     1 0      0      55501\n")

    def tearDown(self):
        shutil.rmtree(self.proc, ignore_errors=True)

    def pid(self, pid, comm, sockets):
        d = os.path.join(self.proc, str(pid), "fd")
        os.makedirs(d)
        with open(os.path.join(self.proc, str(pid), "comm"), "w") as fh:
            fh.write(comm + "\n")
        for i, ino in enumerate(sockets):
            os.symlink(f"socket:[{ino}]", os.path.join(d, str(i)))

    def test_holder_found_by_inode(self):
        self.pid(31, "dhclient", [55501])
        self.pid(32, "nginx", [77777])
        self.assertEqual(sniffing._packet_sockets(proc=self.proc), [("31", "dhclient")])
        self.assertEqual(sniffing.packet_socket_scan(proc=self.proc), ([("31", "dhclient")], 0))

    def test_socket_with_no_readable_holder_is_unknown_not_absent(self):
        self.pid(33, "nginx", [77777])
        self.assertEqual(sniffing.packet_socket_scan(proc=self.proc), ([], 1))
        from unittest import mock
        with mock.patch.object(sniffing, "packet_socket_scan", return_value=([], 1)), \
                mock.patch.object(sniffing, "_capture_procs_linux", return_value=[]), \
                mock.patch.object(sniffing, "_promisc_ifaces", return_value=[]):
            out = sniffing._linux()
        self.assertEqual([(f["category"], f["severity"]) for f in out], [("visibility", "medium")])

    def test_unreadable_table_falls_back_to_ss(self):
        os.remove(os.path.join(self.proc, "net", "packet"))
        from unittest import mock
        with mock.patch.object(sniffing, "_packet_sockets_ss", return_value=[("9", "x")]) as ss:
            self.assertEqual(sniffing._packet_sockets(proc=self.proc), [("9", "x")])
            ss.assert_called_once()
