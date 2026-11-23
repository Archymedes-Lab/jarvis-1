import errno
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from jarvis.collectors.process.hidden import kernel, sockets
from jarvis.collectors.process.hidden.run import (
    _local_only_listener,
    _orphan_finding,
    _orphan_findings,
)
from jarvis.platform import linux


class ReplacedExecutableTests(unittest.TestCase):
    def setUp(self):
        # Not under /tmp: executing a binary from a world-writable directory
        # is exactly what the Sysmon rules flag, and this suite runs on the
        # protected host at every deploy.
        scratch = os.path.join(os.path.expanduser("~"), ".cache", "jarvis-tests")
        os.makedirs(scratch, mode=0o700, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.tmp.cleanup)
        self.exe = os.path.join(self.tmp.name, "worker")
        shutil.copy2(shutil.which("sleep"), self.exe)
        self.proc = subprocess.Popen([self.exe, "30"])
        self.addCleanup(self.proc.wait)
        self.addCleanup(self.proc.kill)
        time.sleep(0.2)

    def swap(self, source):
        fresh = self.exe + ".new"
        shutil.copy2(source, fresh)
        os.replace(fresh, self.exe)     # new inode; the running one is now (deleted)
        return os.readlink(f"/proc/{self.proc.pid}/exe")

    def test_identical_reinstall_is_recognised(self):
        mapped = self.swap(shutil.which("sleep"))
        self.assertTrue(mapped.endswith("(deleted)"))
        self.assertTrue(kernel._replaced_identically(self.proc.pid, mapped))

    def test_different_bytes_stay_a_deleted_mapping(self):
        mapped = self.swap(shutil.which("true"))
        self.assertFalse(kernel._replaced_identically(self.proc.pid, mapped))

    def test_removed_file_stays_a_deleted_mapping(self):
        mapped = self.swap(shutil.which("sleep"))
        os.unlink(self.exe)
        self.assertFalse(kernel._replaced_identically(self.proc.pid, mapped))

    def test_deleted_mapping_comparisons_are_cached_and_bounded(self):
        entries = ["101", "102", "103"]
        maps = "00400000-00401000 r-xp 0 00:00 0 /opt/tool (deleted)\n" * 2
        def read(path, binary=False):
            return maps if path.endswith("/maps") else (b"" if binary else "")
        with mock.patch.object(kernel.os, "listdir", return_value=entries), \
             mock.patch.object(kernel, "_read", side_effect=read), \
             mock.patch.object(kernel, "_describe", return_value={"name": "tool", "cmdline": "", "exe": ""}), \
             mock.patch.object(kernel, "_replaced_identically", return_value=True) as check:
            hits = kernel.injected_processes()
        self.assertEqual(check.call_count, kernel.MAX_REPLACEMENT_CHECKS)
        self.assertEqual(len(hits), 3)
        self.assertEqual(hits[-1]["reasons"][0][0], "executable mapping was deleted from disk")


class OrphanListenerTests(unittest.TestCase):
    def test_fresh_socket_view_bypasses_shared_cache(self):
        with mock.patch.object(linux, "_read_socket_table", return_value={11: {"state": "LISTEN"}}) as read, \
             mock.patch("jarvis.core.state.get_socket_table", side_effect=AssertionError("cache used")):
            self.assertEqual(linux.socket_table(fresh=True), {11: {"state": "LISTEN"}})
        read.assert_called_once_with()

    def test_only_peerless_loopback_or_wsl_dns_listeners_qualify(self):
        def conn(local, remote="0.0.0.0", port=0):
            return {"local_ip": local, "remote_ip": remote, "remote_port": port}
        self.assertTrue(_local_only_listener(conn("10.255.255.254")))
        self.assertTrue(_local_only_listener(conn("0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:0")))
        self.assertFalse(_local_only_listener(conn("127.0.0.1", "1.2.3.4", 443)))
        self.assertFalse(_local_only_listener(conn("0.0.0.0")))
        self.assertFalse(_local_only_listener(conn("172.20.1.2")))
        self.assertFalse(_local_only_listener(conn("junk")))

    def test_orphan_scan_reads_fresh_table_and_excludes_claimed_fds(self):
        rows = {11: {"state": "ESTABLISHED"}, 12: {"state": "LISTEN"},
                13: {"state": "TIME_WAIT"}}
        with mock.patch.object(sockets, "socket_table", return_value=rows) as read, \
             mock.patch.object(sockets.os, "listdir", side_effect=lambda path: ["42"] if path == sockets.PROC else ["3"]), \
             mock.patch.object(sockets.os, "readlink", return_value="socket:[12]"):
            valid, unclaimed, denied = sockets._unclaimed_socket_rows()
        read.assert_called_once_with(fresh=True, strict=True)
        self.assertTrue(valid)
        self.assertEqual(unclaimed, {11: rows[11]})
        self.assertEqual(denied, 0)

    def test_transient_orphan_does_not_become_a_high_finding(self):
        # The first sighting is kept as a transient record (low), never
        # dropped and never scored as a confirmed discrepancy.
        row = {"proto": "tcp", "local_ip": "127.0.0.1", "local_port": 8787,
               "remote_ip": "127.0.0.1", "remote_port": 50000, "state": "ESTABLISHED"}
        with mock.patch.object(sockets, "_unclaimed_socket_rows",
                                   side_effect=[(True, {11: row}, 0), (True, {}, 0)]), \
             mock.patch.object(sockets.time, "sleep"):
            observed, denied = sockets.orphan_sockets()
        self.assertEqual(observed, [{**row, "_verification": "transient",
                                     "_fd_visibility": "complete"}])
        self.assertEqual(_orphan_finding(observed[0], True)["severity"], "low")

    def test_persistent_orphan_remains_reported(self):
        row = {"state": "ESTABLISHED", "local_port": 443}
        with mock.patch.object(sockets, "_unclaimed_socket_rows",
                                   side_effect=[(True, {11: row}, 0), (True, {11: row}, 0)]), \
             mock.patch.object(sockets.time, "sleep"):
            self.assertEqual(sockets.orphan_sockets(),
                             ([{**row, "_verification": "confirmed",
                                "_fd_visibility": "complete"}], 0))

    def test_reused_inode_with_different_connection_is_not_confirmed(self):
        first = {"state": "ESTABLISHED", "local_port": 443}
        reused = {"state": "ESTABLISHED", "local_port": 8443}
        with mock.patch.object(sockets, "_unclaimed_socket_rows",
                               side_effect=[(True, {11: first}, 0), (True, {11: reused}, 0)]), \
             mock.patch.object(sockets.time, "sleep"):
            observed, _ = sockets.orphan_sockets()
        self.assertEqual([o["_verification"] for o in observed], ["transient"])

    def test_failed_recheck_does_not_clear_initial_discrepancy(self):
        row = {"state": "ESTABLISHED", "local_port": 443}
        with mock.patch.object(sockets, "_unclaimed_socket_rows",
                                   side_effect=[(True, {11: row}, 0), (False, {}, 0)]), \
             mock.patch.object(sockets.time, "sleep"):
            self.assertEqual(sockets.orphan_sockets(),
                             ([{**row, "_verification": "inconclusive",
                                "_fd_visibility": "complete"}], 0))

    def test_denied_fd_read_keeps_owner_uncertain(self):
        row = {"state": "ESTABLISHED", "local_port": 443}
        with mock.patch.object(sockets, "_unclaimed_socket_rows",
                               side_effect=[(True, {11: row}, 1), (True, {11: row}, 0)]), \
             mock.patch.object(sockets.time, "sleep"):
            observations, denied = sockets.orphan_sockets()
        self.assertEqual(denied, 1)
        self.assertEqual(observations[0]["_fd_visibility"], "limited")

    def test_empty_initial_socket_table_is_not_reported_as_clean(self):
        with mock.patch.object(sockets, "_unclaimed_socket_rows", return_value=(False, {}, 0)):
            with self.assertRaisesRegex(RuntimeError, "socket tables unreadable"):
                sockets.orphan_sockets()

    def test_fd_permission_denial_is_counted(self):
        row = {11: {"state": "ESTABLISHED"}}
        with mock.patch.object(sockets, "socket_table", return_value=row), \
             mock.patch.object(sockets.os, "listdir",
                        side_effect=lambda path: ["42"] if path == sockets.PROC else
                        (_ for _ in ()).throw(PermissionError(errno.EACCES, "denied"))):
            valid, unclaimed, denied = sockets._unclaimed_socket_rows()
        self.assertTrue(valid)
        self.assertEqual(unclaimed, row)
        self.assertEqual(denied, 1)

    def test_peer_connection_classes_keep_high_and_state_uncertainty(self):
        base = {"proto": "tcp", "local_ip": "127.0.0.1", "local_port": 50000,
                "remote_ip": "127.0.0.1", "remote_port": 8787,
                "state": "ESTABLISHED", "_verification": "confirmed",
                "_fd_visibility": "complete"}
        local = _orphan_finding(base, True)
        self.assertEqual((local["severity"], local["title"]),
                         ("high", "local connection with no visible owner"))
        external = _orphan_finding({**base, "remote_ip": "198.51.100.10",
                                    "_fd_visibility": "limited"}, True)
        self.assertEqual(external["severity"], "high")
        self.assertIn("visibility was limited", external["detail"])
        self.assertNotIn("malicious", external["detail"])

    def test_local_listener_is_medium_and_broad_listener_is_high(self):
        base = {"proto": "tcp", "local_ip": "127.0.0.1", "local_port": 53,
                "remote_ip": "0.0.0.0", "remote_port": 0, "state": "LISTEN",
                "_verification": "confirmed", "_fd_visibility": "complete"}
        self.assertEqual(_orphan_finding(base, True)["severity"], "medium")
        broad = _orphan_finding({**base, "local_ip": "0.0.0.0"}, True)
        self.assertEqual((broad["severity"], broad["title"]),
                         ("high", "network endpoint with no visible owner"))

    def test_fd_scan_denial_is_visible_even_without_socket_candidate(self):
        findings = _orphan_findings([], 2, True)
        self.assertEqual([(f["severity"], f["title"]) for f in findings],
                         [("low", "socket owner visibility limited")])


if __name__ == "__main__":
    unittest.main()


class SchedulerViewTests(unittest.TestCase):
    def test_nested_pid_namespace_disables_the_view_and_is_a_stated_limit(self):
        from unittest import mock

        from jarvis.collectors.process.hidden import views
        from jarvis.service import coverage
        with mock.patch.object(views, "pid_namespace_nested", return_value=True), \
             mock.patch.object(views, "_read", return_value=" S  init  1  5.0\n"):
            self.assertIsNone(views.view_sched_debug())
        with mock.patch("jarvis.collectors.process.hidden.pid_namespace_nested", return_value=True):
            rows = [(f["category"], f["severity"]) for f in coverage.visibility()
                    if "scheduler" in f["title"]]
        self.assertEqual(rows, [("limits", "low")])

    def test_host_namespace_reads_debugfs_when_proc_file_is_gone(self):
        from unittest import mock

        from jarvis.collectors.process.hidden import views
        sample = (" S            task   PID       vruntime\n"
                  " S       systemd     1  24850587.675748   E\n"
                  " R        worker   812      138.776533   E\n")
        reads = {f"{views.PROC}/sched_debug": "", views.SCHED_DEBUGFS: sample}
        with mock.patch.object(views, "pid_namespace_nested", return_value=False), \
             mock.patch.object(views, "_read", side_effect=lambda p, *a, **k: reads.get(p, "")):
            self.assertEqual(views.view_sched_debug(), {1, 812})


class SocketReadEvidence(unittest.TestCase):
    HEADER = 'sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'

    def test_valid_empty_tables_are_distinct_from_unreadable_tables(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            net = root / 'net'
            net.mkdir()
            for name in ('tcp', 'tcp6', 'udp', 'udp6'):
                (net / name).write_text(self.HEADER)
            with mock.patch.object(linux, 'PROC', str(root)), mock.patch.object(sockets, 'PROC', str(root)):
                self.assertEqual(linux.socket_table(fresh=True, strict=True), {})
                self.assertEqual(sockets.orphan_sockets(), ([], 0))
                (net / 'tcp').unlink()
                with self.assertRaisesRegex(RuntimeError, 'unreadable'):
                    sockets.orphan_sockets()

    def test_malformed_and_over_budget_reads_remain_unknown(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'net').mkdir()
            for name in ('tcp', 'udp'):
                (root / 'net' / name).write_text(self.HEADER)
            with mock.patch.object(linux, 'PROC', str(root)):
                # IPv6 can be disabled; complete empty IPv4 observations stay valid.
                self.assertEqual(linux.socket_table(strict=True), {})
                (root / 'net/tcp').write_text(self.HEADER + 'incomplete row\n')
                with self.assertRaises(ValueError):
                    linux.socket_table(strict=True)
                (root / 'net/tcp').write_bytes(self.HEADER.encode() + b'\xff')
                with self.assertRaises(UnicodeError):
                    linux.socket_table(strict=True)
                (root / 'net/tcp').write_text(self.HEADER)
                with mock.patch.object(linux, 'MAX_SOCKET_TABLE_BYTES', 8):
                    with self.assertRaises(ValueError):
                        linux.socket_table(strict=True)

    def test_permission_error_does_not_become_valid_empty_evidence(self):
        with mock.patch.object(sockets, 'socket_table', side_effect=PermissionError('denied')):
            self.assertEqual(sockets._unclaimed_socket_rows(), (False, {}, 0))
