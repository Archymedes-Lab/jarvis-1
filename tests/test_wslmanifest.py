"""WSL process manifest: attribution, approval and drift (owner request 2026-10-31)."""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.host import wslmanifest as w

DOCKER = "/system.slice/docker-" + "a" * 64 + ".scope"


class FakeProc:
    """A /proc tree: pid -> (cgroup, exe or None, ppid)."""

    def __init__(self, procs):
        self.root = tempfile.mkdtemp()
        for pid, (cgroup, exe, ppid) in procs.items():
            d = os.path.join(self.root, str(pid))
            os.makedirs(d)
            with open(os.path.join(d, "cgroup"), "w") as fh:
                fh.write(f"0::{cgroup}\n")
            with open(os.path.join(d, "stat"), "w") as fh:
                fh.write(f"{pid} (x y) S {ppid} 0 0\n")
            if exe is not None:
                os.symlink(exe, os.path.join(d, "exe"))

    def close(self):
        shutil.rmtree(self.root, True)


BASE = {
    1: ("/init.scope", "/usr/lib/systemd/systemd", 0),
    2: ("/init.scope", "/init", 1),
    3: ("", None, 2),                                              # kernel thread
    10: ("/system.slice/sysmon.service", "/opt/sysmon/sysmon", 1),
    11: ("/system.slice/jarvis.service", "/usr/bin/python3.12", 1),
    12: ("/system.slice/snap-core24-2124.mount", "/usr/bin/snapfuse", 1),
    13: (DOCKER, "/usr/local/bin/nats-server", 1),
    14: ("/user.slice/user-1000.slice/session-3.scope", "/usr/bin/bash", 1),
    15: ("/init.scope", "/usr/bin/bash", 2),                       # a terminal opened from Windows
    16: ("/user.slice/user-1000.slice/user@1000.service/init.scope", "/usr/lib/systemd/systemd", 1),
}


class Base(unittest.TestCase):
    def proc(self, procs):
        fp = FakeProc(procs)
        self.addCleanup(fp.close)
        return fp.root

    def manifest_path(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        return os.path.join(d, "wsl-manifest.json")

    def titles(self, out):
        return {f["title"]: f for f in out}


class AttributionTests(Base):
    def test_every_owner_kind_comes_from_the_cgroup(self):
        with mock.patch.object(w, "_user", return_value="chris"):
            rows, unreadable = w.read_procs(self.proc(BASE))
        owners = {pid: owner for pid, owner, _e, _u in rows}
        self.assertEqual(unreadable, 0)
        self.assertNotIn(3, owners)                                     # kernel thread skipped
        self.assertEqual(owners[1], "systemd")
        self.assertEqual(owners[2], "wsl-plumbing")
        self.assertEqual(owners[10], "unit:sysmon.service")
        self.assertEqual(owners[12], "unit:snap-core24-N.mount")        # revision folded
        self.assertEqual(owners[13], "containers")
        self.assertEqual(owners[14], "login-session")
        self.assertEqual(owners[15], "wsl-session:chris")
        self.assertEqual(owners[16], "user-manager:1000")

    def test_cgroupfs_container_layout_and_root_from_windows(self):
        self.assertEqual(w.owner_of("/docker/" + "b" * 64, "/x", 5, "root"), "containers")
        self.assertEqual(w.owner_of("/init.scope", "/usr/bin/id", 77, "root"), "wsl-session:root")

    def test_unreadable_process_is_counted_not_dropped(self):
        procs = dict(BASE)
        procs[20] = ("/system.slice/cron.service", None, 1)             # exe link denied
        with mock.patch.object(w, "_user", return_value="chris"):
            rows, unreadable = w.read_procs(self.proc(procs))
        self.assertEqual(unreadable, 1)
        self.assertNotIn(20, {r[0] for r in rows})

    def test_bounded_read(self):
        many = {i: ("/system.slice/x.service", "/bin/x", 1) for i in range(10, 10 + 60)}
        with mock.patch.object(w, "MAX_PROCS", 25), mock.patch.object(w, "_user", return_value="u"):
            rows, _ = w.read_procs(self.proc(many))
        self.assertEqual(len(rows), 25)


class ManifestTests(Base):
    def observed(self, procs=BASE):
        with mock.patch.object(w, "_user", return_value="chris"):
            rows, _ = w.read_procs(self.proc(procs))
        return rows, w.observe(rows)

    def test_without_approval_nothing_is_drift(self):
        path = self.manifest_path()
        with mock.patch.object(w, "_user", return_value="chris"):
            out = w.audit(proc=self.proc(BASE), path=path)
        self.assertEqual([f["severity"] for f in out], ["low"])
        self.assertIn("no approved WSL process manifest", out[0]["title"])
        self.assertFalse(os.path.exists(path))                          # a run never writes it

    def test_approval_is_owner_only_and_interactive_sessions_allow_any_binary(self):
        _rows, obs = self.observed()
        path = self.manifest_path()
        data = w.approve(obs, path)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(data["owners"]["wsl-session:chris"]["binaries"], w.ANY)
        self.assertEqual(data["owners"]["containers"]["binaries"], ["/usr/local/bin/nats-server"])
        self.assertTrue(data["owners"]["unit:sysmon.service"]["required"])
        self.assertFalse(data["owners"]["containers"]["required"])

    def test_clean_run_after_approval_is_ok_only(self):
        path = self.manifest_path()
        _rows, obs = self.observed()
        w.approve(obs, path)
        with mock.patch.object(w, "_user", return_value="chris"):
            out = w.audit(proc=self.proc(BASE), path=path)
        self.assertEqual([f["severity"] for f in out], ["ok"])

    def test_drift_new_owner_new_binary_root_session_risky_and_missing(self):
        path = self.manifest_path()
        _rows, obs = self.observed()
        w.approve(obs, path)
        procs = dict(BASE)
        del procs[10]                                                    # sysmon stopped
        procs[13] = (DOCKER, "/usr/local/bin/xmrig", 1)                  # new binary in containers
        procs[30] = ("/system.slice/evil.service", "/usr/bin/socat", 1)  # new unit
        procs[31] = ("/init.scope", "/usr/bin/bash", 2)                  # root shell from Windows
        procs[32] = ("/system.slice/jarvis.service", "/tmp/.x/kworker (deleted)", 11)
        with mock.patch.object(w, "_user", side_effect=lambda uid: "chris"):
            rows, _ = w.read_procs(self.proc(procs))
        rows = [(p, o if p != 31 else "wsl-session:root", e, u if p != 31 else "root")
                for p, o, e, u in rows]
        got = self.titles(w.drift(w.observe(rows), w.load(path), rows))
        new = next(f for t, f in got.items() if "not in the approved manifest" in t and "owner" in t)
        self.assertEqual(new["severity"], "high")                       # root from Windows among them
        self.assertIn("unit:evil.service", new["detail"])
        self.assertIn("wsl-session:root", new["detail"])
        cont = next(f for t, f in got.items() if t.startswith("containers is running"))
        self.assertIn("/usr/local/bin/xmrig", cont["detail"])
        risky = next(f for t, f in got.items() if "deleted or world-writable" in t)
        self.assertEqual(risky["severity"], "high")
        miss = got["1 approved WSL unit(s) are not running"]
        self.assertEqual(miss["severity"], "high")                       # the sensor
        self.assertIn("unit:sysmon.service", miss["detail"])

    def test_audit_records_the_daemon_view_for_approval(self):
        from jarvis.core.store import Store
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        store = Store(os.path.join(d, "j.db"))
        with mock.patch.object(w, "_user", return_value="chris"):
            w.audit(store, proc=self.proc(BASE), path=self.manifest_path())
        observed, unreadable, age = w.daemon_view(store)
        self.assertIn("unit:sysmon.service", observed)
        self.assertEqual(unreadable, 0)
        self.assertLess(age, 5)

    def test_a_cli_run_never_overwrites_the_daemon_view(self):
        from jarvis.core.store import Store
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        store = Store(os.path.join(d, "j.db"))
        with mock.patch.object(w, "_user", return_value="chris"):
            w.audit(store, proc=self.proc(BASE), path=self.manifest_path())          # the daemon
            partial = {1: BASE[1], 11: BASE[11]}
            w.audit(store, proc=self.proc(partial), path=self.manifest_path(), record=False)  # a shell
        self.assertIn("unit:sysmon.service", w.daemon_view(store)[0])

    def test_cli_approve_refuses_a_partial_view(self):
        from types import SimpleNamespace

        from jarvis.cli.commands import audit as cli
        with mock.patch.object(w, "read_procs", return_value=([(11, "unit:jarvis.service", "/init", "chris")], 70)), \
                mock.patch.object(w, "daemon_view", return_value=None), \
                mock.patch.object(w, "approve") as approve:
            code = cli.cmd_wslmanifest(SimpleNamespace(approve=True, partial=False, json=False,
                                                       verbose=False, severity=None), store=object())
        self.assertEqual(code, 1)
        approve.assert_not_called()

    def test_snap_revisions_do_not_read_as_new_binaries(self):
        rows = [(1, "unit:snapd.service", "/snap/snapd/28254/usr/lib/snapd/snapd", "root")]
        later = [(1, "unit:snapd.service", "/snap/snapd/28399/usr/lib/snapd/snapd", "root")]
        self.assertEqual(w.observe(rows), w.observe(later))
        self.assertEqual(w.observe(rows)["unit:snapd.service"]["binaries"], ["/snap/snapd/N/usr/lib/snapd/snapd"])

    def test_release_folders_are_folded(self):
        rows = [(1, "unit:jarvis.service", "/opt/jarvis/releases/20261031T220908Z-55cdd0afe00b/rust-runtime/x", "chris")]
        later = [(1, "unit:jarvis.service", "/opt/jarvis/releases/20261101T090000Z-0123456789ab/rust-runtime/x", "chris")]
        self.assertEqual(w.observe(rows), w.observe(later))
        old_manifest = {"approved_at": 1, "owners": {"unit:jarvis.service": {
            "binaries": ["/opt/jarvis/releases/20261031T220908Z-55cdd0afe00b/rust-runtime/x"], "required": True}}}
        self.assertEqual(w.drift(w.observe(later), old_manifest, later), [])

    def test_self_reinstalled_binary_is_low_and_a_vanished_one_high(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        present = os.path.join(d, "sysmon")
        open(present, "w").close()
        gone = os.path.join(d, "vanished")
        manifest = {"approved_at": 1, "owners": {
            "unit:sysmon.service": {"binaries": [present], "required": True},
            "unit:x.service": {"binaries": [gone], "required": True}}}
        rows = [(463, "unit:sysmon.service", present + " (deleted)", "root"),
                (9, "unit:x.service", gone + " (deleted)", "root")]
        got = {f["title"]: f for f in w.drift(w.observe(rows), manifest, rows)}
        low = next(f for t, f in got.items() if "replaced on disk" in t)
        high = next(f for t, f in got.items() if "deleted or world-writable" in t)
        self.assertEqual((low["severity"], high["severity"]), ("low", "high"))
        self.assertIn("pid 463", low["detail"])
        self.assertIn("pid 9", high["detail"])

    def test_names_are_bounded(self):
        obs = {f"unit:s{i}.service": {"binaries": ["/bin/x"], "users": ["u"], "pids": 1} for i in range(40)}
        out = w.drift(obs, {"approved_at": 1, "owners": {}})
        self.assertIn("(+28 more)", out[0]["detail"])

    def test_unlistable_proc_is_not_clean(self):
        out = w.audit(proc="/nonexistent-proc", path=self.manifest_path())
        self.assertEqual(out[0]["severity"], "medium")

    def test_corrupt_manifest_reads_as_none(self):
        path = self.manifest_path()
        with open(path, "w") as fh:
            fh.write("{not json")
        self.assertIsNone(w.load(path))
        with open(path, "w") as fh:
            json.dump({"owners": []}, fh)
        self.assertIsNone(w.load(path))


if __name__ == "__main__":
    unittest.main()
