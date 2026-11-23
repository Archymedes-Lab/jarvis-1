"""WSL trust-boundary guard: posture, checkpoint drift, registration changes."""
import json
import os
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.host import wslguard
from jarvis.core import collection
from jarvis.core.execution import wsl_drift
from jarvis.core.store import Store
from jarvis.service.jobs import RUNNERS
from jarvis.service.schedule import ALL_JOBS, LINUX_ONLY, WINDOWS_ONLY

GUID = "{3aa60676-2291-4d89-ba9b-a424d3b0a9a2}"


def snap(facts=None, sources=None, boot="boot-1"):
    facts = dict(facts or {})
    srcs = {"wsl_conf": {"status": "current", "facts": {}},
            "windows_wslconfig": {"status": "current", "facts": {}},
            "interop": {"status": "current", "facts": {"interop.binfmt": "enabled"}},
            "mounts": {"status": "current", "facts": {}},
            "sockets": {"status": "current", "facts": {}},
            "path": {"status": "current", "facts": {}}}
    for name, value in facts.items():
        bucket = ("windows_wslconfig" if name.startswith("wslconfig.")
                  else "wsl_conf" if name.startswith("wsl_conf.")
                  else "sockets" if name.startswith("docker.") else "mounts")
        srcs[bucket]["facts"][name] = value
    for name, status in (sources or {}).items():
        srcs[name] = {"status": status, "facts": {}, "reason": "PermissionError"}
    return {"boot_id": boot, "sources": srcs}


def distro(uid=1000, base=r"C:\Users\chris\AppData\Local\wsl\x", flags=15, name="Ubuntu"):
    return {"guid": GUID, "name": name, "defaultUid": uid, "basePath": base,
            "flags": flags, "version": 2}


def registration(distros=None, plugins=(), policy=None, default=GUID, errors=()):
    return {"distros": [distro()] if distros is None else distros,
            "defaultDistribution": default, "plugins": list(plugins),
            "policy": dict(policy or {}), "wslVersion": "2.7.8.0", "errors": list(errors)}


def titles(findings):
    return [f["title"] for f in findings]


class LinuxPostureTests(unittest.TestCase):
    def run_linux(self, facts=None, sources=None, entries=(), read_error=None):
        return wslguard.linux_findings(snap(facts, sources), list(entries), read_error)

    def test_a_clean_snapshot_without_a_checkpoint_only_asks_for_one(self):
        out, unreadable = self.run_linux()
        self.assertEqual([(f["severity"], f["category"]) for f in out], [("low", "visibility")])
        self.assertIn("--accept", out[0]["detail"])
        self.assertEqual(unreadable, [])

    def test_root_boot_command_and_custom_kernel_need_no_checkpoint(self):
        out, _ = self.run_linux({"wsl_conf.boot.command": "/root/x.sh",
                                 "wslconfig.wsl2.kernel": r"C:\k\bzImage",
                                 "wslconfig.wsl2.kernelmodules": r"C:\k\mods.vhdx",
                                 "wslconfig.wsl2.kernelcommandline": "quiet"})
        by_title = {f["title"]: f for f in out}
        self.assertEqual(by_title["a command runs as root at every WSL boot"]["severity"], "high")
        self.assertEqual(by_title["WSL boots a kernel that is not the Microsoft one"]["severity"], "high")
        self.assertEqual(by_title["WSL loads custom kernel modules"]["severity"], "high")
        self.assertEqual(by_title["WSL kernel command line is customised"]["severity"], "medium")
        self.assertIn("/root/x.sh", by_title["a command runs as root at every WSL boot"]["detail"])
        self.assertEqual(by_title["a command runs as root at every WSL boot"]["category"], "persistence")

    def test_long_values_are_bounded_in_the_detail(self):
        out, _ = self.run_linux({"wsl_conf.boot.command": "x" * 500})
        self.assertLess(len(out[0]["detail"]), 400)

    def test_firewall_off_safe_mode_and_docker_socket_are_reported(self):
        out, _ = self.run_linux({"wslconfig.wsl2.firewall": "false",
                                 "wslconfig.wsl2.safemode": "true",
                                 "docker.socket": "/var/run/docker.sock"})
        sev = {f["title"]: f["severity"] for f in out}
        self.assertEqual(sev["the Hyper-V firewall for WSL is turned off"], "medium")
        self.assertEqual(sev["WSL safe mode is on"], "medium")
        self.assertEqual(sev["the Docker socket makes this user root inside WSL"], "low")
        out, _ = self.run_linux({"wslconfig.wsl2.firewall": "true"})
        self.assertNotIn("the Hyper-V firewall for WSL is turned off", titles(out))

    def test_unreadable_sources_are_visibility_not_clean(self):
        out, unreadable = self.run_linux(sources={"windows_wslconfig": "unavailable"})
        self.assertEqual(unreadable, ["windows_wslconfig"])
        self.assertNotIn("WSL boots a kernel that is not the Microsoft one", titles(out))


class CheckpointDriftTests(unittest.TestCase):
    def accepted(self, facts=None, boot="boot-1"):
        return [wsl_drift.make_entry(snap(facts, boot=boot))]

    def test_matching_checkpoint_is_silent(self):
        out, _ = wslguard.linux_findings(snap(), self.accepted(), None)
        self.assertEqual(out, [])

    def test_critical_drift_is_high_and_other_drift_medium(self):
        entries = self.accepted({"wslconfig.wsl2.memory": "8GB"})
        out, _ = wslguard.linux_findings(
            snap({"wslconfig.wsl2.memory": "4GB", "wslconfig.wsl2.kernel": r"C:\k\bzImage"}),
            entries, None)
        drift = {f["title"]: f for f in out if "since the accepted checkpoint" in f["title"]}
        self.assertEqual(drift["WSL boundary changed since the accepted checkpoint: "
                               "wslconfig.wsl2.kernel"]["severity"], "high")
        self.assertEqual(drift["WSL boundary changed since the accepted checkpoint: "
                               "wslconfig.wsl2.memory"]["severity"], "medium")
        self.assertIn("'8GB' -> '4GB'", drift["WSL boundary changed since the accepted checkpoint: "
                                             "wslconfig.wsl2.memory"]["detail"])

    def test_offline_change_is_named_as_such(self):
        entries = self.accepted({"wslconfig.wsl2.memory": "8GB"})
        out, _ = wslguard.linux_findings(snap({"wslconfig.wsl2.memory": "4GB"}, boot="boot-2"),
                                         entries, None)
        self.assertTrue(any("while the distro was down" in f["detail"] for f in out))

    def test_lost_evidence_is_low_visibility_never_removed(self):
        entries = self.accepted({"wslconfig.wsl2.memory": "8GB"})
        out, _ = wslguard.linux_findings(snap(sources={"windows_wslconfig": "unavailable"}),
                                         entries, None)
        # One for the fact that vanished, one for the source that went unreadable.
        lost = [f for f in out if f["title"] == "a WSL boundary source became unreadable"]
        self.assertEqual([f["severity"] for f in lost], ["low", "low"])
        self.assertEqual({f["category"] for f in lost}, {"visibility"})
        self.assertEqual(sorted(f["detail"].split(":")[0] for f in lost),
                         ["source", "wslconfig.wsl2.memory"])
        self.assertFalse(any("removed" in f["detail"] for f in out))

    def test_broken_chain_or_unreadable_file_is_high(self):
        entries = self.accepted()
        entries[0]["hash"] = "0" * 64
        out, _ = wslguard.linux_findings(snap(), entries, None)
        self.assertEqual([f["severity"] for f in out], ["high"])
        out, _ = wslguard.linux_findings(snap(), [], "PermissionError")
        self.assertEqual([f["severity"] for f in out], ["high"])
        self.assertIn("PermissionError", out[0]["detail"])

    def test_checkpoint_file_reading(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.jsonl")
            self.assertEqual(wslguard.load_checkpoints(path), ([], None))
            with open(path, "w") as fh:
                fh.write(json.dumps({"seq": 1}) + "\n\n")
            self.assertEqual(wslguard.load_checkpoints(path), ([{"seq": 1}], None))
            with open(path, "w") as fh:
                fh.write("{not json\n")
            self.assertEqual(wslguard.load_checkpoints(path), ([], "JSONDecodeError"))


class WindowsRegistrationTests(unittest.TestCase):
    def test_first_sample_reports_posture_only(self):
        out, current = wslguard.windows_findings(registration(), {})
        self.assertEqual(out, [])
        self.assertEqual(current["distros"][GUID]["defaultUid"], 1000)
        self.assertEqual(current["default"], GUID)

    def test_root_by_default_and_plugins_are_high(self):
        out, _ = wslguard.windows_findings(
            registration([distro(uid=0)], plugins=["Updater"]), {})
        sev = {f["title"]: f for f in out}
        self.assertEqual(sev["WSL distribution Ubuntu opens as root by default"]["severity"], "high")
        self.assertEqual(sev["WSL service plugin registered"]["severity"], "high")
        self.assertIn("Updater", sev["WSL service plugin registered"]["detail"])
        self.assertTrue(all(f["host"] == "win" for f in out))

    def test_missing_default_uid_is_not_root(self):
        out, _ = wslguard.windows_findings(registration([distro(uid=-1)]), {})
        self.assertEqual(out, [])
        out, _ = wslguard.windows_findings(registration([distro(uid="junk")]), {})
        self.assertEqual(out, [])

    def test_changes_since_the_previous_sample(self):
        _, previous = wslguard.windows_findings(
            registration(policy={"AllowCustomKernelUserSetting": "0"}), {})
        other = dict(distro(name="evil", base=r"C:\Users\Public\evil"), guid="{evil}")
        now = registration([distro(uid=0, base=r"C:\Users\Public\x", flags=1), other],
                           default="{evil}", policy={"AllowCustomKernelUserSetting": "1"})
        out, _ = wslguard.windows_findings(now, previous)
        sev = {f["title"]: f["severity"] for f in out}
        self.assertEqual(sev["new WSL distribution registered: evil"], "medium")
        self.assertEqual(sev["WSL default user changed for Ubuntu"], "high")
        self.assertEqual(sev["WSL disk location changed for Ubuntu"], "high")
        self.assertEqual(sev["WSL flags changed for Ubuntu"], "medium")
        self.assertEqual(sev["default WSL distribution changed"], "medium")
        self.assertEqual(sev["WSL policy value changed: AllowCustomKernelUserSetting"], "medium")
        flags = [f for f in out if f["title"] == "WSL flags changed for Ubuntu"][0]
        self.assertIn("0xf (interop, drive mounting, Windows PATH) -> 0x1 (interop)", flags["detail"])

    def test_a_change_is_reported_once_not_every_sample(self):
        # Jev review (2026-10-21) ranked a five-minute flood as the top risk: the
        # sample replaces the previous one, so the next run compares against the
        # changed state and is quiet.
        _, previous = wslguard.windows_findings(registration(), {})
        changed = registration([distro(base=r"C:\Users\Public\x")])
        out, current = wslguard.windows_findings(changed, previous)
        self.assertEqual(titles(out), ["WSL disk location changed for Ubuntu"])
        out, _ = wslguard.windows_findings(changed, current)
        self.assertEqual(out, [])

    def test_unregistered_distribution_is_reported(self):
        _, previous = wslguard.windows_findings(registration(), {})
        out, _ = wslguard.windows_findings(registration([]), previous)
        self.assertEqual(titles(out), ["WSL distribution unregistered: Ubuntu"])

    def test_malformed_rows_and_bounds(self):
        rows = [distro()] + ["junk", {"name": "no guid"}] + [
            dict(distro(), guid=f"{{{i}}}") for i in range(60)]
        out, current = wslguard.windows_findings(registration(rows), {})
        self.assertEqual(out, [])
        self.assertLessEqual(len(current["distros"]), wslguard.MAX_DISTROS)
        self.assertFalse(wslguard._valid({"distros": "x", "errors": []}))
        self.assertFalse(wslguard._valid(None))


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "s.db"))
        self.addCleanup(self.store.close)
        self.checkpoint = os.path.join(self.tmp.name, "c.jsonl")

    def run_audit(self, data, hosts=("wsl", "win"), facts=None):
        with mock.patch.object(wslguard, "ps_json", return_value=data), \
             mock.patch.object(wslguard.wsl_boundary, "snapshot", return_value=snap(facts)), \
             mock.patch.object(wslguard, "CHECKPOINT", self.checkpoint), \
             mock.patch.object(wslguard.machine, "has_linux", return_value=True), \
             collection.observe() as obs:
            return wslguard.audit(self.store, hosts=hosts), obs

    def test_both_sides_run_and_state_is_kept(self):
        out, obs = self.run_audit(registration())
        self.assertEqual([f["severity"] for f in out], ["low"])
        self.assertIn("wsl", obs.successes)
        kept = json.loads(self.store.get_meta(wslguard.STATE_KEY))
        self.assertEqual(kept["distros"][GUID]["basePath"], r"C:\Users\chris\AppData\Local\wsl\x")
        out, _ = self.run_audit(registration([distro(base=r"C:\Users\Public\x")]))
        self.assertIn("WSL disk location changed for Ubuntu", titles(out))

    def test_invalid_windows_read_keeps_previous_evidence(self):
        self.run_audit(registration())
        before = self.store.get_meta(wslguard.STATE_KEY)
        out, obs = self.run_audit(None)
        self.assertIn("WSL registration visibility unavailable", titles(out))
        self.assertEqual(self.store.get_meta(wslguard.STATE_KEY), before)
        self.assertTrue(any(f.startswith("wsl:") for f in obs.failures))
        self.assertNotIn("wsl", obs.successes)

    def test_partial_windows_read_is_incomplete_not_clean(self):
        out, obs = self.run_audit(registration(errors=["WSL plugin list unreadable"]))
        self.assertIn("WSL registration visibility incomplete", titles(out))
        self.assertNotIn("wsl", obs.successes)

    def test_windows_side_skipped_without_the_domain(self):
        with mock.patch.object(wslguard, "ps_json") as ps:
            out, _ = self.run_audit(registration(), hosts=("wsl",))
        ps.assert_not_called()
        self.assertEqual(titles(out), ["no accepted WSL boundary checkpoint"])

    def test_registered_as_a_cross_domain_job(self):
        self.assertIn("wsl", RUNNERS)
        self.assertEqual(ALL_JOBS["wsl"][0], 300)
        # 2026-10-24 (ARGUS-SERVER.md W1): the boundary needs a Windows host,
        # so a plain Linux server does not schedule it.
        self.assertIn("wsl", WINDOWS_ONLY)
        self.assertNotIn("wsl", LINUX_ONLY)


if __name__ == "__main__":
    unittest.main()
