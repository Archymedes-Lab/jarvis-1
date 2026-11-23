"""Argus on plain Linux servers (docs/architecture/ARGUS-SERVER.md).

Each test names the invariant it holds. Fixtures are synthetic: no test reads
this machine's sockets, mounts or firewall.
"""

import json
import os
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from jarvis.collectors.host import storage, wslguard
from jarvis.collectors.network import exposure, firewall
from jarvis.collectors.persistence import control
from jarvis.platform import host
from jarvis.platform.netsensor import netstate, spool
from jarvis.service import schedule

GIB = 1024 ** 3


def as_kind(kind):
    return mock.patch.object(host, "KIND", kind)


class MetaStore:
    def __init__(self):
        self.meta = {}

    def get_meta(self, key, default=""):
        return self.meta.get(key, default)

    def set_meta(self, key, value):
        self.meta[key] = value


# -- W1: honest applicability --------------------------------------------------

class ApplicabilityTests(unittest.TestCase):
    def test_windows_natured_jobs_are_not_applicable_on_a_server_with_a_reason(self):
        # I2: absent with a reason, never an empty success.
        keep, absent = schedule.applicable(windows=False, linux=True)
        for name in ("netwatch", "wsl"):
            self.assertNotIn(name, keep)
            self.assertIn("Windows", absent[name])
        for name in ("storage", "firewall", "backdoor", "bruteforce"):
            self.assertIn(name, keep)

    def test_wsl_workstation_keeps_both(self):
        # I9: nothing changes on the WSL workstation.
        keep, absent = schedule.applicable(windows=True, linux=True)
        self.assertIn("netwatch", keep)
        self.assertIn("wsl", keep)
        self.assertEqual(absent, {})

    def test_wsl_guard_reads_no_guest_on_plain_linux(self):
        with as_kind("linux"), mock.patch.object(wslguard.wsl_boundary, "snapshot") as snap:
            self.assertEqual(wslguard.audit(MetaStore(), hosts=("wsl",)), [])
            snap.assert_not_called()


# -- W1: storage on a server ---------------------------------------------------

def _vfs(free, total, ifree=10**6, itotal=10**6, frsize=4096):
    return SimpleNamespace(f_bavail=free // frsize, f_frsize=frsize, f_blocks=total // frsize,
                           f_favail=ifree, f_files=itotal)


MOUNTS = """\
/dev/sda1 / ext4 rw,relatime 0 0
proc /proc proc rw,nosuid 0 0
tmpfs /run tmpfs rw 0 0
/dev/sda1 /var/lib/docker/overlay ext4 rw 0 0
/dev/sdb1 /data xfs rw 0 0
/dev/loop0 /snap/core squashfs ro 0 0
/dev/sdc1 /backup ext4 ro 0 0
/dev/sdd1 /srv/my\\040files ext4 rw 0 0
"""


class StorageTests(unittest.TestCase):
    def _mounts(self, vfs, devs):
        return storage.linux_mounts(MOUNTS, statvfs=lambda m: vfs[m],
                                    stat=lambda m: SimpleNamespace(st_dev=devs[m]))

    def test_real_writable_mounts_once_per_device(self):
        vfs = {m: _vfs(50 * GIB, 100 * GIB) for m in ("/", "/var/lib/docker/overlay", "/data",
                                                       "/srv/my files")}
        devs = {"/": 1, "/var/lib/docker/overlay": 1, "/data": 2, "/srv/my files": 3}
        mounts, unreadable = self._mounts(vfs, devs)
        self.assertEqual([m[0] for m in mounts], ["/", "/data", "/srv/my files"])
        self.assertEqual(unreadable, [])

    def test_thresholds_and_inodes(self):
        mounts = [("/", "ext4", int(0.5 * GIB), 100 * GIB, 10**6, 10**6),
                  ("/data", "xfs", 6 * GIB, 100 * GIB, 10**6, 10**6),
                  ("/srv", "ext4", 50 * GIB, 100 * GIB, 1000, 10**6),
                  ("/ok", "btrfs", 80 * GIB, 100 * GIB, 0, 0)]
        found = {(f["where"], f["severity"], f["title"]) for f in
                 storage.judge_linux(mounts, [], time.time())}
        self.assertIn(("/", "critical", "/ is nearly full"), found)
        self.assertIn(("/data", "high", "/data is low on space"), found)
        self.assertIn(("/srv", "critical", "/srv is out of inodes"), found)
        self.assertFalse([f for f in found if f[0] == "/ok"])     # btrfs: no inode limit

    def test_growth_warns_in_days(self):
        now = 10**9
        history = {"/": [(now - 6 * 3600, 60 * GIB)]}          # 10 GiB lost in 6 h
        out = storage.judge_linux([("/", "ext4", 50 * GIB, 400 * GIB, 1, 1)], [], now, history)
        self.assertTrue(any("fills in" in f["title"] and f["severity"] == "high" for f in out))

    def test_unreadable_is_not_clean(self):
        # I1: a mount statvfs refused, or no mount table, is a visibility finding.
        self.assertEqual(storage.judge_linux(None, [], 0)[0]["category"], "visibility")
        out = storage.judge_linux([], ["/data"], 0)
        self.assertTrue(all(f["category"] == "visibility" for f in out))
        self.assertEqual(len(out), 2)

    def test_history_is_bounded_to_present_mounts(self):
        store = MetaStore()
        store.set_meta(storage.LINUX_HISTORY_META, json.dumps({"/gone": [[1, 2]]}))
        storage._linux_history(store, 5, [("/", "ext4", 7, 10, 1, 1)])
        self.assertEqual(json.loads(store.meta[storage.LINUX_HISTORY_META]), {"/": [[5, 7.0]]})

    def test_server_storage_does_not_report_windows(self):
        with as_kind("linux"), mock.patch.object(storage, "audit_linux", return_value=["x"]) as al:
            self.assertEqual(storage.audit(MetaStore(), hosts=("wsl",)), ["x"])
            al.assert_called_once()


# -- W2: declared services ----------------------------------------------------

class DeclaredTests(unittest.TestCase):
    def test_parse(self):
        declared, problems = exposure.parse_declared(
            "22/tcp  # ssh\n443\n5432/tcp 10.0.0.0/8 192.168.1.0/24\n53/udp\n"
            "70000/tcp\nabc\n22/sctp\n")
        self.assertEqual(set(declared), {(22, "tcp"), (443, "tcp"), (5432, "tcp"), (53, "udp")})
        self.assertEqual(len(problems), 3)

    def test_sources_narrow_only_that_port(self):
        declared, _ = exposure.parse_declared("5432/tcp 10.0.0.0/8\n22/tcp\n")
        self.assertTrue(exposure.is_declared(declared, 5432, "tcp", "10.1.2.3"))
        self.assertFalse(exposure.is_declared(declared, 5432, "tcp", "203.0.113.9"))
        self.assertTrue(exposure.is_declared(declared, 5432, "tcp6", "::ffff:10.1.2.3"))
        self.assertTrue(exposure.is_declared(declared, 22, "tcp", "203.0.113.9"))
        self.assertFalse(exposure.is_declared(declared, 22, "udp", "203.0.113.9"))
        self.assertFalse(exposure.is_declared(None, 22, "tcp"))

    def test_missing_file_is_undeclared_not_empty(self):
        declared, path, problems = exposure.load_declared(("/nonexistent/services.conf",))
        self.assertIsNone(declared)


# -- W2: nftables reachability --------------------------------------------------

def rs(*items):
    return {"nftables": list(items)}


def chain(name, policy="drop", hook="input", family="inet", table="filter"):
    return {"chain": {"family": family, "table": table, "name": name, "type": "filter",
                      "hook": hook, "prio": 0, "policy": policy}}


def regular(name, family="inet", table="filter"):
    return {"chain": {"family": family, "table": table, "name": name}}


def rule(chain_name, *expr, family="inet", table="filter"):
    return {"rule": {"family": family, "table": table, "chain": chain_name, "expr": list(expr)}}


def dport(value, proto="tcp", op="=="):
    return {"match": {"op": op, "left": {"payload": {"protocol": proto, "field": "dport"}},
                      "right": value}}


ACCEPT, DROP = {"accept": None}, {"drop": None}
CT_EST = {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}
LO = {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}
SADDR = {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                   "right": {"prefix": {"addr": "10.0.0.0", "len": 8}}}}


class NftTests(unittest.TestCase):
    def reach(self, ruleset, port, proto="tcp"):
        return exposure.nft_reachability(ruleset, port, proto)

    def test_typical_server(self):
        r = rs(chain("input"), rule("input", CT_EST, ACCEPT), rule("input", LO, ACCEPT),
               rule("input", dport({"set": [22, 443]}), ACCEPT), rule("input", dport({"range": [6000, 6010]}), ACCEPT))
        self.assertEqual(self.reach(r, 22), exposure.OPEN)
        self.assertEqual(self.reach(r, 443), exposure.OPEN)
        self.assertEqual(self.reach(r, 6005), exposure.OPEN)
        self.assertEqual(self.reach(r, 8080), exposure.FILTERED)   # established/lo do not open it
        self.assertEqual(self.reach(r, 22, "udp"), exposure.FILTERED)

    def test_policy_accept_and_explicit_drop(self):
        r = rs(chain("input", policy="accept"), rule("input", dport(23), DROP))
        self.assertEqual(self.reach(r, 23), exposure.FILTERED)
        self.assertEqual(self.reach(r, 80), exposure.OPEN)

    def test_source_restricted_accept(self):
        r = rs(chain("input"), rule("input", SADDR, dport(5432), ACCEPT))
        self.assertEqual(self.reach(r, 5432), exposure.RESTRICTED)

    def test_unreadable_rule_never_reads_as_filtered(self):
        # I1: an accept we cannot read could open the port.
        r = rs(chain("input"), rule("input", {"xt": {"type": "match", "name": "recent"}}, ACCEPT))
        self.assertEqual(self.reach(r, 8080), exposure.UNKNOWN)

    def test_jumps_are_followed(self):
        r = rs(chain("input"), regular("svc"), rule("input", {"jump": {"target": "svc"}}),
               rule("svc", dport(80), ACCEPT))
        self.assertEqual(self.reach(r, 80), exposure.OPEN)
        self.assertEqual(self.reach(r, 81), exposure.FILTERED)

    def test_every_base_chain_must_accept(self):
        r = rs(chain("a", policy="accept", table="t1"), chain("b", table="t2"),
               rule("b", dport(22), ACCEPT, table="t2"))
        self.assertEqual(self.reach(r, 22), exposure.OPEN)
        self.assertEqual(self.reach(r, 80), exposure.FILTERED)

    def test_no_input_hook_filters_nothing(self):
        self.assertEqual(self.reach(rs(chain("out", hook="output")), 22), exposure.OPEN)
        self.assertEqual(exposure.nft_input_policies(rs(chain("out", hook="output"))), [])

    def test_garbage_does_not_raise(self):
        for junk in (None, {}, {"nftables": "x"}, {"nftables": [1, {"rule": "x"}, {"chain": 3}]}):
            self.assertIn(self.reach(junk, 22), (exposure.OPEN, exposure.UNKNOWN))


class TextFirewallTests(unittest.TestCase):
    def test_ufw(self):
        u = exposure.parse_ufw("Status: active\nLogging: on (low)\n"
                               "Default: deny (incoming), allow (outgoing), disabled (routed)\n\n"
                               "To                         Action      From\n"
                               "--                         ------      ----\n"
                               "22/tcp                     ALLOW IN    Anywhere\n"
                               "5432/tcp                   ALLOW IN    10.0.0.0/8\n")
        self.assertTrue(u["active"])
        self.assertEqual(u["default_in"], "deny")
        self.assertEqual(u["allow"], {(22, "tcp"): False, (5432, "tcp"): True})

    def test_firewalld(self):
        f = exposure.parse_firewalld("public (active)\n  target: default\n  services: ssh https\n"
                                     "  ports: 8443/tcp\n  sources: \n")
        self.assertEqual(set(f["allow"]), {(22, "tcp"), (443, "tcp"), (8443, "tcp")})

    def test_snapshot_fallbacks(self):
        ufw = {"ufw": {"ok": True, "text": "Status: active\nDefault: deny (incoming)\n22/tcp ALLOW IN Anywhere\n"},
               "nft": {"ok": False, "error": "exit 1"}}
        self.assertEqual(exposure.reachability(ufw, 22, "tcp")[0], exposure.OPEN)
        self.assertEqual(exposure.reachability(ufw, 80, "tcp")[0], exposure.FILTERED)
        self.assertEqual(exposure.reachability({}, 80, "tcp")[0], exposure.UNKNOWN)


# -- W2: the server firewall audit ------------------------------------------------

def sock(proto, lip, lport, rip="0.0.0.0", rport=0, state="LISTEN"):
    return {"proto": proto, "local_ip": lip, "local_port": lport, "remote_ip": rip,
            "remote_port": rport, "state": state}


TABLE = {
    1: sock("tcp", "0.0.0.0", 22), 2: sock("tcp6", "::", 443), 3: sock("tcp", "0.0.0.0", 9000),
    4: sock("tcp", "127.0.0.1", 5432), 5: sock("udp", "0.0.0.0", 68),
    10: sock("tcp", "198.51.100.7", 22, "185.220.101.5", 51000, "ESTABLISHED"),
    11: sock("tcp6", "2001:db8::1", 443, "2001:db8:ffff::9", 51001, "ESTABLISHED"),
    12: sock("tcp", "198.51.100.7", 9000, "185.220.101.66", 40000, "ESTABLISHED"),
    13: sock("tcp", "198.51.100.7", 9000, "10.0.0.8", 40001, "ESTABLISHED"),
    14: sock("tcp", "127.0.0.1", 5432, "127.0.0.1", 40002, "ESTABLISHED"),
}
FIREWALL = {"ts": 0, "nft": {"ok": True, "ruleset": rs(
    chain("input"), rule("input", CT_EST, ACCEPT), rule("input", dport({"set": [22, 443, 9000]}), ACCEPT))}}


class ServerFirewallTests(unittest.TestCase):
    def run_audit(self, declared_text=None, snap=FIREWALL, problem=""):
        declared = exposure.parse_declared(declared_text)[0] if declared_text is not None else None
        return firewall.audit_server(table=TABLE, declared=declared, snapshot=snap,
                                     snapshot_problem=problem, load=False)

    def test_declared_traffic_is_not_a_finding(self):
        # I3: the server doing its job is silent.
        out = self.run_audit("22/tcp\n443/tcp\n")
        titles = [f["title"] for f in out]
        self.assertFalse([t for t in titles if "22/" in t or "443/" in t])
        self.assertIn("internet clients on undeclared port 9000/tcp", titles)
        self.assertNotIn("critical", {f["severity"] for f in out})

    def test_undeclared_open_service_is_high_and_aggregated(self):
        out = self.run_audit("22/tcp\n443/tcp\n")
        exposed = [f for f in out if f["title"] == "undeclared service listening on 9000/tcp"]
        self.assertEqual(len(exposed), 1)
        self.assertEqual(exposed[0]["severity"], "high")
        inbound = [f for f in out if "undeclared port 9000" in f["title"]]
        self.assertEqual({f["severity"] for f in inbound}, {"high", "medium"})

    def test_filtered_listener_is_low(self):
        snap = {"ts": 0, "nft": {"ok": True, "ruleset": rs(chain("input"), rule("input", dport(22), ACCEPT))}}
        out = self.run_audit("22/tcp\n443/tcp\n", snap=snap)
        f = next(f for f in out if f["title"] == "undeclared service listening on 9000/tcp")
        self.assertEqual(f["severity"], "low")

    def test_without_declarations_nothing_is_high_and_the_gap_is_named(self):
        out = self.run_audit(None)
        self.assertNotIn("high", {f["severity"] for f in out})
        self.assertIn("exposed services are not declared", [f["title"] for f in out])

    def test_an_all_commented_file_is_still_undeclared(self):
        out = self.run_audit("# 22/tcp\n# 9000/tcp\n")
        self.assertNotIn("high", {f["severity"] for f in out})
        self.assertIn("exposed services are not declared", [f["title"] for f in out])

    def test_unobserved_firewall_is_unknown_not_open(self):
        # I1: a stale or missing snapshot never claims the port is open or closed.
        import tempfile
        from unittest import mock

        from jarvis.collectors.network import exposure
        with mock.patch.object(exposure, "NET_DIR", "/nonexistent/argus-net"):
            out = self.run_audit("22/tcp\n443/tcp\n", snap=None, problem="not installed")
        f = next(f for f in out if f["title"] == "undeclared service listening on 9000/tcp")
        self.assertEqual(f["severity"], "medium")
        self.assertIn("not known", f["detail"])
        # Opt-in sensor absent: unknown posture stated, not a failing collector.
        absent = next(f for f in out if f["title"] == "firewall rules are not read")
        self.assertEqual((absent["severity"], absent["category"]), ("medium", "configuration"))
        # Sensor installed but no snapshot: that is a visibility failure.
        with tempfile.TemporaryDirectory() as d, mock.patch.object(exposure, "NET_DIR", d):
            out = self.run_audit("22/tcp\n443/tcp\n", snap=None, problem="has not run")
        stale = next(f for f in out if f["title"] == "firewall rules not observed")
        self.assertEqual(stale["category"], "visibility")

    def test_dhcp_client_is_not_a_service_and_loopback_is_ignored(self):
        titles = " ".join(f["title"] for f in self.run_audit("22/tcp\n443/tcp\n9000/tcp\n"))
        self.assertNotIn("68/udp", titles)
        self.assertNotIn("5432", titles)

    def test_no_input_chain_is_named(self):
        snap = {"ts": 0, "nft": {"ok": True, "ruleset": rs()}}
        out = self.run_audit("22/tcp\n443/tcp\n", snap=snap)
        f = next(f for f in out if f["title"] == "no inbound packet filtering")
        self.assertEqual(f["severity"], "high")     # 9000 is undeclared and open

    def test_workstation_keeps_its_audit(self):
        # I9: the WSL path is untouched.
        with as_kind("wsl"), mock.patch.object(firewall, "audit_server") as srv, \
                mock.patch.object(firewall, "socket_table", return_value={}), \
                mock.patch.object(firewall, "read_file", return_value="x"):
            firewall.audit_linux()
            srv.assert_not_called()


class ControlDedupTests(unittest.TestCase):
    SS = ("Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
          "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"
          "tcp LISTEN 0 128 0.0.0.0:5938 0.0.0.0:* users:((\"teamviewerd\",pid=2,fd=3))\n")

    def findings(self, kind):
        with as_kind(kind), mock.patch.object(control, "_run", side_effect=lambda cmd, **k: self.SS if cmd[0] == "ss" else ""), \
                mock.patch.object(control.glob, "glob", side_effect=lambda p: ["/k"] if "authorized_keys" in p else []), \
                mock.patch("builtins.open", mock.mock_open(read_data="ssh-ed25519 AAAA me@laptop\n")):
            return control.audit_linux()

    def test_server_leaves_keys_and_plain_listeners_to_their_owners(self):
        titles = [f["title"] for f in self.findings("linux")]
        self.assertNotIn("SSH key can log in as this user", titles)
        listening = [t for t in titles if t == "listening on all interfaces"]
        self.assertEqual(len(listening), 1)      # the remote-access agent stays visible

    def test_workstation_unchanged(self):
        titles = [f["title"] for f in self.findings("wsl")]
        self.assertIn("SSH key can log in as this user", titles)
        self.assertEqual(titles.count("listening on all interfaces"), 2)


# -- W5: spool and the firewall reader ----------------------------------------------

class SpoolTests(unittest.TestCase):
    def test_atomic_write_and_bounded_read(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.json")
            spool.write_json(path, {"a": 1})
            self.assertEqual(spool.read_json(path), {"a": 1})
            self.assertEqual([n for n in os.listdir(d)], ["x.json"])
            with self.assertRaises(ValueError):
                spool.read_json(path, max_bytes=3)
            os.symlink(path, os.path.join(d, "link.json"))
            with self.assertRaises(OSError):
                spool.read_json(os.path.join(d, "link.json"))

    def test_windows_sort_by_time_across_restarts_and_prune(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, spool.WINDOW_DIR))
            for start, boot, seq in ((100, "aaaaaaaa", 7), (160, "aaaaaaaa", 8), (220, "bbbbbbbb", 0)):
                spool.write_json(os.path.join(d, spool.WINDOW_DIR, spool.window_name(start, boot, seq)), {})
            self.assertEqual([(b, s) for _t, b, s, _p in spool.list_windows(d)],
                             [("aaaaaaaa", 7), ("aaaaaaaa", 8), ("bbbbbbbb", 0)])
            self.assertEqual(spool.prune(d, keep=1), 2)
            self.assertEqual(len(spool.list_windows(d)), 1)


class NetstateTests(unittest.TestCase):
    def test_every_source_says_whether_it_was_read(self):
        def run(argv, **kw):
            name = os.path.basename(argv[0])
            if name == "nft":
                return SimpleNamespace(returncode=0, stdout=b'{"nftables": []}', stderr=b"")
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"ERROR: You need to be root\n")
        snap = netstate.snapshot(run=run, which=lambda n, path=None: "/usr/sbin/" + n, now=5)
        self.assertEqual(snap["nft"], {"ok": True, "ruleset": {"nftables": []}})
        self.assertFalse(snap["ufw"]["ok"])
        self.assertIn("root", snap["ufw"]["error"])

    def test_missing_tools_and_timeouts_are_errors_not_absence(self):
        snap = netstate.snapshot(which=lambda n, path=None: None, now=5)
        self.assertTrue(all(snap[k] == {"ok": False, "error": "not installed"} for k in ("nft", "ufw", "firewalld")))

        def slow(argv, **kw):
            raise netstate.subprocess.TimeoutExpired(argv, 20)
        snap = netstate.snapshot(run=slow, which=lambda n, path=None: "/x/" + n, now=5)
        self.assertIn("timed out", snap["nft"]["error"])

    def test_commands_only_list(self):
        for _name, argv, _json in netstate.COMMANDS:
            self.assertTrue({"list", "status", "--list-all"} & set(argv), argv)
            self.assertFalse({"add", "delete", "flush", "allow", "deny", "--add-port"} & set(argv))

    def test_stale_snapshot_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            spool.write_json(os.path.join(d, "netstate.json"), {"ts": 1000})
            snap, problem = exposure.load_netstate(d, now=1000 + 3600)
            self.assertIn("min old", problem)
            snap, problem = exposure.load_netstate(d, now=1001)
            self.assertEqual(problem, "")
            _snap, problem = exposure.load_netstate(os.path.join(d, "missing"), now=0)
            self.assertIn("not installed", problem)


if __name__ == "__main__":
    unittest.main()
