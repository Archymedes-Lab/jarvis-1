"""Argus server: packet sensor, netflow, logins, package integrity, alert
channels (docs/architecture/ARGUS-SERVER.md W3-W5). Synthetic fixtures only;
the one real-kernel test attaches the filter to an unprivileged UDP socket."""

import hashlib
import hmac
import io
import json
import os
import socket
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from jarvis.collectors.identity import logins
from jarvis.collectors.network import exposure, netflow
from jarvis.collectors.persistence import pkgverify
from jarvis.platform.netsensor import bpf, capture, spool
from jarvis.response import alert


class MetaStore:
    def __init__(self):
        self.meta = {}

    def get_meta(self, key, default=""):
        return self.meta.get(key, default)

    def set_meta(self, key, value):
        self.meta[key] = value


def ipv6(nh, payload, src="2001:db8::5"):
    import ipaddress
    return (struct.pack("!IHBB", 6 << 28, len(payload), nh, 64) + ipaddress.ip_address(src).packed
            + ipaddress.ip_address("2001:db8::1").packed + payload)


def dns_response(name):
    body = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00\x00\x01\x00\x01"
    return struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + body


# -- the kernel filter ----------------------------------------------------------

class FilterTests(unittest.TestCase):
    prog = bpf.program(lo_ifindex=1)

    def kept(self, packet, **kw):
        return bpf.interpret(self.prog, packet, **kw)

    def test_new_connections_keep_headers_only(self):
        # I5: a SYN with payload behind it is cut at IPv4 + 20 bytes of TCP.
        self.assertEqual(self.kept(bpf.ipv4(6, bpf.tcp(22, 0x02) + b"secret" * 50)), 40)
        self.assertEqual(self.kept(bpf.ipv4(6, bpf.tcp(22, 0x02), ihl=7)), 48)   # IP options counted
        for flags in (0x12, 0x10, 0x18, 0x04, 0x11):                            # SYN-ACK, ACK, PSH, RST, FIN
            self.assertEqual(self.kept(bpf.ipv4(6, bpf.tcp(22, flags))), 0, hex(flags))

    def test_udp_icmp_and_dns_lengths(self):
        self.assertEqual(self.kept(bpf.ipv4(17, bpf.udp(5000, b"payload" * 40))), 28)
        self.assertEqual(self.kept(bpf.ipv4(1, b"\x08\x00" + b"\x00" * 100)), 28)
        self.assertEqual(self.kept(bpf.ipv4(17, bpf.udp(1234, b"x" * 600, sport=53))), bpf.DNS_SNAP)
        self.assertEqual(self.kept(bpf.ipv4(17, bpf.udp(53, b"x" * 10))), 38)   # shorter than the cap

    def test_ipv6(self):
        v6 = bpf.ETH_P_IPV6
        self.assertEqual(self.kept(ipv6(6, bpf.tcp(443, 0x02) + b"x" * 80), protocol=v6), bpf.V6_TCP_SNAP)
        self.assertEqual(self.kept(ipv6(6, bpf.tcp(443, 0x12)), protocol=v6), 0)
        self.assertEqual(self.kept(ipv6(58, b"\x80\x00" + b"\x00" * 60), protocol=v6), bpf.V6_SMALL_SNAP)
        self.assertEqual(self.kept(ipv6(17, bpf.udp(9, b"y" * 99)), protocol=v6), bpf.V6_SMALL_SNAP)
        self.assertEqual(self.kept(ipv6(0, b"\x00" * 60), protocol=v6), 0)        # extension header: not parsed

    def test_only_inbound_non_loopback_ip(self):
        syn = bpf.ipv4(6, bpf.tcp(22, 0x02))
        self.assertEqual(self.kept(syn, pkttype=4), 0)          # outgoing
        self.assertEqual(self.kept(syn, pkttype=1), 0)          # broadcast
        self.assertEqual(self.kept(syn, ifindex=1), 0)          # loopback
        self.assertEqual(self.kept(syn, protocol=0x0806), 0)    # ARP
        self.assertEqual(self.kept(bpf.ipv4(6, bpf.tcp(22, 0x02), frag=0x2005)), 0)   # later fragment
        self.assertEqual(self.kept(bpf.ipv4(47, b"\x00" * 40)), 0)                    # GRE

    def test_truncated_packets_are_dropped_not_misread(self):
        self.assertEqual(self.kept(bpf.ipv4(6, b"\x00" * 6)), 0)
        self.assertEqual(self.kept(b"\x45"), 0)

    def test_the_real_kernel_accepts_the_program(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            self.assertEqual(bpf.attach(s, self.prog), len(self.prog))

    def test_the_real_kernel_rejects_a_broken_program(self):
        # Guards the guard: attach really hands bytecode to the kernel.
        broken = [(bpf.JMP | bpf.JEQ | bpf.K, 200, 0, 1), (bpf.RET | bpf.K, 0, 0, 0)]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s, self.assertRaises(OSError):
            bpf.attach(s, broken)


# -- parsing and windows -----------------------------------------------------------

class CaptureTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(capture.parse(bpf.ipv4(6, bpf.tcp(8080, 2))[:40], bpf.ETH_P_IP),
                         ("185.220.101.5", "syn", 8080, None))
        self.assertEqual(capture.parse(bpf.ipv4(1, b"\x08\x00\x00\x00\x00\x00\x00\x00"), bpf.ETH_P_IP)[1:],
                         ("icmp", None, "v4:8"))
        src, kind, dport, extra = capture.parse(bpf.ipv4(17, bpf.udp(41000, dns_response("a.b.example.com"), sport=53)),
                                                bpf.ETH_P_IP)
        self.assertEqual((kind, dport, extra[0]), ("udp", 41000, True))
        self.assertIsNone(capture.parse(b"\x45\x00", bpf.ETH_P_IP))
        self.assertIsNone(capture.parse(b"x" * 60, 0x0806))

    def test_dns_features_keep_no_names(self):
        label = "x8f3kq0zt7w2mv9b1c6n4r5y0p2l7d3a"
        resp, qlen, llen, ent = capture.dns_features(dns_response(label + ".tunnel.example"))
        self.assertTrue(resp)
        self.assertEqual(llen, len(label))
        self.assertGreater(ent, capture.ENTROPY_BITS)
        w = capture.Window(0)
        w.add("1.1.1.1", "udp", 41000, (resp, qlen, llen, ent))
        blob = json.dumps(w.to_json("abcdef01", 0, 60))
        self.assertNotIn(label, blob)
        self.assertNotIn("tunnel", blob)
        self.assertEqual(w.dns["high_entropy"], 1)

    def test_window_caps_are_counted(self):
        w = capture.Window(0)
        with mock.patch.object(capture, "MAX_SOURCES", 2), mock.patch.object(capture, "MAX_PORTS_PER_SOURCE", 3):
            for i in range(5):
                w.add(f"10.0.0.{i}", "syn", 22, None)
            for p in range(10):
                w.add("10.0.0.0", "syn", 1000 + p, None)
        self.assertEqual(len(w.sources), 2)
        self.assertEqual(w.stats["source_cap"], 3)
        self.assertEqual(len(w.sources["10.0.0.0"]["tports"]), 3)
        self.assertEqual(w.stats["port_cap"], 8)
        self.assertEqual(w.syn["22"] if "22" in w.syn else w.syn[22], 5)     # totals still counted

    def test_rate_limit(self):
        t = [0.0]
        rl = capture.RateLimit(10, clock=lambda: t[0])
        self.assertEqual(sum(rl.allow() for _ in range(50)), 10)
        t[0] += 0.5
        self.assertEqual(sum(rl.allow() for _ in range(50)), 5)

    def test_run_writes_sequenced_windows_and_a_partial_one_on_stop(self):
        syn = bpf.ipv4(6, bpf.tcp(22, 2))[:40]
        events = [(syn, 1.0), (syn, 30.0), (None, 61.0), (syn, 70.0), (None, 125.0), ("stop", 130.0)]

        class FakeSock:
            def __init__(self):
                self.i = 0

            def recvfrom(self, n):
                data, _t = events[self.i]
                if data is None or data == "stop":
                    raise socket.timeout
                return data, ("eth0", bpf.ETH_P_IP, 0, 1, b"")

            def getsockopt(self, *a):
                return struct.pack("II", 3, 1)

        sock = FakeSock()

        def clock():
            # The sensor reads the clock after each receive: the time of the
            # event just handed over.
            return events[max(sock.i - 1, 0)][1]

        def stop():
            done = events[sock.i][0] == "stop"
            return done

        def advance(fn):
            def wrapped(n):
                try:
                    return fn(n)
                finally:
                    sock.i = min(sock.i + 1, len(events) - 1)
            return wrapped
        sock.recvfrom = advance(sock.recvfrom)
        with tempfile.TemporaryDirectory() as d:
            capture.run(spool_dir=d, sock=sock, clock=clock, stop=stop)
            files = spool.list_windows(d)
            self.assertEqual([seq for _s, _b, seq, _p in files], [0, 1, 2])
            first, second, last = (spool.read_json(p) for *_x, p in files)
            self.assertEqual(first["syn"], {"22": 2})
            self.assertEqual(second["syn"], {"22": 1})
            self.assertTrue(last["partial"])
            self.assertEqual(first["stats"]["kernel_drops"], 1)
            self.assertEqual(len({w["boot"] for w in (first, second, last)}), 1)


# -- netflow ----------------------------------------------------------------------

def window(start, boot="aaaaaaaa", seq=0, sources=None, syn=None, stats=None, dns=None):
    return {"version": 1, "boot": boot, "seq": seq, "start": start, "end": start + 60,
            "syn": syn or {}, "udp": {}, "icmp": {}, "dns": dns or {},
            "stats": {"seen": 10, "kernel_packets": 10, "kernel_drops": 0, "over_rate": 0,
                      "source_cap": 0, "port_cap": 0, **(stats or {})},
            "sources": sources or {}}


def write_windows(d, wins):
    os.makedirs(os.path.join(d, spool.WINDOW_DIR), exist_ok=True)
    for w in wins:
        spool.write_json(os.path.join(d, spool.WINDOW_DIR, spool.window_name(w["start"], w["boot"], w["seq"])), w)


LISTEN = {1: {"proto": "tcp", "local_ip": "0.0.0.0", "local_port": 22, "remote_ip": "0.0.0.0",
              "remote_port": 0, "state": "LISTEN"},
          2: {"proto": "tcp", "local_ip": "0.0.0.0", "local_port": 9000, "remote_ip": "0.0.0.0",
              "remote_port": 0, "state": "LISTEN"}}
DECLARED = exposure.parse_declared("22/tcp\n")[0]


class NetflowTests(unittest.TestCase):
    def audit(self, d, store, now):
        return netflow.audit(store, now=now, spool_dir=d, table=LISTEN, declared=DECLARED, load=False)

    def titles(self, out):
        return {f["title"]: f for f in out}

    def test_not_installed_is_low_configuration_not_silence(self):
        # 2026-10-25: an opt-in not taken is stated (low) without counting as a
        # failing collector; an installed sensor that stops is visibility (below).
        out = netflow.audit(MetaStore(), now=0, spool_dir="/nonexistent/argus-net", table={}, load=False)
        self.assertEqual([(f["severity"], f["category"]) for f in out], [("low", "configuration")])
        from jarvis.core import incidents
        self.assertEqual(incidents.coverage_status(out), "complete")

    def test_scan_is_aggregated_and_declared_ports_do_not_count(self):
        now = 10_000
        scanner = {"tports": list(range(1, 30)), "syn": 29, "udp": 0, "icmp": 0, "uports": []}
        ssh_user = {"tports": [22], "syn": 1, "udp": 0, "icmp": 0, "uports": []}
        with tempfile.TemporaryDirectory() as d:
            write_windows(d, [window(now - 120, sources={"185.220.101.5": scanner, "185.220.101.9": scanner,
                                                         "8.8.8.8": ssh_user})])
            out = self.titles(self.audit(d, MetaStore(), now))
        scan = out["port scans against this server"]
        self.assertEqual(scan["severity"], "medium")
        self.assertIn("1 source network", scan["detail"])        # two scanners, one /24
        self.assertNotIn("undeclared open port 22/tcp is being found", out)

    def test_undeclared_open_port_found_by_a_scanner_is_high(self):
        now = 10_000
        scanner = {"tports": list(range(8990, 9020)), "syn": 30, "udp": 0, "icmp": 0, "uports": []}
        with tempfile.TemporaryDirectory() as d:
            write_windows(d, [window(now - 120, sources={"185.220.101.5": scanner})])
            out = self.titles(self.audit(d, MetaStore(), now))
        self.assertEqual(out["undeclared open port 9000/tcp is being found"]["severity"], "high")

    def test_continuity_gaps_restarts_and_staleness(self):
        # I7: a gap or a restart is reported, never stitched over.
        now = 10_000
        with tempfile.TemporaryDirectory() as d:
            store = MetaStore()
            write_windows(d, [window(now - 600, seq=0)])
            self.audit(d, store, now - 500)
            write_windows(d, [window(now - 400, seq=3), window(now - 300, boot="bbbbbbbb", seq=0)])
            out = self.titles(self.audit(d, store, now))
        self.assertIn("packet sensor windows are missing", out)
        self.assertIn("2 window(s) skipped", out["packet sensor windows are missing"]["detail"])
        self.assertIn("packet sensor restarted", out)
        self.assertIn("packet sensor has stopped reporting", out)       # newest ended 4 min ago

    def test_each_window_is_read_once(self):
        now = 10_000
        scanner = {"tports": list(range(1, 30)), "syn": 29, "udp": 0, "icmp": 0, "uports": []}
        with tempfile.TemporaryDirectory() as d:
            store = MetaStore()
            write_windows(d, [window(now - 60, sources={"185.220.101.5": scanner})])
            self.audit(d, store, now)
            self.assertEqual(netflow.read_new(store, d)[0], [])
            # The hour still remembers it: the finding does not flap away.
            self.assertIn("port scans against this server", self.titles(self.audit(d, store, now + 30)))
            self.assertNotIn("port scans against this server", self.titles(self.audit(d, store, now + 4000)))

    def test_drops_and_sampling_reduce_visibility(self):
        now = 10_000
        with tempfile.TemporaryDirectory() as d:
            write_windows(d, [window(now - 60, stats={"kernel_packets": 900, "kernel_drops": 100, "over_rate": 5})])
            out = self.titles(self.audit(d, MetaStore(), now))
        self.assertIn("packet sensor is dropping packets", out)
        self.assertIn("packet sensor sampled under load", out)

    def test_syn_flood_against_its_own_baseline(self):
        store = MetaStore()
        quiet = [{"syn": {"443": 20}} for _ in range(50)]
        self.assertEqual(netflow._floods(store, quiet), [])
        flood = netflow._floods(store, [{"syn": {"443": 5000}}])
        self.assertEqual([(p, n) for p, n, _m in flood], [(443, 5000)])
        self.assertEqual(netflow._floods(store, [{"syn": {"443": 450}}]), [])    # under the floor

    def test_dns_tunnel_shape(self):
        now = 10_000
        with tempfile.TemporaryDirectory() as d:
            write_windows(d, [window(now - 60, dns={"long_names": 5, "high_entropy": 40})])
            out = self.titles(self.audit(d, MetaStore(), now))
        self.assertIn("DNS traffic shaped like tunnelling", out)

    def test_corrupt_window_is_counted(self):
        now = 10_000
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, spool.WINDOW_DIR))
            with open(os.path.join(d, spool.WINDOW_DIR, spool.window_name(now - 60, "aaaaaaaa", 0)), "w") as fh:
                fh.write("{not json")
            out = self.titles(self.audit(d, MetaStore(), now))
        self.assertIn("packet windows unreadable", out)


# -- logins -------------------------------------------------------------------------

def acc(user, ip, method="publickey", fp="SHA256:aaaa"):
    tail = f": ED25519 {fp}" if method == "publickey" else ""
    return f"Accepted {method} for {user} from {ip} port 51234 ssh2{tail}"


class LoginTests(unittest.TestCase):
    def test_first_run_learns_but_still_pages_for_root_and_guesses(self):
        recs = [(100, f"Failed password for admin from 185.220.101.5 port {i} ssh2") for i in range(6)]
        recs += [(200, acc("deploy", "10.0.0.5")), (300, acc("root", "10.0.0.5")),
                 (400, acc("admin", "185.220.101.5", method="password"))]
        events, state, _f = logins.evaluate(recs, {}, {}, 500)
        kinds = sorted(e["kind"] for e in events)
        self.assertEqual(kinds, ["guessed", "password", "root"])
        self.assertTrue(state["learned_at"])

    def test_after_learning_new_keys_and_networks(self):
        state = {}
        logins.evaluate([(100, acc("deploy", "10.0.0.5"))], state, {}, 100)
        events, _s, _f = logins.evaluate([(200, acc("deploy", "10.0.0.6")),
                                          (300, acc("deploy", "198.51.100.10", fp="SHA256:bbbb"))], state, {}, 300)
        # 10.0.0.6 is the learned /24: only the 198.51.100.10 login is new, by key and by network.
        self.assertEqual(sorted(e["kind"] for e in events), ["new_key", "new_net"])
        self.assertTrue(all(e["ip"] == "198.51.100.10" for e in events))

    def test_findings_last_a_day_and_then_clear(self):
        e = {"ts": 1000, "kind": "root", "user": "root", "ip": "10.0.0.5", "net": "10.0.0.0/24", "method": "publickey"}
        self.assertEqual(len(logins.findings([e], 1000 + 3600)), 1)
        self.assertEqual(logins.findings([e], 1000 + 2 * 86400), [])

    def _popen(self, lines, rc=0, err=""):
        class P:
            returncode = rc

            def __init__(self, *a, **k):
                self.stdout = io.StringIO("".join(json.dumps(x) + "\n" for x in lines))

            def kill(self):
                pass

            def communicate(self, timeout=None):
                return "", err
        return P

    def test_journal_cursor_and_lost_cursor(self):
        lines = [{"__CURSOR": "c1", "__REALTIME_TIMESTAMP": "1000000", "_UID": "0",
                  "MESSAGE": acc("deploy", "10.0.0.5")}]
        recs, cursor, problem = logins.read_journal(None, run=self._popen(lines))
        self.assertEqual((len(recs), cursor, problem), (1, "c1", ""))
        recs, cursor, problem = logins.read_journal("old", run=self._popen([], rc=1, err="Failed to seek to cursor: x"))
        self.assertIsNone(cursor)                 # starts again instead of retrying forever
        self.assertIn("cursor is gone", problem)

    def test_unreadable_journal_is_not_observed(self):
        store = MetaStore()
        out = logins.audit(store, now=5, reader=lambda c: ([], c, "journalctl failed: permission denied"))
        self.assertEqual([f["category"] for f in out], ["visibility"])


# -- package integrity --------------------------------------------------------------

class PkgVerifyTests(unittest.TestCase):
    OUT = ("??5??????   /usr/sbin/sshd\n"
           "??5?????? c /etc/ssh/sshd_config\n"
           "????????? c /etc/sudoers\n"
           "?????????   /usr/lib/sudo/private.so\n"
           "missing     /usr/bin/su\n"
           "S.5....T.    /usr/lib64/libpam.so.0\n")

    def test_parse(self):
        changed, unverifiable = pkgverify.parse(self.OUT)
        self.assertEqual(changed, [("/usr/sbin/sshd", True, False), ("/usr/bin/su", False, True),
                                   ("/usr/lib64/libpam.so.0", True, False)])
        self.assertEqual(unverifiable, 1)

    def test_audit(self):
        run = lambda argv, **k: SimpleNamespace(returncode=1, stdout=self.OUT, stderr="")   # noqa: E731
        out = pkgverify.audit(manager="dpkg", run=run)
        sev = {f["title"]: f["severity"] for f in out}
        self.assertEqual(sev["packaged file changed: /usr/sbin/sshd"], "critical")
        self.assertEqual(sev["packaged file missing: /usr/bin/su"], "medium")
        self.assertIn("some packaged files could not be verified", sev)

    def test_no_manager_or_failure_is_not_clean(self):
        self.assertEqual(pkgverify.audit(manager="")[0]["category"], "visibility")
        fail = lambda argv, **k: SimpleNamespace(returncode=2, stdout="", stderr="dpkg: error\n")   # noqa: E731
        self.assertEqual(pkgverify.audit(manager="dpkg", run=fail)[0]["title"], "package integrity not checked")


# -- alert channels -----------------------------------------------------------------

class AlertChannelTests(unittest.TestCase):
    def test_channels(self):
        self.assertEqual(alert.channels({}, forwarder=""), [])
        self.assertEqual(alert.channels({"webhook_url": "http://insecure.example/x"}, forwarder=""), [])
        self.assertEqual(alert.channels({"webhook_url": "https://hooks.example/x", "ntfy_url": "https://ntfy.sh/t"},
                                        forwarder=""), ["webhook", "ntfy"])
        # I8: a log line nobody ships is not a channel.
        self.assertEqual(alert.channels({"syslog": True}, forwarder=""), [])
        self.assertEqual(alert.channels({"syslog": True}, forwarder="rsyslogd"), ["syslog"])

    def test_no_channel_stays_critical(self):
        with mock.patch.object(alert, "log_forwarder", return_value=""):
            f = alert.channel_findings({"syslog": True})
        self.assertEqual(f[0]["severity"], "critical")
        self.assertIn("no log forwarder", f[0]["detail"])

    def test_one_failing_channel_does_not_stop_another(self):
        conf = {"webhook_url": "https://hooks.example/x", "ntfy_url": "https://ntfy.sh/t"}
        sent = []
        senders = {"webhook": lambda: "webhook HTTP 500", "ntfy": lambda: sent.append(1) or ""}
        self.assertEqual(alert.deliver(conf, "s", "t", senders=senders), "")
        self.assertEqual(sent, [1])
        self.assertEqual(alert.LAST_DELIVERY["errors"], ["webhook: webhook HTTP 500"])
        senders = {"webhook": lambda: "a", "ntfy": lambda: (_ for _ in ()).throw(RuntimeError("boom"))}
        err = alert.deliver(conf, "s", "t", senders=senders)
        self.assertIn("webhook: a", err)
        self.assertIn("ntfy: RuntimeError", err)

    def test_errors_never_carry_the_url(self):
        secret_url = "https://127.0.0.1:9/services/T000/B000/sEcReTtOkEn"
        err = alert._post(secret_url, b"{}", {}, attempts=1, timeout=1, label="webhook")
        self.assertTrue(err)
        self.assertNotIn("sEcReTtOkEn", err)

    def test_webhook_signature_verifies(self):
        captured = {}

        def fake_post(url, body, headers, **kw):
            captured.update(body=body, headers=headers)
            return ""
        with mock.patch.object(alert, "_post", fake_post):
            alert.send_webhook({"webhook_url": "https://h.example/x", "webhook_secret": "k"}, "CRITICAL x", "t", now=77)
        want = hmac.new(b"k", b"77." + captured["body"], hashlib.sha256).hexdigest()
        self.assertEqual(captured["headers"]["X-Argus-Signature"], "sha256=" + want)
        self.assertEqual(json.loads(captured["body"])["priority"], "critical")

    def test_syslog_line(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "log")
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            srv.bind(path)
            try:
                self.assertEqual(alert.send_syslog("[JARVIS] CRITICAL thing", "line one\nline two", path=path), "")
                msg = srv.recv(4096).decode()
            finally:
                srv.close()
        self.assertTrue(msg.startswith("<26>argus["))
        self.assertIn("line one line two", msg)
        self.assertEqual(alert.send_syslog("s", "t", path="/nonexistent/log")[:13], "syslog socket")


if __name__ == "__main__":
    unittest.main()
