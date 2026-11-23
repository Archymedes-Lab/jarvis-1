"""osquery as an independent second view: containment, parsing and disagreement."""

import os
import stat
import subprocess
import tempfile
import unittest
from types import SimpleNamespace

from jarvis.collectors.host import osquery

HOST_NS = "4026531840"


def answer(kind, items, ns=HOST_NS):
    # osqueryi --json prints every value as a string.
    if kind == "listeners":
        return [{"port": str(v), "net_namespace": ns} for v in items]
    return [{osquery.FIELD[kind]: str(v)} for v in items]


class FakeHost:
    """Argus's own reads (before, after) and osquery's answer per view."""

    def __init__(self, ours=None, theirs=None, after=None):
        base = {"processes": {1, 10, 20}, "listeners": {22, 8787}, "modules": {"ext4", "nf_tables"}}
        self.ours = ours or base
        self.after = after or self.ours
        self.theirs = theirs if theirs is not None else {k: answer(k, v) for k, v in base.items()}
        self.calls = {k: 0 for k in base}
        self.asked = []

    def own(self):
        def reader(kind):
            def read():
                self.calls[kind] += 1
                return set(self.ours[kind] if self.calls[kind] == 1 else self.after[kind])
            return read
        return {k: reader(k) for k in self.calls}

    def ask(self, exe, sql):
        self.asked.append(sql)
        kind = next(k for k, q in osquery.QUERIES.items() if q == sql)
        return self.theirs.get(kind)

    def run(self, alive=lambda pid: True):
        return osquery.audit(locate_fn=lambda: "/usr/bin/osqueryi", ask_fn=self.ask,
                             own=self.own(), alive=alive, netns_fn=lambda: HOST_NS)


def sev(out):
    return [(f["severity"], f["title"]) for f in out]


class Agreement(unittest.TestCase):
    def test_same_sets_are_ok_and_only_fixed_queries_are_asked(self):
        h = FakeHost()
        out = h.run()
        self.assertEqual([f["severity"] for f in out], ["ok"])
        self.assertEqual(h.asked, list(osquery.QUERIES.values()))

    def test_not_installed_is_low_never_ok(self):
        out = osquery.audit(locate_fn=lambda: None, ask_fn=self.fail, own={})
        self.assertEqual([f["severity"] for f in out], ["low"])

    def fail(self, *a):
        raise AssertionError("osquery must not be asked when absent")


class Disagreement(unittest.TestCase):
    def test_process_hidden_from_argus_but_alive_is_high(self):
        theirs = {"processes": answer("processes", {1, 10, 20, 666}),
                  "listeners": answer("listeners", {22, 8787}), "modules": answer("modules", {"ext4", "nf_tables"})}
        out = FakeHost(theirs=theirs).run()
        highs = [f for f in out if f["severity"] == "high"]
        self.assertEqual(len(highs), 1)
        self.assertIn("666", highs[0]["detail"])

    def test_a_process_that_exited_is_a_race_not_a_finding(self):
        theirs = {"processes": answer("processes", {1, 10, 20, 666}),
                  "listeners": answer("listeners", {22, 8787}), "modules": answer("modules", {"ext4", "nf_tables"})}
        out = FakeHost(theirs=theirs).run(alive=lambda pid: pid != 666)
        self.assertNotIn("high", [f["severity"] for f in out])

    def test_a_process_in_either_argus_read_is_not_hidden(self):
        ours = {"processes": {1, 10, 20}, "listeners": {22, 8787}, "modules": {"ext4", "nf_tables"}}
        after = {"processes": {1, 10, 20, 777}, "listeners": {22, 8787}, "modules": {"ext4", "nf_tables"}}
        theirs = {"processes": answer("processes", {1, 10, 20, 777}),
                  "listeners": answer("listeners", {22, 8787}), "modules": answer("modules", {"ext4", "nf_tables"})}
        self.assertEqual([f["severity"] for f in FakeHost(ours=ours, after=after, theirs=theirs).run()], ["ok"])

    def test_listener_hidden_from_argus_is_high(self):
        theirs = {"processes": answer("processes", {1, 10, 20}),
                  "listeners": answer("listeners", {22, 8787, 31337}), "modules": answer("modules", {"ext4", "nf_tables"})}
        out = FakeHost(theirs=theirs).run()
        self.assertTrue(any(s == "high" and "listening TCP ports" in t for s, t in sev(out)))

    def test_seen_by_argus_raw_reads_but_not_osquery_is_high(self):
        # A system-wide hook (ld.so.preload) fools osquery but not Argus's raw reads.
        theirs = {"processes": answer("processes", {1, 10}),
                  "listeners": answer("listeners", {22, 8787}), "modules": answer("modules", {"ext4"})}
        out = FakeHost(theirs=theirs).run()
        got = sev(out)
        self.assertTrue(any(s == "high" and "kernel modules" in t for s, t in got))
        self.assertTrue(any(s == "high" and "process ids" in t for s, t in got))

    def test_unknown_namespace_rows_from_unprivileged_osquery_are_ignored(self):
        # Measured: unprivileged osqueryi 5.24 adds a net_namespace "0" duplicate per port.
        h = FakeHost()
        h.theirs["listeners"] = answer("listeners", {22, 8787}) + answer("listeners", {22, 8787, 9999}, ns="0")
        self.assertEqual([f["severity"] for f in h.run()], ["ok"])


class NetworkNamespaces(unittest.TestCase):
    def test_container_listeners_are_out_of_scope_not_hidden(self):
        h = FakeHost()
        h.theirs["listeners"] = answer("listeners", {22, 8787}) + answer("listeners", {5432, 6379}, ns="4026532999")
        self.assertEqual([f["severity"] for f in h.run()], ["ok"])

    def test_unscoped_answers_are_not_compared(self):
        h = FakeHost()
        h.theirs["listeners"] = [{"port": "22"}, {"port": "8787"}]
        out = h.run()
        self.assertIn("listening TCP ports", next(f["detail"] for f in out if "incomplete" in f["title"]))

    def test_unknown_own_namespace_is_not_compared(self):
        h = FakeHost()
        out = osquery.audit(locate_fn=lambda: "/x", ask_fn=h.ask, own=h.own(), alive=lambda p: True,
                            netns_fn=lambda: None)
        self.assertIn("listening TCP ports", next(f["detail"] for f in out if "incomplete" in f["title"]))

    def test_own_netns_parses_the_link(self):
        self.assertEqual(osquery.own_netns(lambda p: "net:[4026531840]"), "4026531840")
        self.assertIsNone(osquery.own_netns(lambda p: "garbage"))
        self.assertIsNotNone(osquery.own_netns())   # real host


class FailureIsNeverAgreement(unittest.TestCase):
    def test_failed_query_is_reported_and_that_view_is_not_ok(self):
        h = FakeHost()
        h.theirs["listeners"] = None
        out = h.run()
        low = [f for f in out if f["title"] == "osquery cross-view incomplete"]
        self.assertEqual(len(low), 1)
        self.assertIn("listening TCP ports", low[0]["detail"])
        ok = [f for f in out if f["severity"] == "ok"][0]
        self.assertNotIn("listening", ok["detail"])

    def test_malformed_rows_are_not_compared(self):
        h = FakeHost()
        h.theirs["processes"] = [{"pid": "x"}]
        h.theirs["modules"] = [{"name": ""}]
        out = h.run()
        self.assertIn("process ids", next(f["detail"] for f in out if "incomplete" in f["title"]))
        self.assertNotIn("high", [f["severity"] for f in out])

    def test_own_view_unreadable_is_not_compared(self):
        h = FakeHost()
        own = h.own()
        own["modules"] = lambda: None
        out = osquery.audit(locate_fn=lambda: "/x", ask_fn=h.ask, own=own, alive=lambda p: True,
                            netns_fn=lambda: HOST_NS)
        self.assertIn("kernel modules", next(f["detail"] for f in out if "incomplete" in f["title"]))

    def test_everything_failing_gives_no_ok(self):
        h = FakeHost(theirs={})
        self.assertNotIn("ok", [f["severity"] for f in h.run()])


class Containment(unittest.TestCase):
    def test_locate_only_trusts_root_owned_files_nobody_else_writes(self):
        files = {"/opt/osquery/bin/osqueryd": SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0),
                 "/bad": SimpleNamespace(st_mode=stat.S_IFREG | 0o777, st_uid=0),
                 "/user": SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=1000)}

        def st(p):
            if p not in files:
                raise FileNotFoundError(p)
            return files[p]
        links = {"/usr/bin/osqueryi": "/opt/osquery/bin/osqueryd"}
        rp = lambda p: links.get(p, p)  # noqa: E731
        self.assertEqual(osquery.locate(("/missing", "/bad", "/user", "/usr/bin/osqueryi"), st, rp),
                         "/usr/bin/osqueryi")
        self.assertIsNone(osquery.locate(("/bad", "/user"), st, rp))

    def test_ask_runs_fixed_args_without_shell_or_inherited_env_and_cleans_home(self):
        seen = {}

        def runner(args, **kw):
            seen.update(args=args, **kw)
            self.assertTrue(os.path.isdir(kw["env"]["HOME"]))
            return SimpleNamespace(returncode=0, stdout=b'[{"pid":"1"}]')
        rows = osquery.ask("/usr/bin/osqueryi", osquery.QUERIES["processes"], runner)
        self.assertEqual(rows, [{"pid": "1"}])
        self.assertEqual(seen["args"], ["/usr/bin/osqueryi", *osquery.FLAGS, osquery.QUERIES["processes"]])
        self.assertEqual(list(seen["env"]), ["HOME"])
        self.assertFalse(seen.get("shell", False))
        self.assertEqual(seen["timeout"], osquery.TIMEOUT_S)
        self.assertFalse(os.path.exists(seen["env"]["HOME"]))

    def test_ask_rejects_failures_oversize_and_bad_shapes(self):
        cases = [SimpleNamespace(returncode=1, stdout=b"[]"),
                 SimpleNamespace(returncode=0, stdout=b"x" * (osquery.MAX_OUTPUT + 1)),
                 SimpleNamespace(returncode=0, stdout=b"not json"),
                 SimpleNamespace(returncode=0, stdout=b'{"pid": "1"}'),
                 SimpleNamespace(returncode=0, stdout=b'["1"]')]
        for r in cases:
            self.assertIsNone(osquery.ask("/x", "SELECT 1;", lambda *a, _r=r, **k: _r))
        for exc in (OSError("gone"), subprocess.TimeoutExpired("x", 30)):
            def boom(*a, _e=exc, **k):
                raise _e
            self.assertIsNone(osquery.ask("/x", "SELECT 1;", boom))


class OwnView(unittest.TestCase):
    def test_listeners_are_listen_state_rows_only_read_raw(self):
        d = tempfile.mkdtemp()
        os.makedirs(f"{d}/net")
        head = "  sl  local_address rem_address   st tx_queue rx_queue\n"
        with open(f"{d}/net/tcp", "w") as fh:
            fh.write(head + "   0: 0100007F:2253 00000000:0000 0A 0\n"   # 8787 listen
                            "   1: 0100007F:0016 0100007F:A000 01 0\n")  # 22 established
        self.assertEqual(osquery.own_listeners(d), {8787})            # real raw syscalls
        self.assertIsNone(osquery.own_listeners(d, reader=lambda p: None))

    def test_raw_read_matches_ordinary_read_and_fails_closed(self):
        from jarvis.platform import procfs
        with open("/proc/net/tcp", "rb") as fh:
            ordinary = fh.read().splitlines()[0]
        self.assertEqual(procfs.read_raw("/proc/net/tcp").splitlines()[0], ordinary)
        self.assertIsNone(procfs.read_raw("/nonexistent/file"))
        self.assertLessEqual(len(procfs.read_raw("/proc/self/maps", limit=10)), 65536)

    def test_real_host_own_views_are_readable(self):
        self.assertTrue(osquery.own_processes())
        self.assertIsNotNone(osquery.own_listeners())
        self.assertIsNotNone(osquery.own_modules())


if __name__ == "__main__":
    unittest.main()
