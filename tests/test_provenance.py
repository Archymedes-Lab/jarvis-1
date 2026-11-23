"""Execution identities, the issuing authority and the agent capsule.

Invariants (docs/architecture/EVIDENCE-FABRIC.md): P1 identity comes from a
signature by a key the user's processes cannot read, never a name; P2/P3
anything unverifiable is "no provenance"; P4 the binding is observed by the
authority, not supplied by the requester; P6 capsules never use /tmp; P7
everything is bounded.

A throwaway key pair under TMPDIR stands in for the root-owned key. Nothing
here touches /etc/jarvis or the live ledger.
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from jarvis.platform.provenance import authority as auth
from jarvis.platform.provenance import capsule
from jarvis.platform.provenance import identity as ident


def private_tmp():
    """A temp root no other account can write, whatever TMPDIR is: these
    tests assert that world-writable locations are refused (P6)."""
    base = os.path.expanduser("~/.cache/jarvis-tests")
    os.makedirs(base, mode=0o700, exist_ok=True)
    return base


class Keys:
    def __init__(self, base):
        self.dir = Path(base) / "keys"
        ident.generate_keypair(self.dir, owner=os.getuid())
        self.private = ident.load_private_key(self.dir / "ed25519.key")
        self.public = ident.load_public_key(self.dir / "ed25519.pub")
        self.public_path = self.dir / "ed25519.pub"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=private_tmp())
        self.addCleanup(self.tmp.cleanup)
        os.chmod(self.tmp.name, 0o700)
        self.keys = Keys(self.tmp.name)
        self.ledger = Path(self.tmp.name) / "state" / "ledger.jsonl"
        self.index = ident.Index(self.ledger, self.keys.public_path)
        self.authority = auth.Authority(self.keys.private, ledger=self.ledger,
                                        socket_path=Path(self.tmp.name) / "state" / "a.sock",
                                        release_id="sha256:" + "1" * 64)

    def record(self, **over):
        me = ident.proc_stat(os.getpid())
        args = dict(actor="codex", basis="declared", pid=os.getpid(), start=me[1],
                    exe=ident.proc_exe(os.getpid()), uid=os.getuid(), release_id="", ttl_s=60)
        args.update(over)
        return ident.make_identity(**args)


class SigningTests(Base):
    def test_keys_are_created_owner_only(self):
        self.assertEqual(os.stat(self.keys.dir / "ed25519.key").st_mode & 0o777, 0o400)
        self.assertEqual(os.stat(self.keys.public_path).st_mode & 0o777, 0o444)
        again = ident.generate_keypair(self.keys.dir, owner=os.getuid())   # idempotent
        self.assertEqual(again, ident.key_id(self.keys.public))

    def test_signature_round_trip_and_tamper(self):
        row = ident.sign(self.record(), self.keys.private)
        self.assertIsNotNone(ident.verify_row(row, self.keys.public))
        for field, value in (("actor", "jarvis"), ("actor_basis", "observed"),
                             ("expires_boot_s", 1e12)):
            forged = json.loads(json.dumps(row))
            forged["identity"][field] = value
            self.assertIsNone(ident.verify_row(forged, self.keys.public), field)
        forged = json.loads(json.dumps(row))
        forged["identity"]["binding"]["pid"] = 1
        self.assertIsNone(ident.verify_row(forged, self.keys.public))

    def test_other_key_is_not_trusted(self):
        other = Keys(Path(self.tmp.name) / "attacker")
        row = ident.sign(self.record(actor="jarvis", basis="observed"), other.private)
        self.assertIsNone(ident.verify_row(row, self.keys.public))
        self.assertIsNone(ident.verify_row(row, None))

    def test_record_bounds(self):
        with self.assertRaises(ident.ProvenanceError):
            self.record(actor="root")
        with self.assertRaises(ident.ProvenanceError):
            self.record(ttl_s=ident.MAX_TTL_S + 1)
        with self.assertRaises(ident.ProvenanceError):
            self.record(capabilities=[f"c{i}" for i in range(ident.MAX_CAPABILITIES + 1)])
        rec = self.record(purpose="x\n\x1b[31m" + "y" * 500, session="s" * 200)
        self.assertEqual(len(rec["purpose"]), ident.MAX_TEXT)
        self.assertNotIn("\n", rec["purpose"])
        self.assertEqual(len(rec["session"]), 64)


class LiveBindingTests(Base):
    def test_live_problems(self):
        rec = self.record()
        self.assertEqual(ident.live_problem(rec), "")
        self.assertEqual(ident.live_problem(rec, boot="other-boot"), "different boot")
        self.assertEqual(ident.live_problem(rec, boot_now=rec["expires_boot_s"] + 1), "expired")
        self.assertEqual(ident.live_problem(rec, stat=(1, rec["binding"]["start"] + 1)),
                         "process gone or pid reused")
        self.assertIn("different executable", ident.live_problem(rec, exe="/usr/bin/evil"))

    def test_wall_clock_jump_does_not_extend_an_identity(self):
        rec = self.record(now=0)            # wall clock claims 1970: irrelevant
        self.assertEqual(ident.live_problem(rec), "")
        self.assertEqual(ident.live_problem(rec, boot_now=rec["expires_boot_s"]), "expired")

    def test_stat_parses_names_with_parentheses(self):
        stat = ident.proc_stat(os.getpid())
        self.assertEqual(stat[0], os.getppid())
        self.assertIsNone(ident.proc_stat(2 ** 22 + 7))


class LedgerTests(Base):
    def test_forged_and_garbage_rows_are_skipped_and_counted(self):
        self.authority.issue_self()
        other = Keys(Path(self.tmp.name) / "attacker")
        with open(self.ledger, "a") as fh:
            fh.write("not json\n")
            fh.write(json.dumps(ident.sign(self.record(), other.private)) + "\n")
            fh.write("x" * (ident.MAX_ROW_BYTES + 10) + "\n")
        me = ident.proc_stat(os.getpid())
        found = ident.lookup(os.getpid(), me[1], self.index)
        self.assertEqual(found.actor, "jarvis")
        self.assertEqual(found.actor_basis, "observed")
        self.assertEqual(self.index.rejected, 3)

    def test_deleting_the_ledger_loses_attribution_only(self):
        self.authority.issue_self()
        me = ident.proc_stat(os.getpid())
        self.assertIsNotNone(ident.lookup(os.getpid(), me[1], self.index))
        self.ledger.unlink()
        self.assertIsNone(ident.lookup(os.getpid(), me[1], self.index))

    def test_missing_public_key_means_no_provenance(self):
        self.authority.issue_self()
        index = ident.Index(self.ledger, Path(self.tmp.name) / "absent.pub")
        me = ident.proc_stat(os.getpid())
        self.assertIsNone(ident.lookup(os.getpid(), me[1], index))

    def test_rotation_bounds_disk(self):
        with mock.patch.object(ident, "LEDGER_ROTATE_BYTES", 4000):
            for _ in range(30):
                self.authority.issue_self()
        rotated = self.ledger.with_name(self.ledger.name + ".1")
        self.assertTrue(rotated.exists())
        self.assertLessEqual(self.ledger.stat().st_size, 4000)
        self.assertFalse(self.ledger.with_name(self.ledger.name + ".2").exists())
        me = ident.proc_stat(os.getpid())
        self.assertIsNotNone(ident.lookup(os.getpid(), me[1], self.index))

    def test_request_flood_cannot_evict_live_identities(self):
        self.authority.issue_self()
        me = ident.proc_stat(os.getpid())
        other = Keys(Path(self.tmp.name) / "flooder")
        dead = self.record(pid=2 ** 22 + 7, start=1)          # binds nothing live
        with mock.patch.object(ident, "LEDGER_ROTATE_BYTES", 6000):
            for _ in range(40):                                 # several rotations
                ident.append(ident.sign(dead, other.private), self.ledger)
        found = ident.lookup(os.getpid(), me[1], self.index)
        self.assertIsNotNone(found)
        self.assertEqual(found.actor, "jarvis")
        self.assertLessEqual(self.ledger.stat().st_size, 6000)
        self.assertFalse(found.as_dict()["mitigates_findings"])

    def test_attribute_walks_live_ancestry(self):
        self.authority.issue_self()
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        found = ident.attribute(child.pid, self.index)
        self.assertEqual(found.pid, os.getpid())
        self.assertEqual(found.chain, (child.pid, os.getpid()))
        self.assertEqual(found.as_dict()["advisory"], "attribution only")

    def test_unattested_process_has_no_provenance(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        self.assertIsNone(ident.attribute(child.pid, self.index))


class AuthorityTests(Base):
    def req(self, **over):
        body = {"op": "issue", "actor": "codex", "session": "s1"}
        body.update(over)
        return body

    def test_binding_is_observed_not_requested(self):
        me = ident.proc_stat(os.getpid())
        reply = self.authority.handle(self.req(pid=1, start=5, binding={"pid": 1}),
                                      os.getpid(), os.getuid())
        self.assertTrue(reply["ok"], reply)
        b = reply["row"]["identity"]["binding"]
        self.assertEqual((b["pid"], b["start"]), (os.getpid(), me[1]))
        self.assertEqual(reply["row"]["identity"]["actor_basis"], "declared")
        self.assertEqual(reply["row"]["identity"]["release_id"], "sha256:" + "1" * 64)

    def test_refusals(self):
        uid = os.getuid()
        cases = [(self.req(actor="jarvis"), uid), (self.req(actor="root"), uid),
                 (self.req(), uid + 1), ({"op": "sign", "data": "x"}, uid), (None, uid),
                 (self.req(capabilities="net"), uid), (self.req(ttl_s="x"), uid)]
        for body, requester_uid in cases:
            reply = self.authority.handle(body, os.getpid(), requester_uid)
            self.assertFalse(reply["ok"], body)
        self.assertFalse(self.authority.handle(self.req(), 2 ** 22 + 7, uid)["ok"])

    def test_rate_limited(self):
        now = [100.0]
        self.authority.clock = lambda: now[0]
        results = [self.authority.handle(self.req(), os.getpid(), os.getuid())["ok"]
                   for _ in range(auth.RATE_PER_MINUTE + 3)]
        self.assertEqual(results.count(True), auth.RATE_PER_MINUTE)
        now[0] += 61
        self.assertTrue(self.authority.handle(self.req(), os.getpid(), os.getuid())["ok"])

    def test_exited_requester_is_refused(self):
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        child.wait()
        pidfd = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, pidfd)
        # A live pidfd passes; the exited child's pid is not observable.
        self.assertTrue(auth._pidfd_alive(pidfd))
        self.assertFalse(self.authority.handle(self.req(), child.pid, os.getuid())["ok"])

    def test_socket_round_trip_and_oversize(self):
        server = self.authority.bind()
        self.addCleanup(server.close)
        self.assertEqual(os.stat(self.authority.socket_path).st_mode & 0o777, 0o600)
        threading.Thread(target=self.authority.serve_forever, args=(server,),
                         daemon=True).start()
        record, reason = capsule.obtain("codex", "s", "/w", ["build"], "test", 60,
                                        socket_path=self.authority.socket_path,
                                        public_key=self.keys.public)
        self.assertIsNotNone(record, reason)
        self.assertEqual(record["binding"]["pid"], os.getpid())
        big = auth.request({"op": "issue", "actor": "codex", "purpose": "x" * 5000},
                           self.authority.socket_path)
        self.assertFalse(big["ok"])

    def test_start_reports_unavailable_without_key(self):
        with mock.patch.object(ident, "PRIVATE_KEY", Path(self.tmp.name) / "absent"):
            self.assertTrue(auth.start().startswith("unavailable"))


class CapsuleTests(Base):
    def setUp(self):
        super().setUp()
        self.devnull = open(os.devnull, "w")
        self.addCleanup(self.devnull.close)

    def test_reply_must_be_signed_and_bind_the_caller(self):
        me = ident.proc_stat(os.getpid())
        good = {"ok": True, "row": ident.sign(self.record(), self.keys.private)}
        self.assertIsNotNone(capsule.verify_reply(good, self.keys.public, os.getpid(), me[1]))
        self.assertIsNone(capsule.verify_reply(good, self.keys.public, os.getpid(), me[1] + 1))
        other = Keys(Path(self.tmp.name) / "squatter")
        forged = {"ok": True, "row": ident.sign(self.record(), other.private)}
        self.assertIsNone(capsule.verify_reply(forged, self.keys.public, os.getpid(), me[1]))

    def test_workspace_is_private_and_never_world_writable(self):
        root = Path(self.tmp.name) / "capsules"
        ws = capsule.make_workspace("codex", "s1", root)
        self.assertEqual(os.stat(ws).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(ws / "tmp").st_mode & 0o777, 0o700)
        with self.assertRaises(FileExistsError):
            capsule.make_workspace("codex", "s1", root)
        for bad in ("../x", "a/b", "", "x" * 65):
            with self.assertRaises(ident.ProvenanceError):
                capsule.make_workspace("codex", bad, root)
        with self.assertRaises(ident.ProvenanceError):
            capsule.make_workspace("jarvis", "s2", root)
        shared = Path(self.tmp.name) / "shared"
        shared.mkdir(mode=0o777)
        os.chmod(shared, 0o1777)
        with self.assertRaises(ident.ProvenanceError):
            capsule.make_workspace("codex", "s3", shared / "capsules")

    def test_run_attributes_the_tree_and_keeps_tmp_private(self):
        server = self.authority.bind()
        self.addCleanup(server.close)
        threading.Thread(target=self.authority.serve_forever, args=(server,),
                         daemon=True).start()
        root = Path(self.tmp.name) / "capsules"
        report = Path(self.tmp.name) / "child.json"
        code = ("import json, os, sys, time, tempfile\n"
                "json.dump({'pid': os.getpid(), 'tmp': tempfile.gettempdir(),"
                " 'actor': os.environ.get('JARVIS_CAPSULE')}, open(sys.argv[1], 'w'))\n"
                "time.sleep(3)\n")
        seen = {}

        def observe():
            # Monotonic: the wall clock here steps by ~9 s (WSL clock fight).
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and "prov" not in seen:
                try:
                    child = json.loads(report.read_text())
                except (OSError, ValueError):
                    time.sleep(0.05)
                    continue
                seen["child"] = child
                seen["prov"] = ident.attribute(child["pid"], self.index)

        watcher = threading.Thread(target=observe)
        watcher.start()
        status = capsule.run("test_suite", [sys.executable, "-c", code, str(report)],
                             session="t1", root=root, socket_path=self.authority.socket_path,
                             public_key=self.keys.public, out=self.devnull)
        watcher.join()
        self.assertEqual(status, 0)
        self.assertEqual(seen["child"]["actor"], "test_suite")
        self.assertTrue(seen["child"]["tmp"].startswith(str(root / "test_suite" / "t1" / "tmp")))
        prov = seen["prov"]
        self.assertIsNotNone(prov)
        self.assertEqual((prov.actor, prov.actor_basis, prov.session),
                         ("test_suite", "declared", "t1"))
        self.assertEqual(prov.pid, os.getpid())       # the launcher is the capsule root
        meta = json.loads((root / "test_suite" / "t1" / "session.json").read_text())
        self.assertEqual(meta["provenance"], "signed")
        self.assertEqual(meta["exit_status"], 0)
        self.assertNotIn("-c", json.dumps(meta))      # no command lines recorded

    def test_run_without_authority_still_runs_but_is_unattributed(self):
        root = Path(self.tmp.name) / "capsules"
        status = capsule.run("codex", [sys.executable, "-c", "raise SystemExit(3)"],
                             session="t2", root=root,
                             socket_path=Path(self.tmp.name) / "nobody.sock",
                             public_key=self.keys.public, out=self.devnull)
        self.assertEqual(status, 3)
        meta = json.loads((root / "codex" / "t2" / "session.json").read_text())
        self.assertTrue(meta["provenance"].startswith("none: authority unreachable"))
        self.assertIsNone(meta["identity_id"])

    def test_prune_removes_only_old_finished_scratch(self):
        root = Path(self.tmp.name) / "capsules"
        for name, ended in (("old", 1000), ("new", 10 ** 10), ("running", None)):
            ws = capsule.make_workspace("codex", name, root)
            (ws / "tmp" / "artifact").write_text("x")
            (ws / "session.json").write_text(json.dumps({"ended_at": ended}))
        self.assertEqual(capsule.prune_old_tmp(root, now=10 ** 9), 1)
        self.assertFalse((root / "codex" / "old" / "tmp").exists())
        self.assertTrue((root / "codex" / "old" / "session.json").exists())
        self.assertTrue((root / "codex" / "new" / "tmp" / "artifact").exists())
        self.assertTrue((root / "codex" / "running" / "tmp" / "artifact").exists())


if __name__ == "__main__":
    unittest.main()
