import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.collectors.telemetry import evidence, sysmon_policy
from jarvis.core import event
from jarvis.core.eventlog import EventLog
from jarvis.core.paths import win_script
from jarvis.core.store import Store
from jarvis.platform import timestamps

POLICY = {"config_hash": "a" * 64}


def ev(record):
    return event.make(
        host="WINBOX", sensor="sensor", device="device", boot="b", channel="c",
        generation="g", record=record, source="sysmon", source_event=1,
        time="2026-09-23T10:00:00Z", received="2026-09-23T10:00:01Z",
        category="process", action="start",
        process={"pid": record, "guid": f"{{g{record}}}", "image": r"C:\x.exe"})


def calendar_response(digest):
    """A well-formed pending commitment, as a calendar returns it."""
    return (bytes([timestamps.OP_APPEND]) + timestamps._varbytes(b"\x01" * 16)
            + bytes([timestamps.OP_SHA256]) + b"\x00" + timestamps.PENDING
            + timestamps._varbytes(timestamps._varbytes(
                b"https://alice.btc.calendar.opentimestamps.org")))


def fake_fetch(url, data=None, accept=None):
    if url.endswith("/digest"):
        return 200, calendar_response(data)
    return 404, b""


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.logdir = self.tmp / "eventlog"
        self.inbox = self.tmp / "inbox"
        self.vault = self.tmp / "vault"
        self.anchors = self.tmp / "anchors"
        self.store = Store(str(self.tmp / "state.db"))
        self.addCleanup(self.store.close)
        self.log = EventLog(self.logdir, writer=True)
        self.addCleanup(self.log.close)
        self.drive = mock.patch.object(evidence, "WINDOWS_DRIVE", str(self.tmp))
        self.drive.start()
        self.addCleanup(self.drive.stop)
        # No test reaches a real calendar or block explorer.
        network = mock.patch.object(timestamps, "_fetch", fake_fetch)
        network.start()
        self.addCleanup(network.stop)

    def seal(self, first, last):
        self.log.append([ev(n) for n in range(first, last + 1)],
                        {"sensor": "sensor", "channel": "c"})
        return self.log.seal(force=True)

    def vault_job(self):
        """What the elevated vault job does, for the Python side of the test."""
        src, dst = self.inbox / "eventlog", self.vault / "eventlog"
        (dst / "segments").mkdir(parents=True, exist_ok=True)
        vaulted = (dst / "chain.jsonl").read_bytes() if (dst / "chain.jsonl").exists() else b""
        staged = (src / "chain.jsonl").read_bytes()
        self.assertTrue(staged.startswith(vaulted))
        for line in staged[len(vaulted):].splitlines(keepends=True):
            name = evidence._name(json.loads(line)["segment"])
            if (src / "segments" / name).exists():
                shutil.copyfile(src / "segments" / name, dst / "segments" / name)
            with open(dst / "chain.jsonl", "ab") as fh:
                fh.write(line)
        (self.vault / "anchors").mkdir(exist_ok=True)
        for record in (self.inbox / "anchors").glob("*"):
            if not (self.vault / "anchors" / record.name).exists():
                shutil.copyfile(record, self.vault / "anchors" / record.name)
        head = json.loads(staged.splitlines()[-1])
        return ({"ok": True, "head_segment": head["segment"], "head_hash": head["hash"]}, "")

    def run_job(self, vault_job=(None, "not installed"), policy=POLICY, now=None):
        return evidence.audit(self.store, root=self.logdir, inbox=self.inbox,
                              vault=self.vault, anchors=self.anchors, policy=policy,
                              vault_job=vault_job, now=now,
                              network=True)


class VaultTests(Base):
    def test_staging_then_vaulting_verifies_cleanly_and_cleans_the_inbox(self):
        self.seal(1, 3)
        self.seal(4, 5)
        self.run_job()
        self.assertEqual(len(list((self.inbox / "eventlog" / "segments").glob("*.jseg"))), 2)
        job = self.vault_job()
        with mock.patch.object(sysmon_policy, "baseline_sha256", return_value="a" * 64):
            findings = self.run_job(vault_job=job)
        self.assertEqual(findings, [])
        state = evidence.summary(self.store)
        self.assertEqual((state["vaulted"], state["verified_through"]), (2, 2))
        self.run_job(vault_job=job)
        self.assertEqual(list((self.inbox / "eventlog" / "segments").glob("*.jseg")), [])

    def test_rewritten_live_history_is_critical(self):
        self.seal(1, 2)
        self.run_job()
        job = self.vault_job()
        chain = self.logdir / "chain.jsonl"
        chain.write_text(chain.read_text().replace('"count":2', '"count":3'))
        self.log.close()
        titles = {f["title"]: f["severity"] for f in self.run_job(vault_job=job)}
        self.assertEqual(titles["Event history differs from its vaulted copy"], "critical")

    def test_altered_vault_payload_is_reported(self):
        self.seal(1, 2)
        self.run_job()
        job = self.vault_job()
        seg = next((self.vault / "eventlog" / "segments").glob("*.jseg"))
        seg.write_bytes(seg.read_bytes()[:-5] + b"xxxxx")
        titles = [f["title"] for f in self.run_job(vault_job=job)]
        self.assertIn("Evidence vault contents do not verify", titles)

    def test_rolling_recheck_catches_an_old_payload_altered_after_it_was_verified(self):
        for first in range(1, 13, 2):
            self.seal(first, first + 1)                 # six sealed segments
        self.run_job(now=1_000_000)
        job = self.vault_job()
        self.run_job(vault_job=job, now=1_000_100)      # first run hashes all six
        self.assertEqual(evidence.summary(self.store)["verified_through"], 6)
        seg = self.vault / "eventlog" / "segments" / evidence._name(2)
        seg.write_bytes(seg.read_bytes()[:-5] + b"xxxxx")   # altered after verification
        caught_at = None
        for i in range(1, 97):                          # one day of 15-minute runs
            titles = [f["title"] for f in self.run_job(vault_job=job, now=1_000_100 + i * 900)]
            if "Evidence vault contents do not verify" in titles:
                caught_at = i
                break
        self.assertIsNotNone(caught_at, "an altered vaulted payload must be found within a day")
        self.assertLess(caught_at * 900, evidence.FULL_VERIFY_EVERY)

    def test_forged_pruned_claim_is_reported(self):
        self.seal(1, 2)
        self.run_job()
        job = self.vault_job()
        (self.vault / "eventlog" / "unvaulted.txt").write_text(
            "000000000001.jseg removed by retention before it was vaulted\n")
        result = evidence.verify_vault(list(self.log.chain), self.vault, full=True, pruned=set())
        self.assertTrue(any("never recorded pruning" in p for p in result["problems"]))
        self.assertTrue(job[0]["ok"])

    def test_vault_job_divergence_and_absence_are_findings(self):
        self.seal(1, 1)
        findings = {f["title"]: f["severity"] for f in self.run_job(
            vault_job=({"ok": True, "diverged": True, "divergence": "x"}, ""))}
        self.assertEqual(findings["Event history no longer extends its vaulted copy"], "critical")
        findings = {f["title"]: f["severity"] for f in self.run_job()}
        self.assertEqual(findings["Evidence vault job is not running"], "low")


class DriftTests(Base):
    def test_running_config_that_differs_from_the_baseline_is_high(self):
        self.seal(1, 1)
        with mock.patch.object(sysmon_policy, "baseline_sha256", return_value="b" * 64):
            findings = {f["title"]: f["severity"] for f in self.run_job()}
        self.assertEqual(findings["Sysmon is not running the reviewed baseline"], "high")

    def test_unknown_running_config_is_not_called_drift(self):
        self.assertEqual(sysmon_policy.drift({}, "b" * 64), "unknown")
        self.assertEqual(sysmon_policy.config_hash(
            " - Config hash:                   SHA256=" + "C" * 64), "c" * 64)

    def test_baseline_hash_is_the_file_bytes(self):
        path = sysmon_policy.repo_file(sysmon_policy.BASELINE)
        self.assertEqual(sysmon_policy.baseline_sha256(),
                         hashlib.sha256(Path(path).read_bytes()).hexdigest())


class AnchorTests(Base):
    def test_first_run_anchors_and_later_runs_wait_for_the_interval(self):
        self.seal(1, 1)
        self.run_job(now=1_000_000)
        records = list(self.anchors.glob("*.json"))
        self.assertEqual(len(records), 1)
        body = records[0].read_bytes()
        self.assertEqual(hashlib.sha256(body).hexdigest(), records[0].stem)
        digest, _node = timestamps.parse_file((self.anchors / (records[0].stem + ".ots")).read_bytes())
        self.assertEqual(digest.hex(), records[0].stem)
        self.seal(2, 2)
        self.run_job(now=1_000_000 + 60)
        self.assertEqual(len(list(self.anchors.glob("*.json"))), 1)
        self.run_job(now=1_000_000 + evidence.ANCHOR_EVERY + 1)
        self.assertEqual(len(list(self.anchors.glob("*.json"))), 2)

    def test_history_rewritten_after_anchoring_is_critical(self):
        self.seal(1, 1)
        self.run_job(now=1_000_000)
        record = next(self.anchors.glob("*.json"))
        data = json.loads(record.read_bytes())
        data["eventlog"]["hash"] = "f" * 64          # the history it named is gone
        body = evidence._canonical(data).encode()
        (self.anchors / f"{hashlib.sha256(body).hexdigest()}.json").write_bytes(body)
        findings = {f["title"]: f["severity"] for f in self.run_job(now=1_000_100)}
        self.assertEqual(findings["Event history was rewritten after it was anchored"], "critical")

    def test_an_edited_anchor_record_is_reported(self):
        self.seal(1, 1)
        self.run_job(now=1_000_000)
        record = next(self.anchors.glob("*.json"))
        os.chmod(record, 0o600)
        record.write_bytes(record.read_bytes().replace(b'"v":1', b'"v":2'))
        titles = [f["title"] for f in self.run_job(now=1_000_100)]
        self.assertIn("Anchor records were altered", titles)

    def test_bitcoin_proof_is_checked_against_the_block(self):
        digest = b"\x07" * 32
        node = timestamps._node(digest)
        node["att"].append((timestamps.BITCOIN, timestamps._varuint(812345)))
        self.anchors.mkdir()
        (self.anchors / f"{digest.hex()}.ots").write_bytes(timestamps.serialize_file(digest, node))
        records = {digest.hex(): {"at": 0}}
        confirmed, pending, bad = evidence.upgrade_proofs(
            self.anchors, records, now=10, verify=lambda h, m: False)
        self.assertEqual((bad[0]["height"], confirmed, pending), (812345, [], []))
        confirmed, _p, bad = evidence.upgrade_proofs(
            self.anchors, records, now=10, verify=lambda h, m: True)
        self.assertEqual((confirmed[0]["checked"], bad), (True, []))


class ProofFormatTests(unittest.TestCase):
    def test_submit_needs_two_calendars_and_round_trips(self):
        digest = hashlib.sha256(b"x").digest()
        data, accepted = timestamps.submit(digest, fetch=fake_fetch)
        self.assertEqual(len(accepted), len(timestamps.CALENDARS))
        got, node = timestamps.parse_file(data)
        self.assertEqual(timestamps.serialize_file(got, node), data)
        one = iter([(200, calendar_response(digest))] + [(None, b"")] * 10)
        with self.assertRaises(timestamps.ProofError):
            timestamps.submit(digest, fetch=lambda *a, **k: next(one))

    def test_upgrade_only_asks_allowlisted_calendars(self):
        digest = b"\x01" * 32
        node = timestamps._node(digest)
        node["att"].append((timestamps.PENDING, timestamps._varbytes(b"https://evil.example")))
        asked = []
        timestamps.upgrade(timestamps.serialize_file(digest, node),
                           fetch=lambda url, **k: (asked.append(url), (404, b""))[1])
        self.assertEqual(asked, [])

    def test_malformed_proofs_are_rejected(self):
        for data in (b"", timestamps.MAGIC, timestamps.MAGIC + b"\x01\x08" + b"\x00" * 31):
            with self.assertRaises(timestamps.ProofError):
                timestamps.parse_file(data)


class VaultScriptTests(unittest.TestCase):
    SCRIPT = win_script("vault.ps1").read_text(encoding="utf-8")

    def test_the_vault_never_replaces_or_deletes(self):
        code = "\n".join(l for l in self.SCRIPT.splitlines() if not l.lstrip().startswith("#"))
        self.assertIn("[IO.File]::Move($temp, $target)", code)
        self.assertNotIn("Remove-Item -LiteralPath $target", code)
        self.assertNotIn("-Force -Destination $target", code)
        self.assertNotIn("Copy-Item -LiteralPath $source -Destination $target", code)

    def test_prefix_rule_and_owner_only_read(self):
        self.assertIn("staged chain does not extend the vaulted chain", self.SCRIPT)
        # Readable only by the user recorded at install (the job runs as
        # SYSTEM), whose inbox is found through the profile list, not %LOCALAPPDATA%.
        self.assertIn("@($UserSid, 'ReadAndExecute')", self.SCRIPT)
        self.assertNotIn("S-1-5-32-545", self.SCRIPT)       # BUILTIN\\Users
        self.assertIn("Join-Path $UserLocal 'Jarvis\\VaultInbox'", self.SCRIPT)
        self.assertNotIn("$env:LOCALAPPDATA", self.SCRIPT)


if __name__ == "__main__":
    unittest.main()


class RecheckSliceTests(unittest.TestCase):
    def test_a_day_of_runs_covers_every_segment(self):
        seen, cursor = set(), 1
        for _ in range(96):
            picks, cursor = evidence.recheck_slice(2997, cursor, 900)
            seen.update(picks)
        self.assertEqual(seen, set(range(1, 2998)))

    def test_a_long_absence_takes_a_bigger_bounded_slice(self):
        picks, _ = evidence.recheck_slice(2997, 1, 8 * 3600)
        self.assertEqual(len(picks), min(999, evidence.MAX_RECHECK))
        self.assertEqual(len(evidence.recheck_slice(10, 9, 10 * 86400)[0]), 10)
        self.assertEqual(evidence.recheck_slice(0, 1, 900), ([], 1))
        picks, nxt = evidence.recheck_slice(10, 9, 3 * 86400 / 10)
        self.assertEqual((picks, nxt), ([9, 10, 1], 2))
