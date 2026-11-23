import hashlib
import json
import os
import struct
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.host import bootintegrity, tcglog
from jarvis.core import collection
from jarvis.core.store import Store
from jarvis.service.jobs import RUNNERS
from jarvis.service.schedule import JOBS


def variable(name, payload=b"\x01"):
    encoded = name.encode("utf-16-le")
    return bytes(16) + struct.pack("<QQ", len(name), len(payload)) + encoded + payload


def build(events, sha1_too=True):
    """A TCG2 log: Spec ID header, then (pcr, type, body) events."""
    algs = [(0x0004, 20), (0x000B, 32)] if sha1_too else [(0x000B, 32)]
    spec = (b"Spec ID Event03\x00" + struct.pack("<IBBBB", 0, 0, 2, 0, 2)
            + struct.pack("<I", len(algs))
            + b"".join(struct.pack("<HH", a, s) for a, s in algs) + b"\x00")
    out = struct.pack("<II20sI", 0, tcglog.EV_NO_ACTION, bytes(20), len(spec)) + spec
    for pcr, kind, body in events:
        out += struct.pack("<III", pcr, kind, len(algs))
        for alg, _size in algs:
            digest = (hashlib.sha1(body).digest() if alg == 0x0004
                      else hashlib.sha256(body).digest())
            out += struct.pack("<H", alg) + digest
        out += struct.pack("<I", len(body)) + body
    return out


def boot(firmware=b"fw-1", roms=(), apps=(b"bootmgfw",), dbx=b"dbx-1", pk=b"pk-1",
         secure=b"\x01"):
    events = [(0, 0x00000008, firmware), (1, 0x80000002, b"settings")]
    events += [(7, tcglog.EV_EFI_VARIABLE_DRIVER_CONFIG, variable("SecureBoot", secure)),
               (7, tcglog.EV_EFI_VARIABLE_DRIVER_CONFIG, variable("PK", pk)),
               (7, tcglog.EV_EFI_VARIABLE_DRIVER_CONFIG, variable("KEK", b"kek")),
               (7, tcglog.EV_EFI_VARIABLE_DRIVER_CONFIG, variable("db", b"db")),
               (7, tcglog.EV_EFI_VARIABLE_DRIVER_CONFIG, variable("dbx", dbx))]
    events += [(2, tcglog.EV_EFI_BOOT_SERVICES_DRIVER, rom) for rom in roms]
    events += [(4, tcglog.EV_EFI_BOOT_SERVICES_APPLICATION, app) for app in apps]
    events += [(i, tcglog.EV_SEPARATOR, bytes(4)) for i in range(8)]
    return build(events)


def probe(**changes):
    data = {"firmware": {"vendor": "HP", "version": "1.13", "released": "2026-06-22"},
            "secureBoot": {"enabled": 1, "ca2023": "Updated", "dbxError": 0,
                           "dbxErrorReason": ""},
            "tpm": {"TPM Present": "True", "TPM Has Vulnerable Firmware": "False",
                    "Bitlocker PCR7 Binding State": "Bound", "Lockout Counter": "0"},
            "deviceGuard": {"vbs": 2, "running": [1, 2], "codeIntegrity": 2},
            "events": [], "errors": []}
    data.update(changes)
    return data


def event(event_id, values, source="Kernel-Boot", when="2026-10-01T10:00:00.0000000Z"):
    return {"id": event_id, "source": source, "time": when, "values": values}


class TcgLogTests(unittest.TestCase):
    def test_replay_matches_manual_extend_and_skips_no_action(self):
        log = build([(0, 0x8, b"a"), (0, tcglog.EV_NO_ACTION, b"ignored"), (0, 0x8, b"b")])
        pcr = bytes(32)
        for body in (b"a", b"b"):
            pcr = hashlib.sha256(pcr + hashlib.sha256(body).digest()).digest()
        self.assertEqual(tcglog.replay(tcglog.parse(log))[0], pcr.hex())

    def test_summary_names_variables_roms_and_boot_apps(self):
        summary = tcglog.summary(boot(roms=(b"rom",)))
        self.assertEqual(set(summary["variables"]), {"SecureBoot", "PK", "KEK", "db", "dbx"})
        self.assertEqual(len(summary["option_roms"]), 1)
        self.assertEqual(len(summary["boot_apps"]), 1)
        self.assertEqual(set(summary["pcrs"]), {str(i) for i in range(8)})

    def test_single_bank_log_parses(self):
        self.assertEqual(len(tcglog.parse(build([(0, 0x8, b"a")], sha1_too=False))), 1)

    def test_truncated_garbage_and_oversize_are_refused(self):
        good = boot()
        for bad in (good[:-5], good[:40], b"", b"\x00" * 64, good[:32] + b"X" * 40,
                    b"\x00" * (tcglog.MAX_LOG_BYTES + 1), None):
            with self.subTest(size=len(bad or b"")), self.assertRaises(tcglog.LogError):
                tcglog.parse(bad)

    def test_undeclared_algorithm_and_bad_pcr_are_refused(self):
        log = bytearray(build([(0, 0x8, b"a")]))
        header = 32 + struct.unpack_from("<I", log, 28)[0]
        struct.pack_into("<I", log, header, 99)           # pcr index out of range
        with self.assertRaises(tcglog.LogError):
            tcglog.parse(bytes(log))


class BootIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.logs = os.path.join(self.tmp.name, "MeasuredBoot")
        os.mkdir(self.logs)
        self.store = Store(os.path.join(self.tmp.name, "test.db"))
        self.addCleanup(self.store.close)
        self.write_attestation()

    def write_log(self, number, data, resume=0):
        with open(os.path.join(self.logs, f"{number:010d}-{resume:010d}.log"), "wb") as fh:
            fh.write(data)

    def write_attestation(self, health="Attestable", match=True, number=99):
        body = {"Version": 2, "HealthStatus": health,
                "Expected": [{"Field": "PcrsMatchTcgLog", "Value": match}]}
        with open(os.path.join(self.logs, f"{number:010d}-0000000000.json"), "wb") as fh:
            fh.write(json.dumps(body).encode("utf-16"))

    def run_audit(self, data=None):
        with mock.patch.object(bootintegrity, "ps_json",
                               return_value=probe() if data is None else data):
            with collection.observe() as observation:
                findings = bootintegrity.audit(self.store, hosts=("win",),
                                               directory=self.logs)
        return observation, findings

    def titles(self, findings):
        return [f["title"] for f in findings]

    def test_registered_unscored_with_bounded_schedule(self):
        from jarvis.response.reporting import score
        self.assertIn("preos", RUNNERS)
        self.assertEqual(JOBS["preos"][0], 1800)
        self.assertIn("preos", score.UNSCORED)

    def test_identical_boots_are_clean_and_complete(self):
        for number in (1, 2, 3):
            self.write_log(number, boot())
        self.write_log(3, boot(), resume=1)
        observation, findings = self.run_audit()
        self.assertEqual(observation.status, "complete")
        self.assertEqual([f["severity"] for f in findings], ["ok"])
        self.assertIn("3 cold boot(s) and 1 resume(s)", findings[0]["detail"])
        self.assertIn("POST beep itself", findings[0]["detail"])

    def test_first_run_compares_retained_history_against_oldest_boot(self):
        self.write_log(1, boot())
        self.write_log(2, boot(roms=(b"evil-rom",)))
        _obs, findings = self.run_audit()
        rom = [f for f in findings if "option ROM" in f["title"]]
        self.assertEqual(len(rom), 1)
        self.assertEqual(rom[0]["severity"], "high")
        self.assertIn("boot 2", rom[0]["detail"])

    def test_drift_persists_until_owner_accepts_a_new_baseline(self):
        self.write_log(1, boot())
        self.run_audit()
        self.write_log(2, boot(apps=(b"bootmgfw", b"bootkit")))
        for _ in range(2):          # the baseline must not advance by itself
            _obs, findings = self.run_audit()
            self.assertIn("a boot application not in the baseline ran", self.titles(findings))
        self.assertEqual(bootintegrity.load_baseline(self.store)["boot"], 1)
        accepted = bootintegrity.accept_baseline(
            self.store, bootintegrity.read_logs(self.logs), probe()["firmware"])
        self.assertEqual(accepted["boot"], 2)
        _obs, findings = self.run_audit()
        self.assertEqual([f["severity"] for f in findings], ["ok"])

    def test_severity_of_each_measured_difference(self):
        cases = ((dict(pk=b"pk-2"), "Secure Boot variable PK changed", "high"),
                 (dict(secure=b"\x00"), "Secure Boot variable SecureBoot changed", "high"),
                 (dict(dbx=b"dbx-2"), "Secure Boot variable dbx changed", "medium"),
                 (dict(firmware=b"fw-2"), "firmware code measured differently (PCR 0)", "high"))
        base = tcglog.summary(boot())
        for change, title, severity in cases:
            with self.subTest(title=title):
                current = tcglog.summary(boot(**change))
                found = bootintegrity.drift(
                    bootintegrity._state(base, {"version": "1"}),
                    bootintegrity._state(current, {"version": "1"}), "boot 2")
                match = [f for f in found if f["title"] == title]
                self.assertEqual([f["severity"] for f in match], [severity])

    def test_firmware_update_explains_pcr0_and_unknown_version_claims_nothing(self):
        base, new = tcglog.summary(boot()), tcglog.summary(boot(firmware=b"fw-2"))
        updated = bootintegrity.drift(bootintegrity._state(base, {"version": "1"}),
                                      bootintegrity._state(new, {"version": "2"}), "boot 2")
        self.assertEqual(updated[0]["severity"], "medium")
        self.assertIn("firmware update explains", updated[0]["detail"])
        unknown = bootintegrity.drift(bootintegrity._state(base, {"version": "1"}),
                                      bootintegrity._state(new, None), "boot 2")
        self.assertEqual(unknown[0]["severity"], "high")
        self.assertIn("is not known", unknown[0]["detail"])

    def test_repeated_difference_is_one_finding_anchored_at_first_boot(self):
        self.write_log(1, boot())
        for number in (2, 3, 4):
            self.write_log(number, boot(roms=(b"rom",)))
        _obs, findings = self.run_audit()
        rom = [f for f in findings if "option ROM" in f["title"]]
        self.assertEqual(len(rom), 1)
        self.assertIn("boot 2", rom[0]["detail"])
        self.assertIn("also in 2 later boot(s)", rom[0]["detail"])

    def test_unparsed_log_missing_logs_and_bad_probe_are_not_clean(self):
        self.write_log(1, boot())
        self.write_log(2, boot()[:100])
        observation, findings = self.run_audit()
        self.assertNotEqual(observation.status, "complete")
        self.assertIn("a measured-boot log could not be parsed", self.titles(findings))
        os.remove(os.path.join(self.logs, "0000000002-0000000000.log"))
        for bad in (None, {"events": "x"}, probe(errors=["tpm: Win32Exception"]),
                    probe(events=[event(27, ["0"] * 9)])):
            with self.subTest(bad=str(bad)[:40]):
                observation, findings = self.run_audit(bad if bad is not None else {})
                self.assertNotEqual(observation.status, "complete")
                self.assertIn("pre-OS boot evidence is incomplete", self.titles(findings))
        os.remove(os.path.join(self.logs, "0000000001-0000000000.log"))
        observation, findings = self.run_audit()
        self.assertNotEqual(observation.status, "complete")
        self.assertNotIn("ok", [f["severity"] for f in findings])

    def test_bad_probe_on_first_run_pins_no_baseline(self):
        self.write_log(1, boot())
        self.run_audit({})
        self.assertIsNone(bootintegrity.load_baseline(self.store))

    def test_attestation_mismatch_is_high_and_missing_verdict_is_incomplete(self):
        self.write_log(1, boot())
        self.write_attestation(match=False)
        _obs, findings = self.run_audit()
        self.assertIn("the TPM does not match the measured-boot log", self.titles(findings))
        os.remove(os.path.join(self.logs, "0000000099-0000000000.json"))
        observation, _findings = self.run_audit()
        self.assertNotEqual(observation.status, "complete")

    def test_stale_log_for_the_current_boot_is_visibility_loss(self):
        self.write_log(1, boot())
        old = 1_700_000_000
        os.utime(os.path.join(self.logs, "0000000001-0000000000.log"), (old, old))
        os.utime(os.path.join(self.logs, "0000000099-0000000000.json"), (old, old))
        data = probe(events=[event(12, ["10"], "Kernel-General", "2026-10-01T10:00:00.0Z")])
        observation, findings = self.run_audit(data)
        self.assertNotEqual(observation.status, "complete")
        self.assertIn("the current boot left no measured-boot log", self.titles(findings))

    def test_boot_events_dangerous_options_menu_wait_and_extra_entries(self):
        self.write_log(1, boot())
        data = probe(events=[
            event(27, ["0", " NOEXECUTE=OPTIN  TESTSIGNING  NOVGA"]),
            event(27, ["0", " NOEXECUTE=OPTIN  NOVGA"]),
            event(32, ["4200"]), event(32, ["0"]), event(18, ["2"]),
            event(41, ["0"], "Kernel-Power")])
        _obs, findings = self.run_audit(data)
        by_title = {f["title"]: f for f in findings}
        self.assertEqual(by_title["Windows booted with a protection turned off"]["severity"], "high")
        self.assertIn("TESTSIGNING", by_title["Windows booted with a protection turned off"]["detail"])
        self.assertIn("4200 ms", by_title["the boot manager waited for someone at the keyboard"]["detail"])
        self.assertIn("more than one boot entry is configured", by_title)
        self.assertIn("unclean shutdowns before recent boots", by_title)

    def test_safe_boot_options_raise_nothing(self):
        self.write_log(1, boot())
        data = probe(events=[event(27, ["0", " NOEXECUTE=OPTIN  HYPERVISORLAUNCHTYPE=AUTO  NOVGA"]),
                             event(32, ["0"]), event(18, ["1"])])
        _obs, findings = self.run_audit(data)
        self.assertEqual([f["severity"] for f in findings], ["ok"])

    def test_platform_state_findings(self):
        self.write_log(1, boot())
        data = probe(secureBoot={"enabled": 0, "dbxError": 2147946825, "dbxErrorReason": "InstallerError"},
                     tpm={"TPM Present": "True", "TPM Has Vulnerable Firmware": "True",
                          "Lockout Counter": "3", "Bitlocker PCR7 Binding State": "Binding Not Possible"},
                     deviceGuard={"vbs": 0, "running": [], "codeIntegrity": 0})
        _obs, findings = self.run_audit(data)
        titles = self.titles(findings)
        for title in ("Secure Boot is not enabled",
                      "the Secure Boot revocation list failed to update",
                      "the TPM firmware is reported vulnerable",
                      "the TPM recorded failed authorisation attempts",
                      "disk encryption is not bound to Secure Boot state",
                      "virtualization-based security is not running"):
            self.assertIn(title, titles)
        self.assertIn("0x80071149", " ".join(f["detail"] for f in findings))

    def test_boot_counter_gap_is_reported_low(self):
        self.write_log(1, boot())
        self.write_log(4, boot())
        _obs, findings = self.run_audit()
        gap = [f for f in findings if "boot counter gap" in f["title"]]
        self.assertEqual([f["severity"] for f in gap], ["low"])

    # Bug check 0x20001 as Windows recorded it on this host 2026-10-30.
    KP41 = ["131073", "17", "3836698", "4103"]
    WER = ["0x00020001 (0x0000000000000011, 0x00000000003a8b1a, 0x0000000000001007, "
           "0xffffe80000c4af00)", "C:\\WINDOWS\\Minidump\\103026-21578-01.dmp",
           "a42c40a3-0b69-48fb-a98a-c7b6423b03ef"]

    def stops(self, events):
        self.write_log(1, boot())
        _obs, findings = self.run_audit(probe(events=events))
        return [f for f in findings if f["title"] in bootintegrity.BUGCHECK_TITLE.values()]

    def test_hypervisor_crash_is_one_finding_with_code_parameters_and_dump(self):
        found = self.stops([
            event(41, self.KP41, "Kernel-Power", "2026-10-30T18:16:51.2Z"),
            event(1001, self.WER, "WER-SystemErrorReporting", "2026-10-30T18:17:06.9Z")])
        self.assertEqual([(f["title"], f["severity"]) for f in found],
                         [("the hypervisor under Windows crashed", "medium")])
        detail = found[0]["detail"]
        for part in ("1 stop error(s)", "0x20001 HYPERVISOR_ERROR", "0x0000000000000011",
                     "103026-21578-01.dmp", "not a compromise verdict"):
            self.assertIn(part, detail)

    def test_repeated_hypervisor_crashes_escalate(self):
        found = self.stops([
            event(1001, self.WER, "WER-SystemErrorReporting", "2026-10-30T18:17:06Z"),
            event(41, self.KP41, "Kernel-Power", "2026-10-28T09:00:00Z")])
        self.assertEqual([f["severity"] for f in found], ["high"])
        self.assertIn("2 stop error(s)", found[0]["detail"])   # far apart: never merged

    def test_boot_loop_of_identical_crashes_is_never_folded(self):
        # Crash 1 left no WER record; crash 2, minutes later, did. Two crashes.
        found = self.stops([
            event(41, self.KP41, "Kernel-Power", "2026-10-30T18:10:00Z"),
            event(41, self.KP41, "Kernel-Power", "2026-10-30T18:13:00Z"),
            event(1001, self.WER, "WER-SystemErrorReporting", "2026-10-30T18:13:15Z")])
        self.assertIn("2 stop error(s)", found[0]["detail"])
        self.assertEqual(len(bootintegrity.crashes([
            event(41, self.KP41, "Kernel-Power", "2026-10-30T18:13:00Z"),
            event(1001, self.WER, "WER-SystemErrorReporting", "2026-10-30T18:13:15Z"),
            event(1001, self.WER, "WER-SystemErrorReporting", "2026-10-30T18:14:00Z")])), 2)

    def test_kernel_integrity_violation_is_high_even_once(self):
        found = self.stops([event(41, [str(0x109), "0"], "Kernel-Power")])
        self.assertEqual([(f["title"], f["severity"]) for f in found],
                         [("Windows stopped because protected kernel code or data changed", "high")])
        self.assertIn("no dump recorded", found[0]["detail"])

    def test_unknown_code_is_named_by_number_and_low(self):
        found = self.stops([event(41, [str(0xABC)], "Kernel-Power")])
        self.assertEqual([(f["severity"], "0xABC" in f["detail"]) for f in found], [("low", True)])

    def test_malformed_zero_and_foreign_records_raise_no_stop_error(self):
        found = self.stops([
            event(41, ["0"], "Kernel-Power"), event(41, ["-5"], "Kernel-Power"),
            event(41, ["garbage"], "Kernel-Power"), event(41, [], "Kernel-Power"),
            event(41, [str(2 ** 40)], "Kernel-Power"),
            event(1001, ["nonsense"], "WER-SystemErrorReporting"),
            event(1001, ["0x00020001 (0x1, 0x2, 0x3, 0x4, 0x5)"], "WER-SystemErrorReporting"),
            event(1001, self.WER, "Kernel-Boot")])
        self.assertEqual(found, [])

    def test_probe_reads_stop_error_records(self):
        self.assertIn("Microsoft-Windows-WER-SystemErrorReporting'; ids=@(1001)",
                      bootintegrity.PS_BOOT)

    def test_disabled_windows_is_visibility_loss(self):
        with collection.observe() as observation:
            findings = bootintegrity.audit(self.store, hosts=("wsl",))
        self.assertEqual(observation.status, "unavailable")
        self.assertEqual(findings[0]["category"], "visibility")


if __name__ == "__main__":
    unittest.main()
