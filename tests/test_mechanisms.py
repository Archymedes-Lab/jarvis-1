"""The mechanism registry: its views equal the tables they replaced, and its
conformance check catches each way a declaration can break its contract.

tests/data/mechanisms-golden-2026-10-23.json is every per-collector table as it
stood in the checkout before the registry existed (captured by importing the old
modules). Each derived view must reproduce it value for value and, where order
is behaviour, order for order. The only intended difference is `storage`, which
was scheduled but in neither the scored nor the unscored list; it is now
deliberately unscored and maps to the `status` command, like `resources`.
"""

import ast
import dataclasses
import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock

from jarvis.core import governor, mechanisms
from jarvis.response.reporting import score
from jarvis.response.reporting.commands import JOB_COMMANDS
from jarvis.service import jobs, reliability, schedule, scheduler

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = json.loads((ROOT / "tests/data/mechanisms-golden-2026-10-23.json").read_text())
# Collectors declared after the golden capture. Each is reviewed here and must
# still pass every wiring and conformance test below; the equality tests
# compare the views with these taken out, so they still prove the refactor
# changed nothing for the collectors that existed before it.
ADDED_AFTER_GOLDEN = {
    "retention": "event history retention: 30 days whole, then suspicious events only (owner, 2026-11-04)",
    "fwaudit": "HP firmware audit log via the elevated broker (2026-10-23)",
    "netflow": "incoming packet windows from the server packet sensor (ARGUS-SERVER.md W5, 2026-10-24)",
    "logins": "successful SSH logins, new networks and keys (ARGUS-SERVER.md W3, 2026-10-24)",
    "sshwatch": "effective sshd policy, authorised and host key drift, live SSH tunnels (2026-10-28)",
    "opshealth": "failed units, TLS certificate expiry, kernel OOM kills, unclean reboots (2026-10-28)",
    "restarts": "attribution of every jarvis.service stop; unidentified stops are high (2026-11-04)",
    "bootchain": "Linux boot-chain persistence and kernel attack surface (2026-10-29)",
    "keyreaders": "Linux keyboard, raw HID and uinput readers by image; hidden staging (2026-10-29)",
    "friday_defender": "consented Friday Defender reviews of found codebases, advisory (2026-10-29)",
    "pkgverify": "dpkg --verify / rpm -V of intruder-targeted packages (ARGUS-SERVER.md W3, 2026-10-24)",
    "heartbeat": "off-box dead-man ping (ARGUS-SERVER.md W10, 2026-10-25)",
    "patches": "fixable CVEs, pending updates and reboots (ARGUS-SERVER.md W11, 2026-10-25)",
    "wslmanifest": "WSL processes by cgroup owner against an owner-approved manifest (2026-10-31)",
    "updates": "outdated software on every package manager; opt-in bounded auto-update (2026-11-02)",
    "distrovuln": "daily distribution OVAL security data (ARGUS-SERVER.md W11, 2026-10-25)",
    "appcode": "codebases, dependency CVEs, code rules, secrets and web-root leaks (ARGUS-SERVER.md W12, 2026-10-28)",
    "osv": "daily public OSV dumps for the ecosystems found (ARGUS-SERVER.md W12, 2026-10-28)",
    "selfguard": "tamper evidence that survives source disclosure (DETECTION-CONTENT.md, 2026-10-30)",
    "linuxguard": "Linux system integrity: per-install baseline of PAM, sessions, sudo, loader, udev, APT, motd; invariants (2026-11-11)",
    "winblocks": "what Windows Security blocked, explained; flags blocks of Argus's own programs (2026-11-11)",
    "content": "file bytes in drop folders and web roots against compiled community content rules (2026-11-10)",
    "psscript": "PowerShell script blocks (event 4104) checked against community rules; own scripts left out by hash (2026-11-10)",
    "sensorprobe": "positive control of the Linux process sensor, trusted journal origin (2026-11-01)",
    "osquery": "operator-installed osquery as an independent second view (2026-11-02)",
}


# Domains deliberately re-declared after the golden capture: (golden, now, why).
# test_domains checks the golden lists with exactly these moves applied, so any
# other change of domain still fails.
DOMAIN_CHANGED_AFTER_GOLDEN = {
    "netwatch": ("both", "windows", "Wi-Fi and Windows network logs only; failed every "
                                    "run on plain Linux (ARGUS-SERVER.md W1, 2026-10-24)"),
    "wsl": ("both", "windows", "the WSL boundary needs a Windows host; its Linux half "
                               "now runs only on a WSL guest (ARGUS-SERVER.md W1)"),
}


# Golden collectors a release tree may not carry yet (their code ships in its
# own release). The equality tests compare what the tree does carry.
NOT_YET_RELEASED = {"wsl", "canary", "verify"}
ABSENT = set(GOLDEN["order"]) - set(mechanisms.BY_NAME)


def _old(names):
    return [n for n in names if n not in ADDED_AFTER_GOLDEN]


def _here(names):
    return [n for n in names if n not in ABSENT]


ALL = getattr(schedule, "ALL_JOBS", None) or schedule.JOBS


class ViewsEqualTheTablesTheyReplaced(unittest.TestCase):
    def test_only_reviewed_collectors_are_missing_from_this_tree(self):
        self.assertLessEqual(ABSENT, NOT_YET_RELEASED)

    def test_schedule_values_and_order(self):
        self.assertEqual(_old(ALL), _here(GOLDEN["order"]))
        self.assertEqual({k: list(v) for k, v in ALL.items() if k not in ADDED_AFTER_GOLDEN},
                         {k: v for k, v in GOLDEN["all_jobs"].items() if k not in ABSENT})

    def test_domains(self):
        # Trees without the platform seam have no schedule.WINDOWS_ONLY view.
        win = getattr(schedule, "WINDOWS_ONLY", mechanisms.names(domain="windows"))
        lin = getattr(schedule, "LINUX_ONLY", mechanisms.names(domain="linux"))
        golden_win, golden_lin = set(GOLDEN["windows_only"]), set(GOLDEN["linux_only"])
        for name, (was, now, _why) in DOMAIN_CHANGED_AFTER_GOLDEN.items():
            self.assertEqual(mechanisms.BY_NAME[name].domain, now, name)
            for domain, names in (("windows", golden_win), ("linux", golden_lin)):
                if was == domain:
                    names.discard(name)
                if now == domain:
                    names.add(name)
        self.assertEqual(sorted(_old(win)), _here(sorted(golden_win)))
        self.assertEqual(sorted(_old(lin)), _here(sorted(golden_lin)))

    def test_lanes(self):
        # Lanes are only ever tested for membership.
        self.assertEqual(set(_old(scheduler.FAST)), set(_here(GOLDEN["fast"])))
        self.assertEqual(set(_old(scheduler.BULK)), set(_here(GOLDEN["bulk"])))
        self.assertEqual(sorted(_old(scheduler.ISOLATED)), _here(GOLDEN["isolated"]))

    def test_governed(self):
        self.assertEqual(sorted(_old(governor.GOVERNED_JOBS)), _here(GOLDEN["governed"]))

    def test_score_areas_keep_display_order_and_in_area_precedence(self):
        self.assertEqual([[a, _old(m)] for a, m in score.AREAS],
                         [[a, _here(m)] for a, m in GOLDEN["areas"]])

    def test_unscored_adds_only_storage(self):
        self.assertEqual(set(_old(score.UNSCORED)), set(_here(GOLDEN["unscored"])) | {"storage"})

    def test_reliability_budgets(self):
        specs = reliability.build_specs(ALL)
        got = {n: {"interval": s.expected_interval, "timeout": s.execution_timeout,
                   "retries": s.retries, "criticality": s.criticality, "tier": s.tier,
                   "deps": list(s.dependencies)} for n, s in specs.items()
               if n not in ADDED_AFTER_GOLDEN}
        self.assertEqual(got, {k: v for k, v in GOLDEN["specs"].items() if k not in ABSENT})
        self.assertEqual(sorted(_old(reliability.NON_EVIDENCE_JOBS)), _here(GOLDEN["non_evidence"]))

    def test_dependency_roots_and_members(self):
        # Root order is behaviour (ties in the outage root pick the first);
        # members are only tested for membership.
        # The golden file is key-sorted, so the old source order is spelled out.
        self.assertEqual(list(reliability.DEPENDENCIES),
                         ["windows-bridge", "native-sensor", "scheduler"])
        self.assertEqual(set(reliability.DEPENDENCIES), set(GOLDEN["dependencies"]))
        for root, members in GOLDEN["dependencies"].items():
            self.assertEqual(set(_old(reliability.DEPENDENCIES[root])), set(_here(members)), root)

    def test_every_post_golden_collector_is_declared_and_was_not_in_the_golden(self):
        for name in ADDED_AFTER_GOLDEN:
            self.assertIn(name, mechanisms.BY_NAME)
            self.assertNotIn(name, GOLDEN["order"])

    def test_undeclared_names_get_the_generic_interval_rule(self):
        specs = reliability.build_specs({"x": (300, "x"), "y": (3600, "y"), "z": (86400, "z")})
        self.assertEqual([(s.tier, s.criticality, s.execution_timeout) for s in specs.values()],
                         [(2, "medium", 60.0), (3, "medium", 300.0), (4, "low", 300.0)])


class FactsMovedIntoTheRegistry(unittest.TestCase):
    """Second migration (2026-10-23): CLI commands, health sources and elevated
    scripts were three more per-collector tables; each view must equal them."""

    def test_commands(self):
        golden = {k: v for k, v in GOLDEN["job_commands"].items() if k not in ABSENT}
        self.assertEqual({k: v for k, v in JOB_COMMANDS.items() if k not in ADDED_AFTER_GOLDEN
                          and k != "storage"}, golden)
        self.assertEqual(JOB_COMMANDS["storage"], "status")

    def test_health_sources_are_the_old_literals(self):
        # As written in both protection.health and server.py before the move.
        self.assertEqual(mechanisms.health_sources(windows=True),
                         ({"scan": 180, "bridge": 135, "sysmon": 1500, "native": 180},
                          {"internet": 300, "veil": 90, "secrets": 90000, "resources": 900}))
        self.assertEqual(mechanisms.health_sources(windows=False)[0], {"scan": 180})

    @unittest.skipUnless(importlib.util.find_spec("jarvis.platform.broker"), "no broker in this tree")
    def test_broker_scripts(self):
        from jarvis.platform import broker
        golden = dict(GOLDEN["broker_scripts"])
        for name in ADDED_AFTER_GOLDEN:
            if mechanisms.BY_NAME[name].elevated:
                golden[name] = mechanisms.BY_NAME[name].elevated
        # Broker tasks that serve a collector rather than being one, added
        # after the golden snapshot (2026-11-03: the Beep() caller trace,
        # read by the audio collector).
        golden["beeptrace"] = "beeptrace.ps1"
        self.assertEqual(broker.SCRIPTS, golden)

    @unittest.skipUnless(importlib.util.find_spec("jarvis.core.assurance"), "no register")
    def test_assurance_evidence_names_real_sources(self):
        from jarvis.core import assurance
        known = set(mechanisms.BY_NAME) | set(mechanisms.EXTRA_HEALTH_SOURCES)
        for capability, sources in assurance.OBSERVATION_REQUIREMENTS.items():
            self.assertLessEqual(set(sources), known, capability)


class EveryCollectorIsWiredEverywhere(unittest.TestCase):
    def test_runner_for_every_declaration_and_nothing_else(self):
        self.assertEqual(set(jobs.RUNNERS), set(mechanisms.BY_NAME))

    def test_command_for_every_declaration(self):
        self.assertEqual(sorted(set(mechanisms.BY_NAME) - set(JOB_COMMANDS)), [])
        self.assertEqual(JOB_COMMANDS["storage"], "status")

    def test_the_real_declarations_conform(self):
        self.assertEqual(mechanisms.conformance(ROOT), [])


def _with(name, **changes):
    """The registry with one collector's declaration changed."""
    swapped = tuple(dataclasses.replace(c, **changes) if c.name == name else c
                    for c in mechanisms.COLLECTORS)
    return mock.patch.object(mechanisms, "COLLECTORS", swapped)


class ConformanceCatchesBrokenDeclarations(unittest.TestCase):
    def assertBreaks(self, fragment, patcher):
        with patcher:
            problems = mechanisms.conformance(ROOT)
        self.assertTrue(any(fragment in p for p in problems), problems)

    def test_unscored_without_reason(self):
        self.assertBreaks("unscored without a reason", _with("storage", unscored=""))

    def test_scored_with_a_reason_too(self):
        self.assertBreaks("also given an unscored reason", _with("scan", unscored="because"))

    def test_governed_fast_lane(self):
        self.assertBreaks("must never be governed", _with("scan", governed=True))

    def test_governed_tier_zero(self):
        self.assertBreaks("must never be governed", _with("sysmon", governed=True))

    def test_timeout_not_below_interval(self):
        self.assertBreaks("not below interval", _with("hidden", timeout=300.0))

    def test_unknown_lane_domain_area_root(self):
        self.assertBreaks("unknown lane", _with("scan", lane="turbo"))
        self.assertBreaks("unknown domain", _with("scan", domain="mac"))
        self.assertBreaks("unknown area", _with("scan", area="Vibes"))
        self.assertBreaks("unknown dependency root", _with("scan", depends_on=("dns",)))

    def test_budget_bands(self):
        self.assertBreaks("outside the band", _with("secrets", tier=3))
        self.assertBreaks("at most 600s", _with("intel", tier=1, criticality="high"))
        self.assertBreaks("critical means tier 0", _with("hidden", criticality="critical"))
        self.assertBreaks("critical means tier 0", _with("native", criticality="high"))
        self.assertBreaks("over the cap", _with("identity", timeout=200.0))

    def test_command_health_and_elevated_rules(self):
        self.assertBreaks("needs the CLI command", _with("scan", command=""))
        self.assertBreaks("unknown health role", _with("scan", health="sometimes"))
        self.assertBreaks("always read stale", _with("sysmon", health_limit_s=300))
        self.assertBreaks("without a health role", _with("hunt", health_limit_s=60))
        self.assertBreaks("elevated script nowhere.ps1 missing", _with("posture", elevated="nowhere.ps1"))

    def test_area_precedence_must_be_dense(self):
        self.assertBreaks("ranks", _with("deep_hidden", area_rank=4))

    def test_lane_duty_cycle(self):
        self.assertBreaks("measured duty", _with("evidence", cost_s=900.0))

    def test_duplicate_declaration(self):
        dup = mechanisms.COLLECTORS + (mechanisms.BY_NAME["scan"],)
        self.assertBreaks("declared twice", mock.patch.object(mechanisms, "COLLECTORS", dup))

    def test_isolation_outside_fast_lane(self):
        self.assertBreaks("isolation", _with("hidden", isolated=True))

    def test_frequent_lane_contract(self):
        self.assertBreaks("must never be governed", _with("audio", governed=True))
        self.assertBreaks("cadences of at most 300s", _with("audio", interval=600))
        self.assertBreaks("timeout of 90.0s is over 60.0s", _with("audio", timeout=90.0))
        self.assertBreaks("needs a measured cost_s", _with("audio", cost_s=None))
        # A five-minute evidence collector put back on the main lane would
        # wait behind the post-boot sweep again (2026-11-03).
        self.assertBreaks('declare lane="frequent"', _with("audio", lane="main"))

    def test_primitive_pointing_at_missing_code_or_test(self):
        broken = (dataclasses.replace(mechanisms.PRIMITIVES[0],
                                      implemented_by=("jarvis/core/nowhere.py",),
                                      verified_by=("tests/test_nowhere.py",)),)
        with mock.patch.object(mechanisms, "PRIMITIVES", broken):
            problems = mechanisms.conformance(ROOT)
        self.assertIn("primitive collector: implementation jarvis/core/nowhere.py missing", problems)
        self.assertIn("primitive collector: test tests/test_nowhere.py missing", problems)

    def test_primitive_without_invariants(self):
        broken = (dataclasses.replace(mechanisms.PRIMITIVES[0], invariants=()),)
        with mock.patch.object(mechanisms, "PRIMITIVES", broken):
            self.assertTrue(any("all required" in p for p in mechanisms.conformance(ROOT)))

    def test_missing_release_tree_fails_rather_than_passes(self):
        # Pointed at a tree without the code, conformance must report it
        # missing, never return the empty (passing) list.
        self.assertTrue(mechanisms.conformance(ROOT / "no-such-release"))


@unittest.skipUnless(importlib.util.find_spec("jarvis.verify"),
                     "this tree does not ship the verification ladder")
class VerificationLadderCarriesConformance(unittest.TestCase):
    def test_a_broken_declaration_fails_the_whole_report(self):
        from jarvis.verify import report
        with _with("scan", governed=True):
            r = report.run(cases=1)
        self.assertFalse(r["ok"])
        self.assertFalse(r["mechanisms"]["ok"])
        self.assertIn("FAIL V9", report.text(r))

    def test_renamed_package_without_tests_checks_declarations_only(self):
        # The Argus package ships jarvis/ renamed to argus/ and no tests/.
        import importlib.util
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            core = Path(tmp) / "argus" / "core"
            core.mkdir(parents=True)
            shutil.copy(ROOT / "jarvis/core/mechanisms.py", core / "mechanisms.py")
            for p in mechanisms.PRIMITIVES:
                for rel in p.implemented_by:
                    dst = Path(tmp) / (rel.replace("jarvis/", "argus/", 1))
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    dst.touch()
            spec = importlib.util.spec_from_file_location("argus_mech", core / "mechanisms.py")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            self.assertEqual(mod.conformance(files=False), [])
            self.assertTrue(any("test tests/" in p for p in mod.conformance()))
            impl = [p for p in mod.conformance() if "implementation" in p]
            self.assertEqual(impl, [], "jarvis/ paths must resolve inside argus/")
            mod.COLLECTORS = mod.COLLECTORS + (mod.COLLECTORS[0],)
            self.assertTrue(mod.conformance(files=False), "declaration checks still run")


class CatalogueMatchesTheDocument(unittest.TestCase):
    def test_every_primitive_has_a_section(self):
        doc = (ROOT / "docs/architecture/MECHANISMS.md").read_text()
        for p in mechanisms.PRIMITIVES:
            self.assertIn(f"### {p.name}", doc, p.name)


if __name__ == "__main__":
    unittest.main()


# Collections of collector names that are allowed outside the registry, and why.
# Anything else holding three or more collector names is a per-collector fact
# that belongs on the Collector declaration, where conformance can check it.
ALLOWED_NAME_LISTS = {
    "jarvis/service/jobs.py": "RUNNERS: the composition root binds names to functions; core "
                              "cannot import collectors, and a test pins RUNNERS to the registry",
    "jarvis/verify/models/lanes.py": "REQUIRED_FAST is an independent oracle for the lane model; "
                                     "deriving it from the registry would make it check itself",
    "jarvis/core/assurance.py": "OBSERVATION_REQUIREMENTS maps capabilities to evidence sources; "
                                "test_assurance_evidence_names_real_sources checks every name",
    "jarvis/cli/commands/desktop.py": "BROWSER_PAGES are dashboard page names (/coverage, /world, "
                                      "/geo) that share words with jobs, not a list of collectors",
    "jarvis/cli/output.py": "SECTION headings are finding categories that share some words with "
                            "job names, not a list of collectors",
    "jarvis/service/autopilot.py": "MONITORING_CATEGORIES are finding categories (intel, auditd, "
                                   "model upkeep findings) that share names with jobs; deriving "
                                   "them from the registry would turn missing-fix findings into "
                                   "monitoring and stop autopilot investigating them",
}


class TheCodebaseFollowsTheStandard(unittest.TestCase):
    def test_no_new_private_collector_tables(self):
        names = set(mechanisms.BY_NAME)
        found = []
        for path in sorted((ROOT / "jarvis").rglob("*.py")):
            rel = path.relative_to(ROOT).as_posix()
            if "__pycache__" in path.parts or rel == "jarvis/core/mechanisms.py" \
                    or rel in ALLOWED_NAME_LISTS:
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
                    elts = node.elts
                elif isinstance(node, ast.Dict):
                    elts = [k for k in node.keys if k is not None]
                else:
                    continue
                hits = [e.value for e in elts if isinstance(e, ast.Constant) and e.value in names]
                # /api/state's response dict has keys that share words with jobs
                # (internet, intel, posture); it is recognised by its "now" key.
                if len(hits) >= 3 and not (rel == "jarvis/web/server.py" and "now" in
                                           [e.value for e in elts if isinstance(e, ast.Constant)]):
                    found.append(f"{rel}:{node.lineno} {hits[:5]}")
        self.assertEqual(found, [], "declare these on the Collector (core/mechanisms.py) "
                                    "or add the file to ALLOWED_NAME_LISTS with a reason")

    def test_waits_and_timeouts_use_the_monotonic_clock(self):
        # The wall clock on this host steps by ~9 s (WSL clock fight). A wait
        # measured with time.time() gives up early or hangs; on 2026-10-23 that
        # alone failed four tests that looked like flaky product code.
        import re
        wall_wait = re.compile(r"while [^\n]*time\.time\(\)|\bdeadline\s*=\s*time\.time\(\)|"
                               r"lines, deadline = \[\], time\.time\(\)")
        found = []
        for top in ("jarvis", "tests"):
            for path in sorted((ROOT / top).rglob("*.py")):
                for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                    if wall_wait.search(line):
                        found.append(f"{path.relative_to(ROOT)}:{n}")
        self.assertEqual(found, [], "measure waits with time.monotonic()")

    def test_every_allowance_is_still_needed(self):
        for rel in ALLOWED_NAME_LISTS:
            self.assertTrue((ROOT / rel).exists(), rel)
