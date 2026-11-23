"""In-memory images with no file behind them (assemblies.py, memscan.ps1 check 4).

Recognition as JARVIS's own requires every condition at once; each is
removed here in turn and the image must then be reported. The live
validation on 2026-09-28 (isolated fixtures: an assembly declaring injection
APIs, a copied native DLL, a benign Add-Type, an imitation of JARVIS type
names, a partial copy of hidden.ps1) is recorded in
docs/security/DOTNET-ASSEMBLY-DEFENSE.md; these tests pin the same rules.
"""

import hashlib
import json
import unittest
from unittest import mock

from jarvis.collectors.process import assemblies, memscan
from jarvis.core.paths import REPO_ROOT as ROOT
from jarvis.core.paths import load_win_script
from jarvis.response import jev, memory_advice

PS = r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"
LAD = r"C:\Users\chris\AppData\Local"


def own_strings(script, extra=()):
    """A plausible metadata heap for an assembly compiled from `script`."""
    idents = sorted(assemblies._script_facts(script)[0])
    return ["<Module>", "abcd1234.dll", "mscorlib", ".ctor", "get_PidSweep",
            "List`1", "System.Runtime.InteropServices", "kernel32.dll"] \
        + [i for i in idents if i in ("JarvisHidden", "PidSweep", "OpenProcess", "CloseHandle")] \
        + list(extra)


def command_host(pid, script_text, exe=PS, parent=r"C:\Program Files\WSL\wsl.exe"):
    return {"pid": pid, "exe": exe, "launch": "command", "file": "",
            "command_sha256": hashlib.sha256(script_text.encode()).hexdigest(),
            "parent_exe": parent}


def image(strings, managed=True, parsed=True, **kw):
    return dict({"base": 1, "size": 8192, "protect": 4, "exec": False, "private": False,
                 "machine": 332, "managed": managed, "parsed": parsed,
                 "module": "abcd1234.dll", "strings": strings,
                 "strings_total": len(strings)}, **kw)


class RecognitionTests(unittest.TestCase):
    def setUp(self):
        self.hidden = load_win_script("hidden.ps1")

    def verdicts(self, procs, hosts, lad=LAD):
        return [(r["verdict"], assemblies.severity(r))
                for r in assemblies.classify(procs, hosts, lad)]

    def test_reviewed_collector_assembly_is_recognised_and_still_inventoried(self):
        procs = [{"pid": 7, "name": "powershell", "foreign": [image(own_strings("hidden.ps1"))]}]
        rows = assemblies.classify(procs, [command_host(7, self.hidden)], LAD)
        self.assertEqual([r["verdict"] for r in rows], ["recognised"])
        out = assemblies.findings(rows)
        self.assertEqual([f["severity"] for f in out], ["low"])
        self.assertIn("verified as JARVIS's own", out[0]["title"])

    def test_one_foreign_identifier_breaks_recognition(self):
        procs = [{"pid": 7, "name": "powershell",
                  "foreign": [image(own_strings("hidden.ps1", ["DownloadAndRun"]))]}]
        rows = assemblies.classify(procs, [command_host(7, self.hidden)], LAD)
        self.assertEqual(rows[0]["verdict"], "unrecognised")
        self.assertIn("DownloadAndRun", rows[0]["unexplained"])
        self.assertEqual(assemblies.severity(rows[0]), "medium")

    def test_host_must_run_the_reviewed_script_exactly(self):
        procs = [{"pid": 7, "name": "powershell", "foreign": [image(own_strings("hidden.ps1"))]}]
        for host in (command_host(7, self.hidden + "\n# extra"),
                     command_host(7, self.hidden[:-10]),
                     dict(command_host(7, self.hidden), launch="encoded"),
                     dict(command_host(7, self.hidden), exe=r"C:\Users\x\powershell.exe")):
            self.assertEqual(self.verdicts(procs, [host])[0][0], "unrecognised", host)

    def test_count_cannot_exceed_the_scripts_compilations(self):
        compiles = assemblies._script_facts("hidden.ps1")[1]
        self.assertGreaterEqual(compiles, 1)
        imgs = [image(own_strings("hidden.ps1")) for _ in range(compiles + 1)]
        procs = [{"pid": 7, "name": "powershell", "foreign": imgs}]
        verdicts = [v for v, _ in self.verdicts(procs, [command_host(7, self.hidden)])]
        self.assertEqual(verdicts.count("recognised"), compiles)
        self.assertEqual(verdicts.count("unrecognised"), 1)

    def test_template_script_accepts_only_its_launcher_range(self):
        text = load_win_script("window_trace.ps1")
        strings = ["<Module>", "abcd1234.dll", "mscorlib"]
        procs = [{"pid": 9, "name": "powershell", "foreign": [image(strings)]}]
        ok = command_host(9, text.replace("__SECONDS__", "360"))
        bad = command_host(9, text.replace("__SECONDS__", "601"))
        self.assertEqual(self.verdicts(procs, [ok])[0][0], "recognised")
        self.assertEqual(self.verdicts(procs, [bad])[0][0], "unrecognised")

    def test_resident_input_hook_needs_exact_path_and_release_fingerprint(self):
        procs = [{"pid": 5, "name": "powershell",
                  "foreign": [image(["<Module>", "abcd1234.dll", "mscorlib"])]}]
        host = {"pid": 5, "exe": PS, "launch": "file",
                "file": LAD + r"\Jarvis\inputhook.ps1", "parent_exe": r"C:\Windows\System32\conhost.exe"}
        release = assemblies.normalized_text_hash(str(ROOT / "jarvis/platform/win/inputhook.ps1"))
        def installed_hash(path):
            if path.startswith("/mnt/"):
                return release
            with open(path, "rb") as fh:
                return hashlib.sha256(fh.read().replace(b"\r\n", b"\n").rstrip()).hexdigest()
        with mock.patch.object(assemblies, "normalized_text_hash",
                               side_effect=installed_hash):
            self.assertEqual(self.verdicts(procs, [host])[0][0], "recognised")
            moved = dict(host, file=LAD + r"\Temp\inputhook.ps1")
            self.assertEqual(self.verdicts(procs, [moved])[0][0], "unrecognised")
        with mock.patch.object(assemblies, "normalized_text_hash",
                               side_effect=lambda p: "0" * 64 if p.startswith("/mnt/") else "1" * 64):
            self.assertEqual(self.verdicts(procs, [host])[0][0], "unrecognised")

    def test_self_native_and_unparsed(self):
        procs = [{"pid": 1, "name": "powershell", "self": True, "foreign": [image(["X"])]},
                 {"pid": 2, "name": "notepad", "foreign": [image([], managed=False)]},
                 {"pid": 3, "name": "powershell", "foreign": [image([], parsed=False)]}]
        hosts = [{"pid": 3, "exe": PS, "launch": "other"}]
        self.assertEqual(self.verdicts(procs, hosts),
                         [("self", "low"), ("native", "high"), ("unparsed", "medium")])

    def test_non_powershell_host_or_offensive_content_is_high(self):
        strings = ["<Module>", "abcd1234.dll", "Loader", "Run"]
        procs = [{"pid": 4, "name": "notepad", "foreign": [image(strings)]}]
        self.assertEqual(self.verdicts(procs, [{"pid": 4, "exe": r"C:\Windows\notepad.exe"}]),
                         [("unrecognised", "high")])
        for extra in (["VirtualAllocEx"], ["CreateRemoteThread"], ["SetWindowsHookExW"],
                      ["MimikatzLite"], ["ShellcodeRunner"]):
            procs = [{"pid": 7, "name": "powershell", "foreign": [image(strings + extra)]}]
            self.assertEqual(self.verdicts(procs, [{"pid": 7, "exe": PS, "launch": "file"}]),
                             [("unrecognised", "high")], extra)

    def test_tokens_strip_accessors_arity_and_namespaces(self):
        self.assertEqual(assemblies.tokens("get_Length"), ["Length"])
        self.assertEqual(assemblies.tokens("List`1"), ["List"])
        self.assertEqual(assemblies.tokens("System.Runtime.InteropServices"),
                         ["System", "Runtime", "InteropServices"])
        self.assertEqual(assemblies.unexplained(["get_Length"], "m.dll", frozenset({"Length"})), [])
        self.assertEqual(assemblies.unexplained(["get_Length"], "m.dll", frozenset()), ["get_Length"])

    def test_compiler_names_are_language_constructs_only(self):
        for dangerous in ("Load", "Start", "Process", "Assembly", "WebClient",
                          "DownloadData", "VirtualAlloc", "CreateThread", "Marshal"):
            self.assertNotIn(dangerous, assemblies.COMPILER_NAMES)


class AdvisoryTests(unittest.TestCase):
    def row(self, **kw):
        procs = [{"pid": 7, "name": "powershell",
                  "foreign": [image(["<Module>", "abcd1234.dll", "SecretProjectName",
                                     "C:\\Users\\chris\\Documents\\x", "VirtualAllocEx"])]}]
        host = dict({"pid": 7, "exe": PS, "launch": "command",
                     "command_sha256": "f" * 64, "parent_exe": r"C:\Program Files\WSL\wsl.exe"}, **kw)
        return assemblies.classify(procs, [host], LAD)[0]

    def test_features_are_metadata_only(self):
        feats = assemblies.features(self.row())
        blob = json.dumps(feats)
        for private in ("SecretProjectName", "abcd1234", "Documents", "chris", "f" * 64):
            self.assertNotIn(private, blob)
        self.assertEqual(feats["sensitive_native_apis"], ["VirtualAllocEx"])
        self.assertEqual(feats["host_executable"], "powershell.exe")

    def test_jev_state_is_whitelisted_and_bounded(self):
        seen = {}

        def fake(state, questions, timeout):
            seen.update(state=state, timeout=timeout)
            return {"model": "jev", "answers": {"offensive": {"type": "noul", "noul": 0.9}}}
        feats = dict(assemblies.features(self.row()), smuggled="secret")
        with mock.patch.object(jev, "_call", side_effect=fake):
            out = jev.judge_memory_image(feats)
        self.assertTrue(out["advisory_only"])
        self.assertEqual(out["answers"]["offensive_probability"], 0.9)
        self.assertNotIn("smuggled", seen["state"])
        self.assertEqual(seen["timeout"], jev.MEMORY_TIMEOUT_S)

    def test_jev_failure_is_explicit(self):
        with mock.patch.object(jev, "_call", side_effect=jev.JevError("request failed: URLError")):
            out = jev.judge_memory_image(assemblies.features(self.row()))
        self.assertIn("unavailable", out["answers"])
        self.assertIsNone(out["fallback"]["offensive_probability"])

    def test_advice_never_changes_severity_and_is_budgeted(self):
        memory_advice._ADVICE.clear()
        rows = [self.row(), self.row(launch="file"), self.row(parent_exe="a.exe"),
                self.row(parent_exe="b.exe"), self.row(parent_exe="c.exe")]
        calls = []

        def judged(feats):
            calls.append(feats)
            return {"answers": {"offensive_probability": 0.01}, "advisory_only": True}
        with mock.patch.object(jev, "available", return_value=True), \
                mock.patch.object(jev, "judge_memory_image", side_effect=judged):
            out = assemblies.findings(rows, advise=memory_advice.advisor())
        self.assertEqual(len(calls), jev.MEMORY_MAX_CALLS)
        self.assertEqual({f["severity"] for f in out}, {"high"})
        self.assertEqual(sum("0.01 probability" in f["detail"] for f in out), jev.MEMORY_MAX_CALLS)
        self.assertEqual(sum("budget used" in f["detail"] for f in out), 2)

    def test_unavailable_advice_is_not_cached(self):
        memory_advice._ADVICE.clear()
        with mock.patch.object(jev, "available", return_value=True), \
                mock.patch.object(jev, "judge_memory_image",
                                  return_value={"answers": {"unavailable": "x"}}):
            note = memory_advice.advisor()(self.row())
        self.assertIn("unavailable", note)
        self.assertEqual(memory_advice._ADVICE, {})

    def test_no_key_means_no_advisor(self):
        with mock.patch.object(jev, "available", return_value=False):
            self.assertIsNone(memory_advice.advisor())


class ScannerScriptTests(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / "jarvis/platform/win/memscan.ps1").read_text(encoding="utf-8")
        start = self.text.index("public static string Foreign")
        self.foreign = self.text[start:self.text.index("// The syscall stubs")]

    def test_scan_stays_read_only(self):
        for call in ("VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
                     "VirtualProtect", "Assembly.Load", "LoadLibrary"):
            self.assertNotIn(call, self.foreign)
        self.assertIn("PROCESS_QUERY_INFORMATION | PROCESS_VM_READ", self.text)

    def test_file_backed_mappings_and_loader_images_are_excluded(self):
        self.assertIn("mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED", self.foreign)
        self.assertIn("GetMappedFileNameW", self.foreign)
        self.assertIn("MaxImageBytes", self.foreign)

    def test_command_text_never_leaves_the_scanner(self):
        launch = self.text[self.text.index("public static string Launch"):]
        launch = launch[:launch.index("// The syscall stubs")]
        self.assertIn("command_sha256", launch)
        self.assertNotIn('Append(body', launch.replace(" ", ""))
        self.assertNotIn("CommandLine", self.text[self.text.index("$o.hosts"):].split("$o.hosts +=")[1].split("}")[0])


class CollectorIntegrationTests(unittest.TestCase):
    def test_audit_reports_copied_images_beside_existing_checks(self):
        data = {"memory": {"opened": 3, "denied": 0, "procs": [
            {"pid": 7, "name": "powershell", "regions": 0, "foreign": [image(["<Module>", "abcd1234.dll", "Evil"])]},
            {"pid": 8, "name": "notepad", "regions": 0, "foreign": [image([], managed=False, exec=True, private=True)]}]},
                "hosts": [{"pid": 7, "exe": PS, "launch": "encoded"}], "local_app_data": LAD}
        with mock.patch.object(memscan, "_run", return_value=(data, "")):
            out = memscan.audit()
        titles = {f["title"]: f["severity"] for f in out}
        self.assertEqual(titles["powershell holds a .NET assembly with no file behind it"], "medium")
        self.assertEqual(titles["notepad holds a native module with no file behind it"], "high")

    def test_old_scanner_output_without_the_check_still_works(self):
        data = {"memory": {"opened": 1, "denied": 0, "procs": []}}
        with mock.patch.object(memscan, "_run", return_value=(data, "")):
            out = memscan.audit()
        self.assertFalse(any("no file behind it" in f["title"] for f in out))


if __name__ == "__main__":
    unittest.main()
