"""Detector artefacts that looked like threats: empty files and listing races."""

import unittest
from unittest import mock

from jarvis.collectors.host.intrusion import run as intrusion
from jarvis.collectors.process.hidden import windows as hidden


def staged(**item):
    return {"path": r"C:\Users\u\AppData\Local\Temp\x.dll", "sig": "UnknownError",
            "written": "2026-09-15T20:12:05", **item}


class StagedExecutableTests(unittest.TestCase):
    def audit(self, *items):
        with mock.patch.object(intrusion, "ps_json", return_value={"recentExe": list(items)}):
            return [f for f in intrusion.audit() if f["title"] == "recently written unsigned executable"]

    def test_empty_file_in_temp_is_inventory_not_a_threat(self):
        out = self.audit(staged(sha256=intrusion.EMPTY_SHA256.upper()))
        self.assertEqual([f["severity"] for f in out], ["low"])

    def test_powershell_policy_probe_is_inventory_only_with_its_exact_body(self):
        name = r"C:\Users\u\AppData\Local\Temp\__PSScriptPolicyTest_vmpzjz4a.mto.ps1"
        probe = staged(path=name, sig="NotSigned",
                       sha256=intrusion.PS_POLICY_TEST_SHA256.upper())
        self.assertEqual([f["severity"] for f in self.audit(probe)], ["low"])
        # The same name with any other body, or the body under another name,
        # stays a high staged-script finding.
        for item in (dict(probe, sha256="49D3" + "0" * 60),
                     dict(probe, path=r"C:\Users\u\AppData\Local\Temp\run.ps1")):
            self.assertEqual([f["severity"] for f in self.audit(item)], ["high"])

    def test_non_empty_unsigned_file_in_temp_stays_high(self):
        out = self.audit(staged(sha256="49D3" + "0" * 60, sig="NotSigned"))
        self.assertEqual([f["severity"] for f in out], ["high"])


class PackageSourceTests(StagedExecutableTests):
    """Library files an `npm install` unpacked are not unsigned programs."""

    PKG = r"C:\Users\u\AppData\Local\Temp\app\node_modules\left-pad" + "\\"

    def sev(self, name, sig="NotSigned"):
        out = self.audit(staged(path=self.PKG + name, sig=sig, sha256="49D3" + "0" * 60))
        return [f["severity"] for f in out]

    def test_unsigned_package_source_is_listed_but_low(self):
        for name in ("index.js", r"lib\a.mjs", "b.cjs"):
            self.assertEqual(self.sev(name), ["low"], name)

    def test_traversal_out_of_package_tree_stays_high(self):
        self.assertEqual(self.sev(r"..\..\payload.js"), ["high"])

    def test_native_addons_executables_and_bad_signatures_stay_high(self):
        self.assertEqual(self.sev(r"build\x.node"), ["high"])
        self.assertEqual(self.sev(r"bin\tool.exe"), ["high"])
        self.assertEqual(self.sev("index.js", sig="HashMismatch"), ["high"])
        self.assertEqual(self.sev("index.js", sig="NotTrusted"), ["high"])

    def test_the_same_script_outside_node_modules_stays_high(self):
        out = self.audit(staged(path=r"C:\Users\u\AppData\Local\Temp\index.js",
                                sig="NotSigned", sha256="49D3" + "0" * 60))
        self.assertEqual([f["severity"] for f in out], ["high"])


class WmiApiDisagreementTests(unittest.TestCase):
    def audit(self, **extra):
        data = {"wmi": [{"pid": 100, "name": "a"}],
                "api": [{"pid": 100, "name": "a"}, {"pid": 8432, "name": "RuntimeBroker"}],
                "tasklist": [{"pid": 100}, {"pid": 8432}], **extra}
        with mock.patch.object(hidden, "ps_json", return_value=data):
            findings, _ = hidden.audit_windows()
        return [f for f in findings if "not to WMI" in f["title"]]

    def test_process_that_started_between_listings_is_not_reported(self):
        self.assertEqual(self.audit(apiOnly=[]), [])

    def test_disagreement_that_survives_the_requery_is_reported(self):
        out = self.audit(apiOnly=[8432])
        self.assertEqual([f["severity"] for f in out], ["high"])
        self.assertIn("RuntimeBroker", out[0]["detail"])


if __name__ == "__main__":
    unittest.main()


class MemscanRuntimeTests(unittest.TestCase):
    def audit(self, *procs):
        from jarvis.collectors.process import memscan
        data = {"memory": {"opened": len(procs), "denied": 0, "procs": list(procs)}}
        with mock.patch.object(memscan, "_run", return_value=(data, "")):
            return {f["title"].split(" has ")[0]: f for f in memscan.audit()
                    if f["category"] == "injected code" and f["severity"] != "ok"}

    def proc(self, name, pid, runtime=""):
        return {"name": name, "pid": pid, "regions": 2, "bytes": 65536, "rwx": 1,
                "stubs": "", "runtime": runtime}

    def test_loaded_jit_runtime_explains_unbacked_memory(self):
        out = self.audit(self.proc("ProtonVPN.Client", 1, "coreclr.dll"))
        self.assertEqual(out["protonvpn.client"]["severity"], "low")
        self.assertIn("coreclr.dll", out["protonvpn.client"]["detail"])

    def test_rwx_without_a_runtime_stays_high(self):
        self.assertEqual(self.audit(self.proc("ProtonDrive", 2))["protondrive"]["severity"], "high")

    def test_one_process_without_the_runtime_keeps_the_program_flagged(self):
        out = self.audit(self.proc("app", 3, "coreclr.dll"), self.proc("app", 4))
        self.assertEqual(out["app"]["severity"], "high")
