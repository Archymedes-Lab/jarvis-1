"""An elevated result is used only when it is fresh and from reviewed scripts."""

import base64
import json
import os
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from jarvis.cli.commands import broker as broker_cli
from jarvis.core.paths import REPO_ROOT, win_script
from jarvis.platform import broker


class BrokerResultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        os.makedirs(os.path.join(self.tmp, "out"))
        shutil.copy(REPO_ROOT / "jarvis-elevated-broker.ps1", self.tmp)
        for name in broker.SCRIPTS.values():
            shutil.copy(win_script(name), self.tmp)
        for attr, value in (("ROOT", self.tmp), ("OUT", os.path.join(self.tmp, "out"))):
            p = mock.patch.object(broker, attr, value)
            p.start()
            self.addCleanup(p.stop)

    def write(self, ok=True, ts=1000, data=None):
        with open(os.path.join(self.tmp, "out", "status.json"), "w") as fh:
            json.dump({"admin": True, "finished": ts, "jobs": {"memscan": {"ok": ok, "ts": ts, "error": "boom"}}}, fh)
        with open(os.path.join(self.tmp, "out", "memscan.b64"), "w") as fh:
            fh.write(base64.b64encode(json.dumps(data or {"memory": {"opened": 9}}).encode()).decode())

    def test_fresh_reviewed_result_is_used(self):
        self.write()
        self.assertEqual(broker.result("memscan", now=1100)[0], {"memory": {"opened": 9}})

    def test_stale_failed_or_modified_results_are_refused(self):
        self.write()
        self.assertIsNone(broker.result("memscan", now=1000 + broker.MAX_AGE + 1)[0])
        self.write(ok=False)
        self.assertIsNone(broker.result("memscan", now=1100)[0])
        self.write()
        with open(os.path.join(self.tmp, "memscan.ps1"), "a") as fh:
            fh.write("\nStart-Process evil.exe\n")
        data, why = broker.result("memscan", now=1100)
        self.assertIsNone(data)
        self.assertIn("differs", why)

    def test_not_installed(self):
        os.remove(os.path.join(self.tmp, "jarvis-elevated-broker.ps1"))
        self.assertIsNone(broker.result("memscan")[0])

    def test_failed_restage_cannot_pass_because_old_broker_exists(self):
        args = SimpleNamespace(action="install", firewall_logging=False)
        with mock.patch.object(broker_cli, "_elevated",
                               return_value=(1, "staging failed")), \
                mock.patch.object(broker, "installed", return_value=True), \
                mock.patch.object(broker, "drifted", return_value=[]):
            self.assertEqual(broker_cli.cmd_broker(args), 1)

    def test_powershell_commands_are_encoded_for_wsl_interop(self):
        with mock.patch.object(broker_cli.win, "_PS", "powershell.exe"):
            args = broker_cli._ps_args("$x='quoted value'; $x")
        self.assertEqual(args[:3],
                         ["powershell.exe", "-NoProfile", "-NonInteractive"])
        # The script arrives intact, after the progress-silencing preamble.
        self.assertEqual(base64.b64decode(args[-1]).decode("utf-16le"),
                         "$ProgressPreference='SilentlyContinue';$x='quoted value'; $x")
