"""Model availability must be a known state, not a surprise.

ping() is a cheap GET, never a generation, and refuses any non-loopback
endpoint by policy. status_findings() reports the result as visibility —
never above "low", because the model is colour, not detection.
"""

import os
import tempfile
import unittest
from unittest import mock

from jarvis.core.store import Store
from jarvis.response import llm


class PingTests(unittest.TestCase):
    def test_loopback_get_no_generation(self):
        with mock.patch.object(llm, "_open") as opener:
            opener.return_value.__enter__.return_value.read.return_value = \
                b'{"models":[{"name":"llama3.2:3b"}]}'
            state, _seconds = llm.ping({})
        self.assertEqual(state, "model_loaded")
        request = opener.call_args[0][0]
        self.assertTrue(request.full_url.startswith("http://127.0.0.1:11434/api/tags"))

    def test_non_loopback_is_refused_by_policy(self):
        state, _ = llm.ping({"ollama_url": "http://10.0.0.5:11434"})
        self.assertEqual(state, "misconfigured")

    def test_connection_error_is_offline_not_an_exception(self):
        import urllib.error
        with mock.patch.object(llm, "_open",
                               side_effect=urllib.error.URLError("no route")), \
             mock.patch.object(llm, "_bridge_get", return_value=None):
            state, _ = llm.ping({})
        self.assertEqual(state, "offline")

    def test_bridge_refusal_is_refused(self):
        import urllib.error
        with mock.patch.object(llm, "_open",
                               side_effect=urllib.error.URLError("no route")), \
             mock.patch.object(llm, "_bridge_get",
                               return_value={"_jarvis_error": "refused"}):
            state, _ = llm.ping({})
        self.assertEqual(state, "refused")

    def test_successful_bridge_result_is_evaluated(self):
        import urllib.error
        with mock.patch.object(llm, "_open",
                               side_effect=urllib.error.URLError("separate loopback")), \
             mock.patch.object(llm, "_bridge_get",
                               return_value={"models": [{"name": "llama3.2:1b"}]}):
            state, _ = llm.ping({})
        self.assertEqual(state, "model_loaded")


class StatusFindingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_healthy_model_is_ok(self):
        with mock.patch.object(llm, "ping", return_value=("model_loaded", 0.04)):
            f = llm.status_findings({})
        self.assertEqual(f["severity"], "ok")
        self.assertEqual(f["category"], "model")

    def test_dead_model_is_low_and_actionable_never_an_outage(self):
        with mock.patch.object(llm, "ping", return_value=("offline", 3.2)):
            f = llm.status_findings({})
        self.assertEqual(f["severity"], "low")
        self.assertIn("deterministic", f["detail"])

    def test_misconfigured_endpoint_names_the_policy(self):
        with mock.patch.object(llm, "ping", return_value=("misconfigured", 0.0)):
            f = llm.status_findings({"ollama_url": "http://0.0.0.0:11434"})
        self.assertEqual(f["severity"], "low")
        self.assertIn("loopback", f["detail"])


if __name__ == "__main__":
    unittest.main()
