import json
import unittest
from unittest import mock

from jarvis.platform import openvino


class OpenVINOBridgeTests(unittest.TestCase):
    def test_validated_gpu_response_passes(self):
        payload = {"ok": True, "model": "jarvis-deterministic-v1",
                   "execution_devices": ["GPU.0"], "output": [0.95],
                   "latency_s": 0.1}
        completed = mock.Mock(returncode=0, stdout=json.dumps(payload), stderr="")
        with mock.patch.object(openvino, "python_binary",
                               return_value="/mnt/c/python.exe"), \
                mock.patch.object(openvino, "_windows_path",
                                  return_value=r"\\wsl.localhost\worker.py"), \
                mock.patch.object(openvino.subprocess, "run",
                                  return_value=completed):
            out = openvino.infer("anomaly_scoring", [95.0, 20.0, 5.0])
        self.assertTrue(out["ok"])
        self.assertEqual(out["execution_devices"], ["GPU.0"])

    def test_cpu_execution_cannot_masquerade_as_gpu(self):
        payload = {"ok": True, "execution_devices": ["CPU"],
                   "output": [0.95]}
        completed = mock.Mock(returncode=0, stdout=json.dumps(payload), stderr="")
        with mock.patch.object(openvino, "python_binary",
                               return_value="/mnt/c/python.exe"), \
                mock.patch.object(openvino, "_windows_path",
                                  return_value=r"\\wsl.localhost\worker.py"), \
                mock.patch.object(openvino.subprocess, "run",
                                  return_value=completed):
            out = openvino.infer("anomaly_scoring", [95.0, 20.0, 5.0])
        self.assertFalse(out["ok"])

    def test_non_finite_input_is_rejected_before_execution(self):
        with mock.patch.object(openvino.subprocess, "run") as run:
            out = openvino.infer("anomaly_scoring", [1.0, 0.0, float("nan")])
        self.assertEqual(out["error"], "invalid_input")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
