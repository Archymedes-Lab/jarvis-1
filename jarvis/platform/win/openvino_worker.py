"""Execute JARVIS's small deterministic inference graphs on OpenVINO GPU.

This file is launched by Windows Python from WSL. It accepts exactly one JSON
request on stdin and emits exactly one JSON response. It has no filesystem,
network, model-download, or security-response capability.
"""

import json
import sys
import time

import numpy as np
from openvino import Core, Model, Type
from openvino import opset13 as ops

MODEL_VERSION = "jarvis-deterministic-v1"


def _f32(value):
    return ops.constant(np.float32(value))


def _anomaly_model():
    values = ops.parameter([3], Type.f32, name="value_median_mad")
    value = ops.gather(values, ops.constant(0), ops.constant(0))
    median = ops.gather(values, ops.constant(1), ops.constant(0))
    mad = ops.gather(values, ops.constant(2), ops.constant(0))
    zero_mad = ops.less_equal(mad, _f32(0.0))
    same = ops.equal(value, median)
    zero_score = ops.select(same, _f32(0.0), _f32(0.3))
    safe_mad = ops.maximum(mad, _f32(1.0e-12))
    z = ops.absolute(ops.divide(
        ops.multiply(ops.subtract(value, median), _f32(0.6745)),
        safe_mad))
    normal_score = ops.minimum(ops.divide(z, _f32(6.0)), _f32(0.95))
    score = ops.select(zero_mad, zero_score, normal_score)
    return Model([score], [values], "jarvis_anomaly_v1")


def _classifier_model():
    signals = ops.parameter([8], Type.f32, name="signals")
    hits = ops.reduce_sum(signals, ops.constant([0]), keep_dims=False)
    score = ops.minimum(
        ops.add(_f32(0.2), ops.multiply(hits, _f32(0.15))),
        _f32(0.9))
    return Model([score], [signals], "jarvis_signal_classifier_v1")


def _embedding_model():
    counts = ops.parameter([32], Type.f32, name="token_counts")
    magnitude = ops.sqrt(ops.reduce_sum(
        ops.multiply(counts, counts), ops.constant([0]), keep_dims=False))
    norm = ops.maximum(magnitude, _f32(1.0))
    vector = ops.divide(counts, norm)
    return Model([vector], [counts], "jarvis_embedding_normalizer_v1")


def _request(payload):
    task = payload.get("task")
    values = payload.get("values")
    if task == "anomaly_scoring" and isinstance(values, list) and len(values) == 3:
        model = _anomaly_model()
    elif task in ("phishing_classifier", "tracking_classifier") \
            and isinstance(values, list) and len(values) == 8:
        model = _classifier_model()
    elif task == "embeddings" and isinstance(values, list) and len(values) == 32:
        model = _embedding_model()
    else:
        raise ValueError("unsupported task or input shape")
    array = np.asarray(values, dtype=np.float32)
    if not np.isfinite(array).all():
        raise ValueError("non-finite model input")

    started = time.perf_counter()
    core = Core()
    if not any(str(device) == "GPU" or str(device).startswith("GPU.")
               for device in core.available_devices):
        raise RuntimeError("OpenVINO GPU device unavailable")
    compiled = core.compile_model(model, "GPU")
    output = compiled([array])[0]
    devices = [str(device) for device in
               compiled.get_property("EXECUTION_DEVICES")]
    if not any(device == "GPU" or device.startswith("GPU.")
               for device in devices):
        raise RuntimeError("model did not execute on GPU")
    return {"ok": True, "task": task, "model": MODEL_VERSION,
            "execution_devices": devices,
            "output": np.asarray(output).reshape(-1).astype(float).tolist(),
            "latency_s": round(time.perf_counter() - started, 6)}


def main():
    try:
        raw = sys.stdin.buffer.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ValueError("request too large")
        payload = json.loads(raw.decode("utf-8", "replace"))
        if not isinstance(payload, dict):
            raise ValueError("request must be an object")
        result = _request(payload)
    except Exception as exc:
        result = {"ok": False, "error": type(exc).__name__,
                  "detail": str(exc)[:200]}
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
