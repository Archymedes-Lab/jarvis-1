"""JARVIS ML worker: one inference queue, adaptive CPU/GPU routing.

Phase 7: the Intel UHD is used only where GPU execution genuinely helps
(embeddings, small classifiers, anomaly scoring, visual analysis) and
only when measured. Integrated-GPU memory is shared RAM, so every GPU
placement must leave headroom the governor protects; under pressure the
worker defers waitable tasks or falls back to deterministic CPU paths.

No model is loaded under pressure. Unknown backends resolve to the
deterministic path ("none"), never to hope. Callers remain responsible for
keeping secrets out of features. Deferred queue entries retain only task names
and timestamps, never feature content.
"""

from __future__ import annotations

import hashlib
import time
from collections import deque

from jarvis.core import mlroute as mlroute_mod

QUEUE_LIMIT = 256
LATENCY_BUDGET_S = 5.0
CLASSIFIER_TOKENS = ("login", "verify", "urgent", "track", "beacon",
                     "fingerprint", "canvas", "keylog")

_QUEUE: deque = deque()
_STATS = {"submitted": 0, "gpu": 0, "cpu": 0, "deferred": 0, "none": 0,
          "dropped": 0}


def _cpu_score(task, features):
    """Deterministic CPU fallback. Pure, bounded, never claims certainty."""
    features = features if isinstance(features, dict) else {}
    if task == "anomaly_scoring":
        try:
            value = float(features.get("value", 0.0))
            median = float(features.get("median", 0.0))
            mad = float(features.get("mad", 0.0))
        except (TypeError, ValueError):
            return {"score": 0.0, "reason": "non-numeric input; unknown"}
        if mad <= 0:
            return {"score": 0.0 if value == median else 0.3,
                    "reason": "zero MAD; deviation is noted, not scored"}
        z = 0.6745 * (value - median) / mad
        score = min(0.95, abs(z) / 6.0)
        return {"score": round(max(0.0, score), 3),
                "reason": f"robust z={z:.2f}; supporting evidence only"}
    if task in ("phishing_classifier", "tracking_classifier"):
        text = " ".join(str(features.get(k) or "") for k in
                        ("url", "origin", "signals")).lower()
        hits = sum(tok in text for tok in CLASSIFIER_TOKENS)
        score = min(0.9, 0.2 + 0.15 * hits)
        if not text.strip():
            return {"score": 0.0, "reason": "no signals; unknown"}
        return {"score": round(score, 3),
                "reason": f"{hits} heuristic signal(s); metadata only"}
    if task == "embeddings":
        text = str(features.get("text") or "")[:2000]
        vec = [0.0] * 32
        for tok in text.lower().split():
            h = int(hashlib.sha256(tok.encode()).hexdigest(), 16)
            vec[h % 32] += 1.0
        norm = sum(v * v for v in vec) ** 0.5 or 1.0
        return {"vector": [round(v / norm, 4) for v in vec],
                "reason": "hashed bag-of-words; no model loaded"}
    return {"score": 0.0,
            "reason": f"{task} has no deterministic CPU model; unknown"}


def _gpu_values(task, features):
    features = features if isinstance(features, dict) else {}
    try:
        if task == "anomaly_scoring":
            return [float(features.get("value", 0.0)),
                    float(features.get("median", 0.0)),
                    float(features.get("mad", 0.0))]
        if task in ("phishing_classifier", "tracking_classifier"):
            text = " ".join(str(features.get(key) or "") for key in
                            ("url", "origin", "signals")).lower()
            if not text.strip():
                return None
            return [1.0 if token in text else 0.0
                    for token in CLASSIFIER_TOKENS]
        if task == "embeddings":
            text = str(features.get("text") or "")[:2000]
            counts = [0.0] * 32
            for token in text.lower().split():
                digest = int(hashlib.sha256(token.encode()).hexdigest(), 16)
                counts[digest % 32] += 1.0
            return counts
    except (TypeError, ValueError):
        return None
    return None


_GPU_INFER = None


def set_gpu_infer(fn):
    """Register the platform GPU executor. Platform wires itself; core never imports up."""
    global _GPU_INFER
    _GPU_INFER = fn


def _try_openvino_gpu(task, features, infer_fn=None):
    """Run and cross-check a fixed graph on the measured Windows GPU."""
    values = _gpu_values(task, features)
    if values is None:
        return None
    infer = infer_fn or _GPU_INFER
    if infer is None:
        return None
    try:
        response = infer(task, values)
    except Exception:
        return None
    if not isinstance(response, dict) or response.get("ok") is not True:
        return None
    output = response.get("output") or []
    expected = _cpu_score(task, features)
    if task == "embeddings":
        vector = expected.get("vector") or []
        if len(output) != len(vector) or any(
                abs(float(actual) - float(want)) > 0.001
                for actual, want in zip(output, vector)):
            return None
        return {"vector": [round(float(value), 4) for value in output],
                "reason": "validated deterministic embedding graph on GPU",
                "model": response.get("model"),
                "execution_devices": response.get("execution_devices"),
                "latency_s": response.get("latency_s")}
    expected_score = expected.get("score")
    if not output or expected_score is None \
            or abs(float(output[0]) - float(expected_score)) > 0.001:
        return None
    return {"score": round(float(output[0]), 3),
            "reason": expected.get("reason", "") + "; validated GPU graph",
            "model": response.get("model"),
            "execution_devices": response.get("execution_devices"),
            "latency_s": response.get("latency_s")}


def submit(task, features=None, inventory=None, mem_available_mb=None,
           model_mb=0.0, governor_pressured=False, deferrable=True,
           now=None, gpu_infer=None):
    """Route one inference task and execute it. Bounded, never raises."""
    now = time.time() if now is None else now
    _STATS["submitted"] += 1
    route = mlroute_mod.route(
        task, inventory or {}, mem_available_mb=mem_available_mb,
        model_mb=model_mb, governor_pressured=governor_pressured,
        deferrable=deferrable)
    backend = route.get("backend", "none")
    if backend == "deferred":
        if len(_QUEUE) >= QUEUE_LIMIT:
            _STATS["dropped"] += 1
            return {"backend": "deferred", "dropped": True,
                    "reason": "queue full; waitable work shed, never run blind"}
        _QUEUE.append({"task": task, "at": now})
        _STATS["deferred"] += 1
        return {"backend": "deferred", "queued": len(_QUEUE),
                "reason": route.get("reason", "")}
    if backend == "none":
        _STATS["none"] += 1
        result = _cpu_score(task, features)
        result.update({"backend": "none",
                       "reason": route.get("reason", "") + "; deterministic path"})
        return result
    if backend == "gpu":
        gpu_result = _try_openvino_gpu(task, features, infer_fn=gpu_infer)
        if gpu_result is not None:
            _STATS["gpu"] += 1
            gpu_result["backend"] = "gpu"
            return gpu_result
        # Inventory said GPU, but execution or cross-validation failed.
        _STATS["cpu"] += 1
        result = _cpu_score(task, features)
        result.update({"backend": "cpu",
                       "reason": "OpenVINO GPU route failed execution or "
                                 "cross-validation; CPU fallback"})
        return result
    _STATS["cpu"] += 1
    started = time.time()
    result = _cpu_score(task, features)
    result.update({"backend": "cpu", "route_reason": route.get("reason", ""),
                   "latency_s": round(time.time() - started, 4)})
    if result.get("latency_s", 0) > LATENCY_BUDGET_S:
        result["reason"] += "; over latency budget"
    return result


def drain(now=None):
    """Release deferred queue entries so callers may resubmit them.

    No inference is executed here: feature content is intentionally not kept
    in the queue. The returned ``executed`` field prevents queue movement from
    being mistaken for completed ML work.
    """
    now = time.time() if now is None else now
    drained = 0
    while _QUEUE and drained < 32:
        item = _QUEUE.popleft()
        if now - float(item.get("at", now)) > 3600:
            _STATS["dropped"] += 1
            continue
        drained += 1
    return {"drained": drained, "executed": 0, "queued": len(_QUEUE),
            "reason": "queue entries released; caller resubmission required"}


def stats():
    return {"queued": len(_QUEUE),
            "gpu_executor_configured": callable(_GPU_INFER), **dict(_STATS)}


def clear():
    _QUEUE.clear()
    for key in _STATS:
        _STATS[key] = 0
