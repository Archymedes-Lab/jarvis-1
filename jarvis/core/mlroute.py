"""Adaptive ML routing: the right backend for each inference task, or none.

Phase 7. The Intel UHD is idle, but idleness is not a reason — GPU
execution must actually help, and on an integrated GPU RAM is shared, so
every GPU placement spends the same memory the governor protects. Rules:

  - No OpenVINO GPU device -> CPU. Never claim a path that isn't measured.
  - OpenVINO GPU and Ollama are independent runtimes. A measured OpenVINO GPU
    may run a supported fixed graph even when Ollama is unreachable.
  - Only suitable tasks (embeddings, small classifiers, anomaly scoring,
    visual analysis) may route to GPU; arbitrary work stays on CPU.
  - Under RAM or governor pressure -> CPU, or defer the task entirely;
    never load a model into a pressured machine.
  - Unknown inputs -> CPU. The conservative default is always the CPU.

Pure: no IO, no model calls. Thresholds are parameters so tests pin the
contract. This decides; enforcement lives with the callers.
"""

# Tasks where small-model GPU execution genuinely helps. Anything else —
# narration, repair drafting, chat — stays on CPU by default.
SUITABLE_TASKS = frozenset({
    "embeddings",
    "phishing_classifier",
    "tracking_classifier",
    "anomaly_scoring",
    "malware_classifier",
    "visual_analysis",
})

# A GPU placement must leave this much headroom, because shared memory
# means the GPU allocation *is* RAM pressure.
GPU_MIN_HEADROOM_MB = 1024.0


def backends(inventory):
    """Which inference backends actually exist right now. Pure."""
    inventory = inventory or {}
    ov = inventory.get("openvino") or {}
    devices = [str(d) for d in (ov.get("devices") or [])]
    validation = ov.get("validation") or {}
    gpu = (bool(ov.get("installed"))
           and validation.get("ok") is True
           and any(d == "GPU" or d.startswith("GPU.") for d in devices))
    ollama = bool((inventory.get("ollama") or {}).get("reachable"))
    return {"openvino_gpu": gpu, "ollama": ollama,
            "devices": devices}


def route(task, inventory, *, mem_available_mb=None, model_mb=0.0,
          governor_pressured=False, deferrable=True):
    """Route one inference task. Returns {"backend", "reason"}.

    Backend is "gpu", "cpu", "deferred" or "none":
      gpu       OpenVINO GPU measured, task suitable, headroom holds
      cpu       default: measured-safe, or GPU unsuitable right now
      deferred  pressured host and the task can wait (caller retries idle)
      none      no model runtime reachable; use the deterministic path
    """
    avail = backends(inventory)
    if task not in SUITABLE_TASKS:
        if not avail["ollama"]:
            return {"backend": "none",
                    "reason": "no model runtime reachable; deterministic path only"}
        return {"backend": "cpu",
                "reason": f"{task} is not a GPU-suitable task; CPU by default"}
    if not avail["openvino_gpu"]:
        if not avail["ollama"]:
            return {"backend": "none",
                    "reason": "no measured OpenVINO GPU or model runtime; "
                              "deterministic path only"}
        return {"backend": "cpu",
                "reason": "no measured OpenVINO GPU path; CPU instead of hoping"}
    if governor_pressured or (mem_available_mb is not None
                              and mem_available_mb < GPU_MIN_HEADROOM_MB):
        if deferrable:
            return {"backend": "deferred",
                    "reason": "host pressured; inference waits for idle"}
        return {"backend": "cpu",
                "reason": "host pressured and task cannot wait; CPU, no GPU load"}
    if mem_available_mb is not None and model_mb > 0 and \
            mem_available_mb - model_mb < GPU_MIN_HEADROOM_MB:
        return {"backend": "cpu",
                "reason": f"model ({model_mb:.0f} MB) would leave shared RAM "
                          "below headroom; CPU keeps the system whole"}
    return {"backend": "gpu",
            "reason": f"OpenVINO GPU measured ({', '.join(avail['devices'])}), "
                      f"{task} suitable, headroom holds"}
