"""Read-only Windows accelerator and resident-model capability probe.

This inventories hardware and runtimes; it never installs packages, loads a
model, changes Ollama configuration, or treats a GPU as security authority.
The expensive native probe is cached for an hour and rides the existing
resource collector rather than adding another scheduler obligation.
"""

import json
import time

from jarvis.platform.windows import ps_json

META = "accelerator_probe_v2"
TTL = 3600

PS_PROBE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = @{gpus=@(); openvino=@{installed=$false; devices=@(); error=''}; ollama=@{reachable=$false; models=@()}; processes=@()}
$o.gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object {
  @{name=[string]$_.Name; driver=[string]$_.DriverVersion; adapter_ram=[long]$_.AdapterRAM;
    status=[string]$_.Status; pnp_id=[string]$_.PNPDeviceID}
})
$o.processes = @(Get-Process -Name ollama,msedge,chrome,brave -ErrorAction SilentlyContinue | ForEach-Object {
  @{name=[string]$_.ProcessName; pid=[int]$_.Id; rss_bytes=[long]$_.WorkingSet64;
    cpu_seconds=if ($null -eq $_.CPU) { 0 } else { [double]$_.CPU }}
})
try {
  $models = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/ps' -Method Get -TimeoutSec 3 -NoProxy
  $o.ollama = @{reachable=$true; models=@($models.models | ForEach-Object {
    @{name=[string]$_.name; size=[long]$_.size; size_vram=[long]$_.size_vram; expires_at=[string]$_.expires_at}
  })}
} catch {}
$pyArgs = @('-3')
$pyPath = ''
$pyCmd = Get-Command py.exe -ErrorAction SilentlyContinue
if ($pyCmd) {
  $pyPath = if ($pyCmd.Source) { $pyCmd.Source } else { $pyCmd.Path }
} else {
  $pyFile = Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python*\python.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
  if ($pyFile) { $pyPath = $pyFile.FullName; $pyArgs = @() }
}
if ($pyPath) {
  $code = "import json`ntry:`n from openvino import Core`n c=Core()`n print(json.dumps({'installed':True,'devices':list(c.available_devices),'error':''}))`nexcept ModuleNotFoundError:`n print(json.dumps({'installed':False,'devices':[],'error':''}))`nexcept Exception as e:`n print(json.dumps({'installed':True,'devices':[],'error':type(e).__name__+': '+str(e)[:160]}))"
  try { $o.openvino = (& $pyPath @pyArgs -c $code 2>$null | Select-Object -Last 1 | ConvertFrom-Json) } catch {}
}
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Depth 6 -Compress)))
"""


def latest(store):
    try:
        value = json.loads(store.get_meta(META, "{}") or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def audit(store, hosts=("wsl", "win"), now=None):
    now = time.time() if now is None else now
    prior = latest(store)
    if prior and now - float(prior.get("at") or 0) < TTL:
        return [_finding(prior)]
    if "win" not in hosts:
        return []
    data = ps_json(PS_PROBE, timeout=20)
    if not isinstance(data, dict):
        return []
    state = {"at": now,
             "gpus": data.get("gpus") if isinstance(data.get("gpus"), list) else [],
             "openvino": data.get("openvino") if isinstance(data.get("openvino"), dict) else {},
             "ollama": data.get("ollama") if isinstance(data.get("ollama"), dict) else {},
             "processes": data.get("processes") if isinstance(data.get("processes"), list) else []}
    state["openvino"]["validation"] = _validate_inference(state["openvino"])
    state["functional"] = state["openvino"]["validation"].get("ok") is True
    state["routing"] = _routing_advice(state)
    store.set_meta(META, json.dumps(state))
    store.commit()
    return [_finding(state)]


def _routing_advice(state):
    """Persisted routing posture; advisory, recomputed hourly with the probe."""
    try:
        from jarvis.core import mlroute as mlroute_mod
        available = 0
        try:
            values = {}
            with open("/proc/meminfo", errors="replace") as fh:
                for line in fh:
                    name, value = line.split(":", 1)
                    values[name] = int(value.split()[0]) * 1024
            available = values["MemAvailable"]
        except (OSError, ValueError, KeyError, IndexError):
            pass
        models = (state.get("ollama") or {}).get("models") or []
        biggest = max([int(m.get("size") or 0) for m in models] or [0]) / 1024 / 1024
        advice = {}
        for task in sorted(mlroute_mod.SUITABLE_TASKS):
            advice[task] = mlroute_mod.route(
                task, state,
                mem_available_mb=available / 1024 / 1024 if available else None,
                model_mb=biggest)["backend"]
        return {"backends": mlroute_mod.backends(state), "tasks": advice,
                "mem_available_mb": round(available / 1024 / 1024, 1)}
    except Exception:
        return {}


def _validate_inference(openvino_state):
    """Run a known graph and require measured GPU execution plus correct output."""
    devices = [str(device) for device in
               (openvino_state.get("devices") or [])]
    if not any(device == "GPU" or device.startswith("GPU.")
               for device in devices):
        return {"ok": False, "reason": "GPU device not enumerated"}
    try:
        from jarvis.platform import openvino as openvino_mod
        result = openvino_mod.infer("anomaly_scoring", [95.0, 20.0, 5.0])
    except Exception as exc:
        return {"ok": False, "reason": type(exc).__name__}
    if result.get("ok") is not True:
        return {"ok": False, "reason": result.get("error", "inference failed")}
    output = result.get("output") or []
    if not output or abs(float(output[0]) - 0.95) > 0.001:
        return {"ok": False, "reason": "GPU output failed reference check"}
    return {"ok": True, "model": result.get("model"),
            "execution_devices": result.get("execution_devices"),
            "latency_s": result.get("latency_s")}


def _finding(state):
    gpus = state.get("gpus") or []
    ov = state.get("openvino") or {}
    validation = ov.get("validation") or {}
    names = ", ".join(str(g.get("name") or "unknown") for g in gpus) or "none detected"
    devices = [str(d) for d in (ov.get("devices") or [])]
    ready = validation.get("ok") is True
    detail = (f"GPU: {names}. OpenVINO installed={bool(ov.get('installed'))}; "
              f"devices={', '.join(devices) or 'none'}. "
              f"GPU inference validated={ready}; "
              f"execution={','.join(validation.get('execution_devices') or []) or 'none'}. "
              f"Ollama reachable={bool((state.get('ollama') or {}).get('reachable'))}. "
              "Validation uses a fixed bounded model and does not authorize security actions.")
    return {"host": "win", "category": "performance",
            "severity": "ok" if ready else "low",
            "title": ("Intel GPU inference executed successfully" if ready else
                      "Intel GPU inference is not functional"),
            "detail": detail, "where": "Windows accelerator probe"}
