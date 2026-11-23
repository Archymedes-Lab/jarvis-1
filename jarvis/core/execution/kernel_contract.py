"""JarvisKernel.sys contract: authoritative observation, nothing else.

The eventual Windows driver stays tiny on purpose. It reasons about
nothing: no model, no database, no HTTP, no arbitrary commands. It emits
process / thread / image / selected-handle events into a bounded,
lock-free, drop-counted ring buffer that the user-mode sensor drains into
the Rust runtime and the temporal engine.

Allowed (supported Windows callbacks only):

  * PsSetCreateProcessNotifyRoutineEx  process create / exit
  * PsSetCreateThreadNotifyRoutine      thread create / exit
  * PsSetLoadImageNotifyRoutine         image load
  * ObRegisterCallbacks                 selected handle activity only

Forbidden (never in the manifest, never in review):

  * SSDT hooks, kernel patching, inline kernel hooks
  * undocumented structure manipulation, DKOM-style scan / modification
  * writable+executable kernel memory, dynamic kernel code, direct
    modification of executable system memory (HVCI incompatibility)

This module validates a driver manifest against that contract. Pure.
"""

ALLOWED_CALLBACKS = frozenset({
    "PsSetCreateProcessNotifyRoutineEx",
    "PsSetCreateThreadNotifyRoutine",
    "PsSetLoadImageNotifyRoutine",
    "ObRegisterCallbacks",
})

FORBIDDEN_TECHNIQUES = frozenset({
    "ssdt_hook", "kernel_patch", "inline_hook", "dkon_scan",
    "dkom_modify", "undocumented_struct_write", "writable_executable",
    "dynamic_code", "executable_memory_write",
})

ALLOWED_EVENT_TYPES = frozenset({
    "process_create", "process_exit",
    "thread_create", "thread_exit",
    "image_load", "handle_activity",
})

RING_BUFFER_MAX_EVENTS = 65536


def validate_manifest(manifest):
    """Validate a driver manifest dict. Returns [error, ...] (empty == ok)."""
    errors = []
    manifest = manifest or {}
    for cb in (manifest.get("callbacks") or []):
        if cb not in ALLOWED_CALLBACKS:
            errors.append(f"unsupported callback: {cb}")
    for tech in (manifest.get("techniques") or []):
        if tech in FORBIDDEN_TECHNIQUES:
            errors.append(f"forbidden technique: {tech}")
    mem = manifest.get("memory") or {}
    if mem.get("writable_executable"):
        errors.append("writable+executable kernel memory is HVCI-incompatible")
    if mem.get("dynamic_code"):
        errors.append("dynamic kernel code is HVCI-incompatible")
    if mem.get("writes_executable_memory"):
        errors.append("direct modification of executable system memory "
                      "is HVCI-incompatible")
    for cap in ("model", "database", "http", "arbitrary_commands"):
        if manifest.get(cap):
            errors.append(f"driver must not contain {cap}")
    size = manifest.get("ring_buffer_events", 0)
    try:
        size = int(size)
    except (TypeError, ValueError):
        errors.append("ring_buffer_events must be an integer")
        size = 0
    if not 0 < size <= RING_BUFFER_MAX_EVENTS:
        errors.append("ring buffer must be bounded "
                      f"(1..{RING_BUFFER_MAX_EVENTS})")
    return errors


def validate_event(event):
    """Validate one ring-buffer event dict. Returns [error, ...]."""
    errors = []
    event = event or {}
    if event.get("type") not in ALLOWED_EVENT_TYPES:
        errors.append(f"unknown event type: {event.get('type')!r}")
    if not isinstance(event.get("pid"), int) or event.get("pid", 0) < 0:
        errors.append("event needs an integer pid")
    if not event.get("boot_id"):
        errors.append("event needs a boot_id (pid reuse guard)")
    seq = event.get("seq")
    if not isinstance(seq, int) or seq < 0:
        errors.append("event needs a monotonic seq")
    return errors
