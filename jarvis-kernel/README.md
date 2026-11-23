# JarvisKernel.sys — contract only (no driver binary here)

The eventual Windows sensor stays tiny: authoritative observation, nothing
else. This directory records the contract enforced by
`jarvis/core/execution/kernel_contract.py`; it is not a buildable driver yet.

```
jarvis-kernel/
    README.md        this contract
    process.c        PsSetCreateProcessNotifyRoutineEx (create / exit)
    thread.c         PsSetCreateThreadNotifyRoutine (create / exit)
    image.c          PsSetLoadImageNotifyRoutine (image load)
    handles.c        ObRegisterCallbacks (selected handle activity only)
    ringbuffer.c     bounded lock-free ring, drop-counted
    integrity.c      boot_id + monotonic seq per event
```

Output: kernel event -> bounded ring buffer -> Jarvis Windows Sensor ->
Rust runtime -> temporal engine. No model, no database, no HTTP, no
arbitrary commands. HVCI-compatible. No SSDT hooks, patching, inline
hooks, undocumented writes, or DKOM scanning/modification.
