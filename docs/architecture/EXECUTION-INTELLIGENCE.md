# JARVIS Execution Intelligence

Layered observability with escalated depth. The architectural rule: **record
supported event streams with explicit gaps, reconcile against snapshots, then
escalate selected processes into deeper analysis.** Never inspect every
instruction continuously. This document describes a target and pure models;
it is not a live coverage claim.

## Layers

| Layer | Source | Cost | When |
|---|---|---|---|
| L0 hardware / PMU | aggregate counters | trivial | always |
| L1 kernel process truth | kernel callbacks (future), ETW, Sysmon Event 1 | cheap events | always |
| L2 threads / modules / memory | one snapshot, many consumers; hidden.ps1; memscan | one read | always |
| L3 native execution / stacks | bounded per-pid sample (<= 32) | medium | mismatch only |
| L4 .NET runtime | memscan foreign images + assemblies + CLR settings | medium | mismatch only |
| L5 behavioral correlation | temporal detectors over the ordered feed | cheap | always |
| L6 deep forensic trace | memory dump / instruction trace | high | human-gated only |
| L7 cross-view covert detection | presence.reconcile + impossible.check_all | cheap | always |

## Cross-view truth

Views A (kernel callbacks) / B (ETW) / C (Sysmon) / D (snapshot) /
E (threads+images) / F (cpu+network) reconcile per instance key
`(boot_id, pid, started|guid)` in `jarvis/core/execution/presence.py`.
Result is **visibility confidence**, not `exists = true`.

`jarvis/core/execution/impossible.py` fires on impossible combinations:
CPU without process, threads without ProcessStart, network/image orphans.

`jarvis/core/execution/escalate.py` can select L3/L4 pids under governor pressure
and a per-interval budget (default 5). L6 entries appear only for
explicitly human-authorized keys, with a dump-before-act contract.

## Kernel sensor (future)

`jarvis-kernel/` holds the contract only. The driver, when built, uses
solely `PsSetCreateProcessNotifyRoutineEx`,
`PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`, and
`ObRegisterCallbacks` for selected handles; emits into a bounded
(<= 65536) drop-counted ring buffer; contains no model, database, HTTP, or
arbitrary commands; and stays HVCI-compatible (no W+X, no dynamic code, no
executable-memory writes, no SSDT/patching/inline hooks/DKOM).
`jarvis/core/execution/kernel_contract.py` validates manifests and events.

## Privacy and authority

Metadata only (keys, pids, booleans, fixed-list features). No cmdlines,
paths, file contents, or secrets leave the host; Jev notes are advisory
and cannot change severity or authorize L6. L6 needs explicit human
authorization plus evidence preservation and rollback.

## Change-level observability

The canonical event vocabulary can represent thread start/exit,
image unload, connection end, file write/rename, service/account/device
changes, and memory protection changes (`jarvis/core/event.py`). The live
Windows sensor reads Sysmon, Defender and Task Scheduler Event Logs; defining
an event kind does not mean a sensor emits it. The native pipeline preserves
supported records with source identity and a global ingest sequence. Snapshots
can check those streams only where their coverage window is continuous. Identities
(`jarvis/core/execution/identity.py`) survive pid reuse via boot+guid keys.
Formal invariants I1–I5 (`jarvis/core/execution/invariants.py`,
`jarvis/intel/visibility.py`) are pure evaluators over supplied windows;
violations cite keys/seqs and are never labeled malware. Observation is
limited by actual source coverage; interpretation stays disciplined. Protected
processes with lifecycle agreement and OS-restricted memory read as
EXPECTED_PROTECTED_PROCESS, never suspicious.

## Deep planes (change-level)

Memory (`memory.py`): region maps with deltas and RW→write→RX→thread
activation chains; flags private RWX / unbacked executable. Threads
(`threads.py`): start-address and explosion anomalies. Modules
(`modules.py`): expected-vs-current diffs (added/removed/hash/signer).
Sampling (`sampling.py`): module/function heatmaps with unknown-shift
detection. Fingerprints (`fingerprint.py`): baseline-band deviations.
CLR (`dotnet.py`): light assembly/JIT/exception/thread watch, IL→native
resolution, human-gated ClrMD snapshots. Ledger (`ledger.py`): chained
changes with digested before/after values and what-changed rollups.
Baselines (`baseline.py`): FIRST_SEEN/RARE/EXPECTED/CHANGED/ANOMALOUS
labels. Self-watch (`watch.py`): telemetry contradiction, suppression,
envelope breaches, sensor-liveness events. Scores
(`visibility_score.py`): per-entity and global observability, restricted
never failed. Forensics (`forensic.py`): 10s gated capture, buffer
freeze, T±30min hold, return to LEVEL 1.

## Wiring (change-level)

Temporal projection folds thread start/exit (per-instance keys, cleared
on process exit so pid reuse never inherits threads), service
created/changed/started/stopped, connection ends, memory-protection
changes, image unloads, and file write/rename alongside the existing
state; `changes()` reports thread/service/connection/memory deltas.
Sampling schedule (`schedule.py`) keeps lifecycle event-driven and backs
interval signals off by cost, boosting L2/L3 one step and yielding
noncritical sampling under pressure. Rust `reconcile.rs` mirrors the
Python verdicts for the hot path (4 unit tests). Forge
(`jarvis/lab/visibility_evasion.py`, synthetic only) covers short-lived
processes, rapid module bursts, creation/exit races, protected
processes, and dropped-event gaps. Panels (`panel.py`) render factual
per-view checks with confidence and a one-line state.

## Causal view and honest remainder

Chains (`causal.py`) compose one instance's file/network/registry/module/
thread/memory/service transitions in seq order; deltas (`deltas.py`) store
checkpoints plus threshold crossings instead of repeated steady state.
Still future and stated as gaps, not claims: signed HVCI kernel binary,
C# CLR sensor with live EventPipe/ClrMD, PMU/Intel-PT deep traces,
live-scheduled L3/L4 escalation, soak evidence, and live covert-process
validation.
