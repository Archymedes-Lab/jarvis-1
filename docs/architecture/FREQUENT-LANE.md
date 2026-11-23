# The frequent lane (2026-11-03)

## What went wrong (measured on the live release, boot of 2026-11-03 10:13)

After the WSL VM booted, every collector was due at once and their evidence
predated the boot. The single main worker owed one sweep of 55 collectors,
1331 s of measured run time. Most of it went to intrusion (299 s), secrets
(168 s), firewall (117 s), deep_hidden (113 s), boot (91 s), control (85 s) and
storage (75 s). The collectors on a five-minute cadence ran once at start-up
and then waited behind that sweep. Twenty collectors were STALE for about
16 minutes: audio, canary, controls, hidden, input, logins, netflow, netwatch,
privacy, resources, sshwatch, wsl and wslmanifest, plus the long-cadence ones
the sweep had not reached yet. No collector failed, and nothing logged an
error. The stale list was empty again at about 10:31.

Starving-first ordering (LANE-FAIRNESS-AND-OUTAGE-RECORD.md, I1) could not
prevent this. A five-minute job starves only once it is already STALE (2× its
cadence). When that happens, the main lane may be inside a 299 s audit that it
cannot pre-empt.

## Invariants

* **F1 Freshness after boot.** A collector on a cadence of 300 s or less never
  waits behind the main lane. Its wait past its cadence is bounded by one pass
  of its own lane's declared costs (about 85 s), so it never reaches STALE
  because of main-lane work. Measured against the real `_due` in
  `tests/test_lane_fairness.py::PostBootFrequentLaneTests`. The same replay
  without the lane reproduces the fault.
* **F2 Bounded interop.** Frequent-lane jobs launch PowerShell through
  `platform/windows.spawn`, which passes the daemon-wide admission gate
  (`platform/interop_gate.py`: at most 2 gated launches at a time, 1 while
  degraded, a bounded wait, then a recorded refusal). A new lane therefore
  never raises interop concurrency above the gate. The bulk lane keeps its
  stricter no-PowerShell rule.
* **F3 Bounded duty and run length.** The lane's declared duty is 0.31, against
  a limit of 0.8 (LANE_DUTY_LIMIT). Every frequent job declares a measured
  `cost_s` and a timeout of at most 60 s, is never governed, and is not
  isolated. `mechanisms.conformance()` enforces all of these, and it also
  refuses a 300 s evidence collector that is declared back on the main lane.
* **F4 Exclusivity.** Lanes are disjoint, so a job runs in exactly one lane and
  never alongside itself.
* **F5 No silent lane.** A dead frequent thread fails `fast_alive()`, which
  makes protection health not live, and marks link `lane:frequent` silent. A
  lane that has not looped for 900 s makes health not live. Past the main
  lane's stall limit (at least 600 s), the systemd watchdog stops pinging, so
  systemd restarts the daemon.
* **F6 Failures stay failures.** A refused or crashing frequent job is a
  recorded failure with bounded retry through the reliability plane, never an
  empty clean result, and the lane keeps running.

## Designs compared

| | A. Quick lane, jobs under 2 s | **B. Frequent lane, cadence ≤ 300 s (chosen)** | C. Reorder main by stale deadline | D. Heavy lane, jobs over 30 s |
|---|---|---|---|---|
| Fixes audio/resources/controls/wsl (3 to 24 s each) | No: they stay behind the sweep | Yes | No: after a boot the work is 1331 s, and ordering cannot fit it into 600 s | Partly: they still queue behind about 40 medium jobs |
| Worst wait for a 300 s job | Unchanged for the PowerShell ones | One frequent pass, about 85 s | One main job, up to 299 s, plus the backlog | Medium backlog |
| Interop concurrency | Gate-bounded | Gate-bounded (2 launches) | Unchanged | Gate-bounded |
| Cost | One thread | One thread and one SQLite connection | None | One thread |
| Registry rule | Cost-based, which drifts with load | Cadence-based, which is declared and stable | None | Cost-based |

Jev (bounded, metadata-only, advisory) chose B with probability 0.93. It rated
the interop risk of a second PowerShell-using lane at 0.48, which is
uncertain. That uncertainty is answered in code by F2 (the gate), not by the
judgment. It still has to be confirmed on the live host (below).

A per-job "restart until fresh" loop was rejected. The collectors were never
broken, only queued. Forcing them adds work to the same queue. A loop of that
shape held the main worker for 7 hours on 2026-10-10.

## Shared state audit (before deploy)

Some collectors that never overlapped can now run at the same time as a
main-lane audit. Jev ranked this as the most important unverified area (0.99).
An import-closure scan found 48 modules reachable from both lanes. The mutable
module state among them:

- `core.eventlog` parse and sealed caches: guarded by `_PARSE_LOCK`.
- `core.state` process and socket caches: guarded by an RLock.
- `platform.firewall_state._CACHE` (internet and firewall),
  `platform.windows._PS` and `core.util._rdns_cache`: idempotent lazy caches.
  The worst race is one extra lookup or one extra PowerShell read, and the
  gate bounds that read.
- `response.alert.LAST_DELIVERY`: already written by deliveries from the fast,
  main and bulk lanes.

No collector-specific state is shared without a lock. Collectors that use the
same module (audio and privacy, both through `privacyseal`) sit in the same
lane, so they still run one at a time.

## Reconsider if

- after deploy, interop gate refusals (`coverage` → interop gate findings) or
  `bridge` latency rise compared with the pre-deploy baseline;
- the frequent lane's measured duty passes 0.6, or one of its jobs regularly
  runs past 60 s;
- a five-minute collector is still STALE after the next boot or wake.

## Live acceptance (after the owner deploys)

1. Before deploying, write a baseline: `/api/health` reliability levels, the
   interop gate state, and `bridge`/`audio`/`resources` durations.
2. After deploying, `links.lane:frequent` is up and `frequent_lane_age` stays
   under 60 s in `/api/health`.
3. After the next reboot or standby wake, no collector in
   `scheduler.FREQUENT` appears in `reliability.stale_collectors` at any
   readback, and the gate's refusal count is no higher than the baseline.
