# Mechanism design system

JARVIS is built from a small set of mechanisms: collectors that observe, lanes
that run them, budgets that judge their freshness, journals that keep their
evidence, streams that show it and gates that decide before anything acts. This
document is the catalogue. Like a component library in a UI design system, every
part of JARVIS is composed from these primitives and nothing else, and each
primitive has one fixed contract.

The catalogue is executable. `jarvis/core/mechanisms.py` holds the same
primitives as data (`PRIMITIVES`) together with one declaration per collector
(`COLLECTORS`), and `conformance()` checks both. A section heading here that does
not match a primitive in code fails `tests/test_mechanisms.py`.

## Principles

1. **Declare once.** A fact about a mechanism lives in one place. Every other
   table is a view derived from it, never a copy.
2. **Behaviour-preserving by proof.** A refactor onto the registry ships only
   with a golden test showing each derived view equals the table it replaced.
   The live readback against a written baseline is still the acceptance gate
   (docs/guides/DEPLOY.md).
3. **A clean report and no report never look the same.** Every mechanism has a
   defined, visible failure. Silence is never a passing state.
4. **Bounded.** Every loop, retry, stream, lease and helper has a limit written
   in its contract.
5. **Authority stays human.** Gates fail closed. Advisory output, including
   Jev's, can rank or add friction but never allow.
6. **Measured, not estimated.** Costs (`cost_s`) and durations come from this
   machine, and the lane duty check uses only measured values.

## Anatomy of a collector declaration

| Field | Meaning | Rule enforced by `conformance()` |
|---|---|---|
| `name`, `interval`, `label` | the schedule entry | positive interval and a label |
| `area`, `area_rank` | score area and in-area precedence (earlier wins a shared finding) | known area; ranks dense 0..n-1 per area |
| `unscored` | why a collector with `area=None` is unscored | required when unscored, forbidden when scored |
| `tier`, `criticality` | reliability tier 0-4 and paging weight | tiers 2-4 by interval band (≤300 s, ≤7200 s, longer); tiers 0-1 at most 600 s; critical exactly when tier 0 |
| `timeout` | run budget | below the interval (fast lane exempt) and at most a tenth of it, clamped to 60-300 s |
| `lane` | `fast`, `frequent`, `main` or `bulk` serial worker | known lane; measured duty per lane at most 0.8; frequent: cadence ≤ 300 s, measured cost, timeout ≤ 60 s, never governed, and every 300 s evidence collector belongs there ([FREQUENT-LANE.md](FREQUENT-LANE.md)) |
| `domain` | `both`, `windows` or `linux` | known domain |
| `governed` | the resource governor may defer it | never for tier 0 or the fast lane |
| `isolated` | runs in a deadline-bounded child | fast lane only |
| `evidence` | False only for JARVIS's own reporting (coverage, report) | |
| `depends_on` | dependency roots (`windows-bridge`, `native-sensor`, `scheduler`) | known roots |
| `cost_s` | measured wall seconds per run | feeds the duty check |
| `command` | the CLI command that audits the same ground, named in reports | required |
| `health`, `health_limit_s` | `required` (the service is unhealthy while this evidence is older than the limit) or `optional` (reported, never a dependency) | known role; the limit is never shorter than the interval; no limit without a role |
| `elevated` | the broker script that runs the collector's elevated half | the script exists in `jarvis/platform/win/` |

Derived views: `schedule.ALL_JOBS`, `WINDOWS_ONLY` and `LINUX_ONLY`;
`scheduler.FAST`, `BULK` and `ISOLATED`; `governor.GOVERNED_JOBS`;
`score.AREAS` and `UNSCORED`; `reliability` tiers, timeouts,
`DEPENDENCIES` and `NON_EVIDENCE_JOBS`; `commands.JOB_COMMANDS`; the
collector part of `broker.SCRIPTS`; and the required and optional health
sources that `/api/health` and the dashboard both judge from
(`mechanisms.health_sources()`). `veil`, the opt-in browser sensor, is
not a collector. It is the one declared extra health source.

## Adding a collector

1. Write the audit and register its runner in `service/jobs.RUNNERS`.
2. Declare it in `mechanisms.COLLECTORS` with every field: a measured `cost_s`,
   its `command`, a `health` role if the service depends on it, `elevated` if
   the broker runs part of it, and a comment that says why its interval and
   lane are right.
3. Add its name to `ADDED_AFTER_GOLDEN` in `tests/test_mechanisms.py`.
4. Run `python3 -m unittest tests.test_mechanisms`. It refuses a collector with
   no runner, no command, no scoring decision or a broken budget.
5. If it changes the score, the owner decides first (score integrity).

## Keeping to the standard

`tests/test_mechanisms.py::TheCodebaseFollowsTheStandard` scans every module.
A tuple, list, set or dict that names three or more collectors outside the
registry fails the suite. A per-collector fact belongs on the declaration,
where conformance can check it. Four files are allowed such lists, each with
its reason written next to it in `ALLOWED_NAME_LISTS`:

- the composition root `jobs.RUNNERS`;
- the lane model's independent oracle;
- the assurance register's capability-to-evidence map, which is checked name by name;
- finding-category headings that share words with job names.

The same suite fails any wait or timeout measured with `time.time()`. The
wall clock here steps by about 9 s, which on 2026-10-23 alone accounted for four
"flaky" tests and one CLI wait (see the clock primitive).

## Where conformance runs

- **Unit suite:** `tests/test_mechanisms.py`, covering the golden views, wiring
  and every conformance failure path.
- **Verification ladder:** the `mechanism-conformance` property in
  `python -m jarvis.verify`, run by `scripts/dev/static_gate.sh`, by the daily
  `verify` job against the installed release, and by the Argus build
  (`archymedes-site/scripts/argus/build.py`, which already refuses a build whose
  verification fails) and the Argus installer's post-copy verification.

## Irregularities recorded, not changed

The registry made these visible on 2026-10-23. They are kept as they were,
because changing them changes live behaviour and needs its own measurement:

- `sysmon_linux` is tier 0/critical but runs on the main lane.
- `netwatch` is tier 1 fast liveness but runs on the frequent lane (main until 2026-11-03).
- `preos` and `containers` are unscored pending a scoring decision.
- `storage` had no scoring decision at all. It is now unscored like
  `resources`, which leaves the score unchanged, and maps to `status`.

## Design record

Alternatives compared:

- **(A) One declarative table with derived views and a golden test.** Chosen.
- **(B) Decorators next to each collector.** This spreads the contract back
  across 50 modules, and the views would depend on import order.
- **(C) Keep the eight tables and add an agreement test.** This detects drift
  but leaves eight places to edit.

A bounded Jev advisory (`scripts/reviews/mechanism_design_advisory.py`,
metadata only) chose A with probability 1.0. It also judged a live readback
still necessary beyond the golden test (0.84). Jev has no authority here; the
golden test and the live readback do.

Reconsider if collectors gain per-instance configuration (several instances of
one audit), or if a field needs to be computed from runtime measurement rather
than declared.

## Catalogue

### collector

A bounded audit of one ground: run_job(name) returns findings in the common shape and an observation status (complete, partial, unavailable) recorded with a receipt.

Invariants:

- Declared exactly once in COLLECTORS, with a runner in service/jobs.RUNNERS.
- A failure to observe is a visibility finding or partial status, never an empty clean result.
- Scored, or unscored with a written reason.
- Timeout below its interval, so a hang is caught before dependents go stale.

Failure looks like: the coverage view shows it failing or stale; score counts it blind.

Implemented by `jarvis/core/mechanisms.py`, `jarvis/service/jobs.py`, `jarvis/core/collection.py`; held by `tests/test_mechanisms.py`, `tests/test_score.py`.

### lane

A serial worker: fast (sub-second liveness), main (PowerShell interop), bulk (DrvFS and network). One job at a time per lane.

Invariants:

- Fast-lane jobs are never governed and finish in seconds.
- Each lane's measured duty cycle stays under LANE_DUTY_LIMIT.
- Starving jobs (past the hard deadline) are served first.

Failure looks like: lane age grows; protection health reports the lane stalled.

Implemented by `jarvis/service/scheduler.py`; held by `tests/test_mechanisms.py`, `tests/test_lane_fairness.py`, `tests/test_bulk_lane.py`.

### freshness budget

Evidence age against the declared interval: FRESH to 100%, LATE to 130%, DEGRADED to 200%, then STALE.

Invariants:

- No collector is STALE with nothing trying to recover it.
- An unknown age is STALE: no result is no result.
- A failed rerun never rewrites the last good snapshot as unsafe.

Failure looks like: the collector reads stale and coverage pages.

Implemented by `jarvis/service/reliability.py`; held by `tests/test_reliability.py`.

### clock

Two clocks with separate jobs: the monotonic clock measures durations, waits, timeouts and liveness; the wall clock stamps evidence that other processes compare.

Invariants:

- Every wait, timeout and age is measured on time.monotonic().
- A wall-clock step (the WSL clock fight steps ~9 s) never ends a wait early or declares a stall.
- Standby is not a stall: lane ages use the monotonic clock.

Failure looks like: a wait gives up early or a healthy collector reads stalled after a clock step.

Implemented by `jarvis/service/scheduler.py`, `jarvis/platform/procfeed.py`; held by `tests/test_mechanisms.py`, `tests/test_daemon_resilience.py`.

### lease

A worker's claim on one run that expires on its own, so a dead worker is detected by expiry rather than inferred minutes later.

Invariants:

- A lease always expires.
- One active lease per collector.

Failure looks like: an expired lease is recorded as a failed run.

Implemented by `jarvis/service/reliability.py`; held by `tests/test_reliability.py`.

### hold and retry

A transient failure inside the freshness budget keeps the last good result and retries after RETRY_S, at most HOLD_MAX times, then is recorded.

Invariants:

- Bounded: retries end and escalate.
- The held result is labelled as held, not fresh.

Failure looks like: after HOLD_MAX the failure is recorded and visible.

Implemented by `jarvis/service/scheduler.py`, `jarvis/service/reliability.py`; held by `tests/test_daemon_resilience.py`.

### governor deferral

Under CPU, memory, disk or battery pressure only governed collectors may wait.

Invariants:

- Tier 0 and fast-lane collectors are never governed.
- Deferral is recorded, never silent.

Failure looks like: deferred jobs are listed in protection health.

Implemented by `jarvis/core/governor.py`; held by `tests/test_mechanisms.py`.

### observation receipt

Every run writes a receipt with its coverage status beside its findings, so a clean report and no report never look the same.

Invariants:

- Partial or unavailable coverage is carried into the error and the score.

Failure looks like: collector coverage incomplete.

Implemented by `jarvis/core/store.py`, `jarvis/core/collection.py`; held by `tests/test_collection.py`, `tests/test_observation.py`.

### cursor

An incremental reader's resume point (record id, sequence) with gap detection: cleared logs start a new generation, overwritten ranges are recorded as gaps.

Invariants:

- A cursor never moves past unread evidence.
- Every gap is recorded with its range.

Failure looks like: a gap finding with the exact missing range.

Implemented by `jarvis/collectors/telemetry/sysmon.py`, `jarvis/platform/native/ingest.py`; held by `tests/test_sysmon_windows.py`, `tests/test_native.py`.

### hash-chained journal

Append-only records each carrying the previous record's hash; verify() names the first broken link.

Invariants:

- Append fails loudly; a caller that needs the record denies on failure.
- Records hold metadata and digests, never secret values.

Failure looks like: verify() returns the index and reason of the break.

Implemented by `jarvis/core/eventlog.py`, `jarvis/core/canary.py`, `jarvis/argus/journal.py`; held by `tests/test_continuity.py`.

### sealed release

Root-owned code under /opt/jarvis/releases run with python3 -I; switched atomically with the previous release kept for rollback.

Invariants:

- The running daemon never executes user-writable code.
- A release is accepted only on a live readback against a written baseline.

Failure looks like: the release refuses to switch, or rolls back.

Implemented by `scripts/deploy_root_runtime.py`, `jarvis/platform/provenance/release.py`; held by `tests/test_release_controller.py`, `tests/test_verify_models.py`.

### stream

A read-only, bounded push channel (Server-Sent Events) from one shared cached state.

Invariants:

- Read-only: no route back into the daemon.
- Bounded: MAX_STREAMS, MAX_LIFETIME_S, one shared rebuild per period.
- Blindness is never quiet: a failed or stale state is sent as such.

Failure looks like: the client shows unknown, never clean.

Implemented by `jarvis/web/stream.py`, `jarvis/web/procview.py`; held by `tests/test_stream.py`, `tests/test_procfeed.py`.

### helper

A long-lived Windows-side process started from the daemon (input hook, process feed) with a heartbeat and one instance at a time.

Invariants:

- Single instance.
- Heartbeat age decides liveness.
- Runs only with the least privilege it needs.
- Its compiled code is a reviewed script (collectors/process/assemblies.OWN_SCRIPTS).
- Demand-driven helpers stop when their last consumer leaves.

Failure looks like: the watchdog reports it deaf and restarts it within bounds.

Implemented by `jarvis/collectors/host/inputwatch/helper.py`, `jarvis/platform/procfeed.py`, `jarvis/platform/win/procfeed.ps1`; held by `tests/test_inputwatch.py`, `tests/test_procfeed.py`.

### gate

A deterministic decision before a consequential act (fix approval, Argus agent calls): fail closed, human authority bound to the exact act.

Invariants:

- Any failure denies.
- Approval is single use, expiring and bound to one digest.
- No allow without a durable journal record.

Failure looks like: a deny with its reasons in the journal.

Implemented by `jarvis/argus/policy.py`, `jarvis/argus/monitor.py`, `jarvis/response/selffix.py`; held by `tests/test_argus_monitor.py`, `tests/test_selffix.py`.

### advisory

Jev and local models: typed judgments that may rank or add friction.

Invariants:

- Never authorises, applies, suppresses or allows.
- Missing or uncertain output falls back to the deterministic path.

Failure looks like: unavailable is reported, and the safe path runs.

Implemented by `jarvis/response/jev.py`; held by `tests/test_jev.py`.

### verification property

An executable claim checked over generated cases or an exhaustive model, run by python -m jarvis.verify, the daily verify job and the Argus build gate.

Invariants:

- A failing property fails the build.
- Cases are replayable by seed and index.

Failure looks like: the build stops and names the property.

Implemented by `jarvis/verify/properties.py`, `jarvis/verify/report.py`; held by `tests/test_verify_props.py`.

