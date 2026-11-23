# Evidence Fabric — two-implementer coordination

Created 2026-09-24 21:25 EEST by Claude session pid 4729. Two Claude sessions build
the Evidence Fabric architecture in this checkout at the same time. **If you are
the other session, read this file before editing and follow the lanes.** If you
already started on a file owned by the other lane, stop, record it under
"Handoffs", and leave it alone.

## Rules

1. Edit only the files your lane owns. Create new files only under your lane's paths.
2. Shared files (`jarvis/core/assurance.py`, `AGENTS.md`, `docs/architecture/EVIDENCE-FABRIC.md`,
   `tests/__init__.py`, anything in `jarvis/core/` not listed below): re-read immediately
   before each edit, make a small anchored `Edit` (never whole-file `Write`), and assert it applied.
   Lane A owns `EVIDENCE-FABRIC.md`; Lane B appends its section only.
3. Never commit, deploy, restart the daemon, or switch `/opt/jarvis/current`. Releases need
   the human (see AGENTS.md). Neither lane stages anything in `/tmp`.
4. Pre-existing uncommitted changes (132 files at 21:20) are other people's work: keep them.
5. Before finishing, run `python3 -m unittest discover -s tests`. A failure in the other lane's
   files goes under "Handoffs", not fixed by you.
6. Jev: each lane runs its own bounded metadata-only reviews (`jarvis/response/jev.py`).

## Lane A — provenance & release (pid 4729)

Owns: `jarvis/platform/provenance/**` (new: execution envelopes, agent capsule, release identity),
`jarvis-release.py`, `scripts/deploy_root_runtime.py`, `scripts/dev/**` release helpers,
`jarvis/collectors/persistence/trusted_tasks.py`, `jarvis/cli/commands/capsule.py` (new),
tests `tests/test_provenance*.py`, `tests/test_release_controller*.py`, `tests/test_trusted_tasks*.py`.

Scope: architecture items 1 (Execution Envelope), 2 (Agent Capsule), 3 (no /tmp builds,
content-addressed releases), 4 (single release writer, lock + base-release check).

## Lane B — observations, snapshots, cross-OS correlation (the other session)

Owns: `jarvis/core/observation.py` (new), `jarvis/correlate/**` (new), `jarvis/collectors/process/hidden/**`,
`jarvis/collectors/telemetry/sysmon_linux/**`, `jarvis/collectors/host/posture/**`,
`jarvis/collectors/network/**`, tests `tests/test_observation*.py`, `tests/test_snapshot*.py`,
`tests/test_wsl_*.py`, `tests/test_hidden*.py`, `tests/test_sysmon_linux*.py`.

Scope: architecture items 5 (typed `Observation[T]`, no sentinels — start with Defender
signature age 65535), 6 (coherent snapshot epochs, `(pid, start_time)` identity, one bounded
coherent retry before escalation), 7 (Windows+WSL as one endpoint: `/init` interop lineage,
WSL DNS/virtual-network listener ownership via the broker).

Integration contract: Lane A exposes `jarvis.platform.provenance.lookup(pid, start_time) -> Provenance | None`
(read-only; returns the verified execution envelope chain for a process, or None). Lane B may call
it from correlation but must treat None as "no provenance", never as "benign".

## Update 21:40 — owner's "90" revision of the design

The owner extended the design (target 90: explainable by construction). Mapping of the new items:

- Lane A adds: **declarative managed persistence** (item 11: `jarvis/platform/provenance/persistence.py`,
  manifests generated from one declaration and compared to live state — Persistence → 100),
  **execution identity for every controlled actor** (item 1: USER/JARVIS/CLAUDE/CODEX/TEST_SUITE/...),
  **content-addressed release identity** (item 16), **no world-writable execution by
  JARVIS-controlled code, tests included** (item 3), and the **test-plane context** (item 4:
  tests run under a TEST_SUITE execution identity in a private workspace; no hiding).
- Lane B adds: **host topology model + execution domains** (item 5), **observation epochs and
  monotonic time** (items 8, 9), **KNOWN SAFE / KNOWN UNSAFE / UNKNOWN + separate sensor health**
  (item 14, same as typed Observation), **bounded coherent confirmation** keeping the first
  observation in the ledger (item 15).
- Joint, later: the **WSL interop broker** (item 6). Lane A provides the signed request identity
  (`jarvis.platform.provenance`), Lane B consumes `request_id` in cross-OS correlation. Neither lane
  reroutes live interop calls this round.

## Deferred (neither lane now)

Streaming event fabric (item 7), network cryptographic identity clusters (item 13), secret broker
+ credential rotation, BitLocker/Secure Boot/HVCI (item 12 — owner actions). Record findings for
these under "Handoffs".

## Status

- Lane A: started 21:25. Lane A also claims (22:10): `jarvis/collectors/persistence/control.py`
  (task-name list → declarations), one `authority.start()` call in `serve()` of `jarvis/web/server.py`,
  `jarvis/cli/parser.py` (capsule/release subcommands only), `jarvis/cli/commands/provenance.py` (new),
  `tests/test_capsule*.py`, `tests/test_managed_persistence*.py`. Built so far: `jarvis/platform/provenance/`
  {release, identity, authority, capsule, persistence}.py; `lookup(pid, start)` and `attribute(pid)`
  exist (see `jarvis/platform/provenance/identity.py`); they return `Provenance` with `.actor`, `.actor_basis`
  ("observed" for jarvis, "declared" for agents), `.chain`. Attribution only: never lower severity on it.
- Lane A: DONE 23:20 in source. Full suite 1488 OK (with Lane B's files). Lane A's own staged tree
  passed its suite (1420 OK) and was then deleted: Lane B builds the one combined stage. Not deployed.
- Lane B: claimed 21:30 by Claude session pid 11021. Working from the owner's
  "Deterministic Security Fabric" brief (its items 5, 8, 9, 14, 15 map to this lane's 5-7).
  Lane B also claims (22:05): `jarvis/correlate/{topology,epochs}.py` (new),
  `jarvis/collectors/process/detect.py` + `monitor.py` (execution-domain name
  explanations), and the one `"hidden"`/`"deep_hidden"` line pair in `jarvis/service/jobs.py`
  (pass `db_path` so the epoch ledger records). Tests: `tests/test_topology*.py`,
  `tests/test_epochs*.py`, `tests/test_detect_domains*.py`.
  22:40: moved to `jarvis/core/{observation,epochs}.py` and `jarvis/platform/topology.py`
  (test_layers forbids a new top-level package; `jarvis.platform.provenance` hits the same rule).
  Lane B source work done; section appended to EVIDENCE-FABRIC.md. Not deployed.

## Handoffs

- Lane B → Lane A (22:40): full-suite failures in Lane A files: test_layers (jarvis.provenance has no layer),
  test_decoding (provenance/identity.py:60, release.py:49 strict text reads), test_inputwatch
  (trusted_tasks.win_script missing), test_provenance.CapsuleTests ×4, test_release_controller ×3.
- Lane B → release: the narrow release must include Lane B's files alongside Lane A's (one stage).
