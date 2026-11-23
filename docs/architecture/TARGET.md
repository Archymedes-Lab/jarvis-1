# Jarvis architecture: as built

Status: restructure complete on branch `restructure/2026-09-14`, from baseline
`4eea27a` (see `CURRENT.md` for the state before). This document records the
layout, the rules that hold it in place, and what changed from the original
plan.

For the defender engine's runtime contracts, incident foundation, and broader
product direction, see [DEFENDER-ENGINE.md](DEFENDER-ENGINE.md). That design
builds on the dependency boundaries recorded here.

## Layout

```
jarvis/
  core/          store, schema, retention, collection (observation accounting),
                 event + eventlog (canonical events, the temporal log),
                 finding (the common finding factory), vet + vet_lists (indicator validation),
                 paths, util
  platform/      linux (/proc), windows (interop + the one PowerShell runner),
                 win/*.ps1 payloads, native/ (sensor spool ingest + normalization)
  collectors/
    signatures.py  detection knowledge shared across domains (REMOTE_AGENTS)
    process/       monitor, detect, hidden/, memscan, evasion, resourcewatch
    telemetry/     sysmon, sysmon_linux/, auditd
    persistence/   asep, startup, control, trusted_tasks, implant, backdoor
    network/       firewall, netwatch, internetwatch, sniffing, webshell
    identity/      bruteforce, secrets, impersonation/
    host/          posture/, spyware/, inputwatch/, intrusion/, toolchain/,
                   controlwatch, pixel/
  intel/         research (was intel.py), corpus, feeds, hunt, gaps
  response/      alert (delivery policy + transport), remediation, fixit, ledger,
                 flash (startup tracing), evidence/,
                 reporting/ (notifications, advisory, cadence, commands, diff)
  service/       schedule (job table), jobs (runner), scheduler, coverage,
                 selfcheck, supervisors, connectivity, protection, sdnotify
  lab/           JARVIS Arena: adversarial validation (scenario, isolation,
                 scoring, regression, runner, providers/, intel candidate boundary)
  web/           server (dashboard state + HTTP), static/
  cli/           parser, output, commands/ (incl. evidence, pixel,
                 impersonation, repair, retention front ends)
scripts/         harden/, repair/, maintenance/, dev/behavior_snapshot.py
docs/            architecture/, guides/, reports/
```

Kept at the repository root on purpose:

- `install.sh`, `quickstart.sh`, `quickstart.ps1`, `jarvis.sh`, `README.md`,
  `QUICKSTART.md`: the documented entry points.
- `jarvis-wake-watchdog.ps1`, `jarvis-health-monitor.ps1`, `jarvis-connectivity-guard.ps1`: the
  installed Windows tasks self-sync from `<RepoRoot>\<name>`, and
  `control.py` hashes them there. If one moved, the deployed copy would log
  "self-sync skipped" and silently stop receiving fixes.
- `systemd/`, `sysmon/`, `windows-sensor/`: conventional, and referenced by
  the installers and by finding text.

## Dependency rules (enforced by `tests/test_layers.py`, no exceptions)

`core` 0 < `platform` 1 < `collectors` 2 < `lab` 3 < `intel` 4 < `response` 5
< `service` 6 < `web` 7 < `cli` 8

1. A module imports only from its own layer or a lower one.
2. Collector domains don't import each other. Knowledge they share lives in
   `collectors/signatures.py` or lower.
3. A leading-underscore name is never imported from outside the package that
   defines it.
4. There are no import cycles, including through function-local imports.
5. Every module belongs to a layer.

## Deviations from the original plan, and why

| Plan | Built | Reason |
|---|---|---|
| `reporting/` as its own layer above `response` | `response/reporting/` | Alerting and reporting depend on each other, so as separate layers they could only be wired with a cycle. |
| `intel/vet` | `core/vet` | A collector (sysmon) validates domains with it. It's pure stdlib. |
| `collectors/persistence/flash` | `response/flash` | It writes evidence cases. It's a forensic capture tool, not a scheduled collector. |
| `deploy/systemd`, `deploy/sysmon` | left at root | Moving them only changes user-facing instructions and finding text. |
| Watchdog payloads into `scripts/` | left at root | Installed-copy self-sync contract (see above). |
| Ban all cross-module private imports | Scoped to package boundaries | 90 of the remaining underscore imports are package-internal helpers in cohesive subpackages. Renaming them is churn without a boundary gain. |

## Results

| | Baseline | Now |
|---|---|---|
| Modules in `jarvis/` root | 49 | 2 (`__init__`, `__main__`) |
| Import cycles | 2 | 0 |
| Private names imported between modules outside their own subpackage | 49 | 0 |
| Function-local imports | 29 | 2 (CLI startup cost, commented) |
| Layer or domain rule violations once the layout existed | 3 (firewall→control, flash→evidence, sysmon→vet) | 0 |
| Finding factories | 18 identical copies + variants | `core/finding.py` + genuinely different variants |
| PowerShell runner | private helper in a collector (`control._ps_json`) | `platform.windows.ps_json` |
| `server.py` | 807 lines: job table, 270-line `if` dispatch, scheduler, HTTP | `service/schedule`, `service/jobs` (dispatch table), `service/scheduler`, `web/server` |
| Largest modules | server 807, alert 699, intel 698, sysmon_linux 688 | secrets 518, research 516, netwatch 493 (see FOLLOWUPS) |
| Tests | 354 | 362 (layer rules, job registry) |
| Lint (`uvx ruff check`, F + E9 + I) | not configured | clean |

Verification after each step: the full unittest suite; `scripts/dev/behavior_snapshot.py`,
where CLI help for all 52 commands was identical throughout and every string
literal change was reviewed; `compileall`; and, after structural steps, a
restart of the live daemon. Every job's stored snapshot was checked for errors
after the first restart on the new layout and again on the final commit.

## Performance (measured, no change made)

Scheduler duty cycle is 22.9% of one worker. The three largest shares are
`netwatch` (10.4 s / 300 s), `scan` (2.0 s / 60 s) and `hidden` (9.3 s / 300 s).
Profiling each shows that a single, already-batched PowerShell call takes
90–99% of the time (6.76 of 6.82 s, 1.88 of 2.07 s, 9.64 of 10.66 s). Python-side
work is under 0.5 s and SQLite is milliseconds. No Python-side optimization
would be measurable. Reducing the Windows query cost means changing detection
queries, which is out of scope for a behavior-preserving refactor.
