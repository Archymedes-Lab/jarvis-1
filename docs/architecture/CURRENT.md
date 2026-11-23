# Jarvis architecture: as found (2026-09-14, baseline 4eea27a)

Measured with an AST import walk over `jarvis/` and grep over scripts, units,
docs and the dashboard. Numbers are for the baseline commit.

## Size and shape

- 103 Python modules, 23,234 lines. 49 modules sit flat in `jarvis/`; 11
  subpackages (`cli`, `evidence`, `hidden`, `impersonation`, `inputwatch`,
  `native`, `pixel`, `reporting`, `toolchain`, plus `static/` and `win/` data).
- Largest modules: `server` 807, `alert` 699, `intel` 698, `sysmon_linux` 688,
  `hunt` 673, `spyware` 664, `control` 637, `store` 613, `posture` 584.
- Tests: 39 files, 354 tests, stdlib `unittest` (pytest is not installed).
- Top level: 17 `*.ps1`, 6 `*.sh`, 11 `*.md` (3 of them dated session reports).

## Layers that exist implicitly

| Role | Modules |
|---|---|
| Storage and helpers | store, util, collection, retention |
| Platform access | collect_linux (/proc), collect_windows (interop), `control._ps_json` / `control._aslist` (the de-facto PowerShell runner), win/*.ps1 |
| Process and telemetry collectors | monitor, detect, hidden/, memscan, evasion, resourcewatch, sysmon, sysmon_linux, auditd |
| Persistence and control collectors | asep, startup, flash, control, implant, backdoor |
| Network collectors | firewall, netwatch, internetwatch, sniffing, webshell |
| Identity collectors | bruteforce, secrets, impersonation/ |
| Host collectors | posture, spyware, inputwatch/, intrusion, toolchain/, controlwatch, pixel/ |
| Threat intel | feeds, intel, hunt, vet |
| Response | alert, remediation, repair, fixit, ledger, evidence/ |
| Reporting | reporting/ |
| Service and self-supervision | server (scheduler, job dispatch, HTTP), coverage, selfcheck, supervisors, connectivity, protection, sdnotify |
| Interfaces | cli/, server HTTP handler, static/dashboard.html |
| Sensor ingest | native/ |

## Smells

1. **The PowerShell runner lives in a collector.** 25 modules import
   `_ps_json` and 14 import `_aslist` from `control.py`, a persistence
   collector. Every Windows collector depends on another collector's
   private helpers.
2. **157 imports of private names.** Besides the two above:
   `collect_linux._read/_socket_table` (firewall, hidden),
   `cli.output._tty/_hosts/_report/_print_finding/_simple_cmd` (CLI commands,
   impersonation, pixel), and `alert._key` (remediation). The rest (about 110)
   are package-internal: `toolchain/common`, `inputwatch/common|helper`, and
   `hidden/common|views`.
3. **Two import cycles.** `alert` ↔ `reporting.notifications`, and
   `coverage` ↔ `server` (coverage needs `JOBS`, server runs coverage).
   Both are hidden behind function-local imports.
4. **29 function-local imports.** Most of them hide the cycles or the
   upward/sideways dependencies above. One is `__import__(f"jarvis.{name}")`
   in `hunt._intercept_active`.
5. **Paths built from `__file__` in six places** (`server`, `control` ×3,
   `remediation`, `memscan`, `flash` ×2, `inputwatch.common`), each hard-coding
   its own depth. `tests/test_imports.py` records a regression this caused
   earlier.
6. **`server.py` does three jobs.** It holds the job table, a 270-line
   `if name == …` dispatch, the scheduler thread, and the HTTP handler, and
   imports 45 modules.
7. **Collectors importing collectors.** For example `resourcewatch → monitor`,
   `auditd → sysmon_linux`, and `hunt → auditd/sysmon_linux`.
8. **Root clutter.** Operator scripts, installers, and dated reports are mixed
   together at the top level.

## External contracts (must not break)

- `python3 -m jarvis …`: `install.sh`, `quickstart.*`, systemd units, and
  PowerShell tasks.
- `python3 -m jarvis.flash` and `python3 -m jarvis.native` (documented).
- `jarvis-wake-watchdog.ps1`, `jarvis-health-monitor.ps1`, and `jarvis-connectivity-guard.ps1` are
  hashed by `control.py` to verify the installed Windows tasks.
- Finding `(category, severity, title, detail, host)` → `alert._key` identity,
  DB schema, config keys, and meta keys.
