# Windows supervisor names and the 2026-09-28 rename

Every Windows-side supervisor script is named after the scheduled task it
installs, with a `jarvis-` prefix so the family sorts together:

| Scheduled task | Script (repo root) | Installed copy | Was |
| --- | --- | --- | --- |
| JARVIS independent health monitor | `jarvis-health-monitor.ps1` | `%LOCALAPPDATA%\Jarvis\HealthMonitor\` | `deadman-jarvis.ps1` in `Jarvis\Deadman\` |
| jarvis wake watchdog | `jarvis-wake-watchdog.ps1` | `%LOCALAPPDATA%\WSLKeepalive\` | `wake-jarvis.ps1` |
| jarvis reviver | `jarvis-reviver.ps1` | `%LOCALAPPDATA%\Jarvis\Reviver\` | `revive-jarvis.ps1` |
| JARVIS connectivity guard | `jarvis-connectivity-guard.ps1` | `%LOCALAPPDATA%\Jarvis\Connectivity\` | `connectivity-jarvis.ps1` |
| jarvis elevated broker | `jarvis-elevated-broker.ps1` | `C:\ProgramData\Jarvis\Broker\` | `broker-jarvis.ps1` |

The WSL side that reads their state is `jarvis/service/supervisors.py`
(was `deadman.py`): `audit_health_monitor`, `audit_reviver`, `audit_broker`.
Task names and finding titles did not change. The only installed folder that
moved is the health monitor's (`Deadman` to `HealthMonitor`); the others keep
their folders, so their state and logs continue in place.

## Invariants

1. **No false critical.** A genuine, unmodified task still on the old layout
   verifies; renaming files in a release must not turn JARVIS's own
   persistence into critical findings.
2. **Tamper detection is not relaxed.** The old layout is accepted only with
   its exact old arguments *and* the exact fingerprint of the old script as it
   shipped in the sealed release `20260925T140154Z-959cff948858`. Principal,
   run level, logon type and single-action checks apply unchanged. Old and
   new arguments and fingerprints cannot be mixed.
3. **Monitor liveness evidence is continuous.** The health monitor's state is
   read from `Jarvis\Deadman` only while `Jarvis\HealthMonitor\state.json`
   does not exist. Once it does, a stale new file is reported as a stall; it
   is never masked by the old folder.
4. **Recovery and rollback.** `-Install` copies `mail.json` and `state.json`
   forward and never moves, deletes or overwrites; the old folder and old
   script remain the rollback. The broker's old copy stays usable only while it
   matches the pinned fingerprint.
5. **Explicit authority.** Nothing here re-registers a task by itself. The
   installed old copies of the wake watchdog and reviver self-sync by file
   name; their source name is gone, so they skip the sync and keep running
   their current reviewed code until a human re-registers them.

`tests/test_supervisor_names.py` exercises each invariant, both success and
failure paths.

Measured in Windows PowerShell 5.1 on 2026-09-28, against throwaway copies
with task registration and process hand-over stubbed out:

- The old wake watchdog and reviver sync blocks, whose source file no longer
  exists, skip the sync and leave the installed copy unchanged. The wake
  watchdog logs `self-sync skipped` every run until it is re-registered.
- The new scripts pass their own self-sync gates and re-stage themselves.
- `Copy-LegacyState` copies only missing files, never overwrites, and is idempotent.

## Design choice

| Design | Outcome |
| --- | --- |
| Hard cutover (new layout only) | Five genuine tasks read critical, and the monitor reads "never run", from deploy until every task is re-registered, one of them needing UAC. Rejected: it breaks invariants 1 and 3. |
| Keep the old installed names permanently | No transition, but the repo and the machine disagree about names forever. Rejected: it fails the purpose of the rename. |
| **Pinned transition (chosen)** | New names everywhere, plus a time-bounded table of old layouts pinned to exact reviewed fingerprints (`persistence.LEGACY_LAYOUTS`). |

Jev advisory reviews (jev-1.13.0, metadata only; no scripts, paths or
credentials were sent). Design comparison:

- **Design:** Choice picked the pinned transition, confidence 0.99.
- **Pinned acceptance weakens tamper detection:** Noul 0.24.
- **Time-bound the legacy acceptance:** 0.92.
- **Copy rather than move:** 0.74.
- **Top remaining gap:** Choice picked the live task readback, confidence 0.80.

The one residual weakening, recorded here, is that during the transition a task
could be re-registered back to the exact old reviewed script: a downgrade
to reviewed code, not arbitrary code. Removing the table closes it.

After implementation, Jev reviewed the measured test and collector results:

- **Sound to deploy before re-registration:** Noul 0.47, which is uncertain.
- **Weakest evidence:** post-migration readback (0.46), then self-sync of the
  new scripts (0.31) and old copies surviving a missing source (0.22). The
  self-sync measurements above closed the last two. Readback is the owner
  acceptance gate below.
- **Collector most at risk:** control-audit task verification (0.63), then the
  health monitor's state (0.34). Both were measured live, but only on the old
  layout.
- **Side effects acceptable if documented:** 0.67. When the monitor is
  re-registered, its ok finding changes identity (new `where` path) once.

Reconsider the design if a supervisor must keep its old folder for other
reasons, or if a transition longer than one release cycle becomes necessary.

## Migration (owner-run)

Deploy the release first. Measured before deploy on 2026-09-28: all five
installed copies matched the sealed release, and with this code all nine
managed tasks verify (five as "pre-rename ... re-register it on the new
layout"). The supervisor audits read ok.

Re-register from Windows PowerShell in the checkout, one at a time, reading
each back before the next:

```powershell
$repo = '\\wsl.localhost\Ubuntu\home\chris\jarvis'
# 1. health monitor: copies itself, its state and the DPAPI mail config into
#    Jarvis\HealthMonitor, then re-registers the same task name
powershell -ExecutionPolicy Bypass -File "$repo\jarvis-health-monitor.ps1" -Install
# 2. connectivity guard (use the same -InterfaceName/-ProfileName as before)
powershell -ExecutionPolicy Bypass -File "$repo\jarvis-connectivity-guard.ps1" -Install -InterfaceName 'Wi-Fi'
```

Then, from WSL: `./install.sh` stages and registers `jarvis-wake-watchdog.ps1`
and `jarvis-reviver.ps1`; `jarvis broker install` restages the broker (one UAC
prompt). Finally, `powershell -File scripts\maintenance\apply-headless-monitors.ps1 -RepoRoot <repo>`
restores the conhost `--headless` wrapper where an installer registered without it.

**Acceptance (live readback, not command success):**

- Force the control audit (`curl -X POST "http://127.0.0.1:8787/api/run?job=control"`)
  and read its fresh snapshot: every managed task is a low "verified scheduled
  task" reading "exact task definition and script fingerprint verified", none
  says "pre-rename", and none is critical. (`jarvis provenance persistence`
  prints only the expected definitions, not the live ones.)
- `Jarvis\HealthMonitor\state.json` has a `checkedAt` within the last two
  minutes, and `jarvis selfcheck` shows the Windows monitor checking.
- `jarvis-health-monitor.ps1 -TestNotification` produces a toast. Mail is
  proven only by the next real delivery, or by `mailError` staying empty.
- The broker finding reads "feeding privileged read-only evidence".

**Rollback:** re-run the old installed copy's own `-Install` (for example
`%LOCALAPPDATA%\Jarvis\Deadman\deadman-jarvis.ps1 -Install`). The old copies
and state were left in place, and the verifier still accepts them.

**Finish the transition:** once every task reads back on the new layout,
remove `LEGACY_LAYOUTS`, `LEGACY_STATE` and `LEGACY_BROKER_SCRIPT` in a
reviewed release, together with their tests. Then delete the old copies:
`Jarvis\Deadman` (it holds the DPAPI mail key), `WSLKeepalive\wake-jarvis.ps1`,
`Jarvis\Reviver\revive-jarvis.ps1`, `Jarvis\Connectivity\connectivity-jarvis.ps1`,
and `ProgramData\Jarvis\Broker\broker-jarvis.ps1`.
