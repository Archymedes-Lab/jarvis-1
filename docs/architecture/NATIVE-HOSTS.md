# Native hosts: JARVIS without WSL (2026-10-03)

JARVIS was written as a Linux process inside a WSL guest that reaches its
Windows host through interop and `/mnt/c`. This records how the same code now
runs on a Windows machine with no WSL (and on Linux with no Windows host), what
was measured, and what is still unproven. It is not a claim that the native
install is validated: `native_host_portability` is `unverified` in
`jarvis/core/assurance.py`.

## Baseline (measured)

- `import jarvis.cli` failed under native Windows Python 3.13 (`pwd`, `fcntl`).
- No module checked the platform. 108 modules named WSL; 20 sites built
  `/mnt/c/...` paths or called `wslpath`; supervision assumed systemd.
- The Windows collectors themselves are PowerShell payloads that already run
  on Windows. Only their transport (interop) and the paths around them were
  WSL-specific.

## Invariants

1. **WSL is unchanged.** Same schedule in the same order, same paths, same
   finding identities. Finding labels stay `wsl` / `win`.
2. **Absent is not applicable.** A domain that does not exist on the machine is
   never scheduled, scored, reported healthy or reported failed. The absence is
   stated in the coverage audit.
3. **No credit for the unobserved.** Removing a job from the schedule can never
   raise an area to healthy; a machine with nothing observed scores 0.
4. **Unknown stays unknown.** A path that cannot be mapped maps to nothing. A
   file whose privacy cannot be proven is not private.
5. **One event-log writer** on every platform, released by the handle closing.
6. **Asking is not acting.** No liveness probe may signal or stop a process.
   `os.kill(pid, 0)` is a Ctrl+C event on Windows and any other signal
   terminates; neither is reachable there.
7. **Supervision from outside, both ways, bounded.** Something outside the
   daemon restarts it, at most 3 times in 15 minutes; the daemon reports when
   that supervisor is missing, silent, paused, spent, or watching another pid.
8. **No new authority.** Install needs no elevation and changes no Windows
   policy, firewall rule or service. PowerShell is resolved from System32,
   never from `PATH`.

Executable checks: `tests/test_native_hosts.py` (36 tests, success and failure
paths for each invariant) and the declared-task mutation tests in
`tests/test_managed_persistence.py`, which cover the new task automatically.

## Design

Compared:

| Design | Result |
|---|---|
| **One platform seam** (`jarvis/platform/host.py`) | Selected. One place decides the execution domains, PowerShell transport, path mapping and supervision; collectors keep their `hosts` argument. |
| Separate Windows edition | Rejected: duplicates every Windows collector and its detection logic, and the two copies drift. |
| Compatibility shim faking `/mnt/c` and `/proc` on Windows | Rejected: it would present a topology that does not exist, which is the failure invariant 2 forbids. |

What the seam decides:

- `host.KIND` is `wsl`, `windows` or `linux`; `host.domains()` is the tuple of
  finding labels observable from here. The CLI's `--host all`, the daemon and
  the scheduler take their hosts from it. `--host wsl` on native Windows is
  refused rather than answered with "nothing found".
- `service/schedule.py` keeps every audit in `ALL_JOBS`. `JOBS` is the part
  that applies here and `NOT_APPLICABLE` names the rest with a reason. The
  score already ignores jobs outside the schedule, so nothing else changed.
  Linux-only: `auditd`, `sysmon_linux`, `containers`. Windows-only: the 17
  jobs in `WINDOWS_ONLY`.
- `platform/windows.py` starts `powershell.exe` directly on Windows, with no
  window, from the system directory, and through interop under WSL.
- `core/filelock.py` is `flock` on POSIX and a byte-range lock on Windows.
- `jarvis-native-service.ps1` is systemd and the reviver in one scheduled-task
  loop: it owns the daemon process, restarts it when it exits or stalls, and
  writes the state file `supervisors.audit_native_service` reads. It is a
  declared managed task, so the control audit verifies its exact arguments and
  script fingerprint like the others.
- `quickstart.ps1 -Native` installs it; it is chosen automatically when the
  copy is on a local drive and the distro does not exist.

Costs: no new process, thread or dependency under WSL. Natively one extra
PowerShell loop (a health request every 5 s) replaces systemd.

Reconsider the seam if a third execution domain appears (macOS, a container
host), or if native Windows needs detections that have no PowerShell form and
would be better as a native sensor feature.

## Measured on 2026-10-03

One Windows 11 machine that also has WSL, from an isolated copy under `%TEMP%`
with its own JARVIS home, using native Python 3.13:

| Check | Result |
|---|---|
| `tests/test_native_hosts.py` natively | 36 run, 34 pass, 2 POSIX-only skipped |
| Full suite natively | 1973 run, 1661 pass before the evidence-path fixes; the rest assume POSIX (symlinks, mode bits, `/proc`, signals, open files deleted in teardown) |
| 32 read-only collectors, one pass each | all complete (`sysmon` partial: capped query), every finding labelled `win` |
| Daemon on a spare port, read-only jobs | HTTP up, `live=true`, `healthy=false` for the sources left out |
| Supervisor loop against a stand-in daemon | started it, restarted after a kill, replaced a stalled one, stopped acting at the budget |
| Full suite on Linux | see the release notes for this change |

## Not done, not claimed

- Never installed or run on a machine without WSL, and never as the registered
  task. The live install on the test machine was not touched.
- The native sensor ingest, input hook, evidence vault, Rust mirror, mail,
  intel and feed jobs were excluded from the native daemon run because they act
  on the live install. They are unverified natively.
- About 300 unit tests assume POSIX and fail on Windows. The Linux suite is the
  regression gate; the Windows run is a measurement, not a gate.
- NTFS access-control lists are not inspected. `core/fsperm.py` therefore
  never calls a file private on Windows: credential findings are not
  downgraded, and `~/.jarvis/typesafe.env` and similar key files are ignored
  (use the environment variable).
- Directory entries are not fsynced on Windows (file data is).
- Quarantine and suspend remain Linux-only; on Windows they decline.
- Git-hook, agent-hook and package-config checks walk the Linux home only.
- Some Linux-domain modules still label their own findings `wsl` by default;
  they are not reachable when the Linux domain is absent.
- Plain Linux (no Windows host) is covered by unit tests only.
- The health monitor, connectivity guard, elevated broker and sensor installer
  are plain Windows scripts and should work natively, but were not run that way.
