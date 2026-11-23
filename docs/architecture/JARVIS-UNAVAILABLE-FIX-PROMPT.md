# Prompt: make "JARVIS unavailable" mean unavailable, and stop the causes

Measured 2026-10-12 00:15–01:15 EEST (WSL time; Windows logs are one hour behind).
Sources: the reviver log, which holds 2026-10-04 onwards, `defender_runs`/`defender_incidents` in `~/.jarvis/jarvis.db`,
the Windows System and Hyper-V-Worker logs, `timedatectl timesync-status`, the
`jarvis.service` cgroup, and a live latency probe on `/api/health`/`/api/state`.

**1. What the owner actually sees, and why.** "JARVIS monitoring unavailable" is a
toast and mail from the Windows independent health monitor. That monitor fires whenever
`/api/health` returns 503 for 60 s or more, after a 180 s grace given to a working
reviver. The daemon answers 503 whenever any *required* source (scan, bridge, sysmon,
native) is not `complete`. That covers the daemon being down, but it also covers a
daemon that is running and only has one source degraded. The last toast (2026-10-12
00:51) was the second case. The daemon was up and its API answered in under 3.4 s
throughout. Meanwhile `native` had been reporting partial on most passes since boot,
because the Windows sensor logged "The sensor cannot read Sysmon:
EventLogException: timeout period expired" (463 recurrences since 2026-09-21).
`sysmon` was also draining a post-boot backlog of 213k records. The scheduler's
transient hold masked the first failures and then, correctly, recorded "collector
coverage incomplete". The 503 followed and the monitor reported it as "unavailable".
Separately, the reviver log shows eight restart storms between 2026-10-04 and
2026-10-11. In each one the daemon was "active but silent" for 90–400 s during a cold
start or memory stall, the reviver restarted it three times in 15 minutes, which reset
the catch-up each time, and then it gave up with "needs a human". Before the fix, the
longest outage was a 4 h gap (2026-10-11 19:21–23:17 Windows time) in which the laptop
was asleep. The causes outside the daemon are Windows sleep, Kernel-Power 41 hard resets,
host-commit "fatal machine check" panics, and C: filling up. They are real, but most of
them are owner or hardware matters.

**2. Root cause in the sensor (fix it at the source).** `windows-sensor/JarvisSensor.cs`
resumes every pass with the XPath query `*[System[EventRecordID>N]]`. Windows evaluates
that predicate from the oldest record forward, so the first read costs time proportional
to the log size. Measured on the 256 MB, 208,860-record Sysmon log: 770 ms to reach the
first event on an idle host. Under the 228% CPU pressure the governor reported, it runs
past 2 s × 3 attempts and throws ERROR_TIMEOUT. Replace it with a positional resume:
open the channel with `*`, `Seek(SeekOrigin.Begin, after+1-oldest)`, read the first
record, skip forward while `RecordId <= after`, and seek backwards when the landing
record is past `after+1`. The index-to-record-ID mapping is not exact; it landed 43
records short in the measurement. Measured cost: 26 ms to the first record, then
195 ms for 2,000 reads. Bound every correction. Fall back to the old XPath path
(which is correct but slow) only when the bounded correction cannot converge. Keep the
cursor, the gap and wrap detection, and the "a timeout is not EOF" rule exactly as they
are.

**3. Supervisors must not amplify outages or mislabel them.** Change the reviver
(`jarvis-reviver.ps1`) so that it never counts a daemon as hung during its first
`StartGrace` seconds (300) after `ActiveEnterTimestamp`. systemd's WatchdogSec=900 and
the out-of-daemon selfcheck timer stay as backstops, so a daemon that never comes up is
still restarted. Back off per-source `/api/run` kicks exponentially (30 s up to 600 s),
and do not kick a source whose status is `partial`: re-running a collector does not
repair a sensor that reports partial coverage, it only adds load. Change the health
monitor (`jarvis-health-monitor.ps1`) so that a live daemon with degraded required
sources is reported as **"JARVIS coverage degraded"**, naming each source and its
reason. "Monitoring unavailable" stays for an unreachable or stalled daemon. Both
remain toasts and mails with the same confirmation and escalation timing. Nothing is
suppressed and no gate is weakened: `/api/health` semantics and the 503 are unchanged.

**4. Invariants and evidence (write the tests before trusting it).** The invariants are:
- Evidence continuity: no event is skipped. The first record emitted is the lowest
  RecordId greater than the cursor, or the oldest record with an explicit gap.
- Cursor integrity: a timeout or a failed correction leaves the cursor untouched.
- Bounded resource use: a fixed limit on seeks and skips per pass.
- Explicit authority: supervisors may restart only an unhealthy unit past its grace
  period, within the existing budget of 3 restarts in 15 minutes.
- Honest health: an unreachable daemon and a degraded source are distinct states, and
  both stay visible.

Add C# regression tests covering a log with record-ID gaps, a landing point short of
the target, a landing point past it, a wrapped cursor, an empty log, a cursor at the
newest record, and a correction budget that runs out. Run them with the .NET Framework
`csc` on Windows, as the existing `TimeoutRetry` test does. Measure the real Sysmon
channel before and after. Run `python3 -m unittest discover -s tests` and get a bounded
metadata-only Jev advisory on the design and the implementation. Jev is advisory only.

**5. Out-of-code causes and the owner-only steps (report them, don't fake them).**
- Clock: the WSL clock steps back 2.47 s every 32 s. `systemd-timesyncd` steps the guest
  to NTP while Hyper-V time sync pulls it back to a Windows clock that is 2.47 s fast.
  journald rotates on every backward step, and its 100-file cap leaves about 50 minutes
  of system history, so past outages cannot be diagnosed from the journal. Fix it with
  `sudo systemctl disable --now systemd-timesyncd` (WSL is meant to take its time from
  the host) and optionally `w32tm /resync` from an elevated prompt on Windows.
- Crash dumps: cap them with `maxCrashDumpCount` in `.wslconfig`. A single crash wrote
  a 2.4 GB node dump on a C: drive that is 96% full, and a full C: is what took swap
  offline on 2026-10-11.
- Deploying: the sensor rebuild and install need an elevated PowerShell. The reviver
  and health monitor take effect only after the owner re-registers them under their new
  names (`-Install`). The Python daemon itself is unchanged.
- Out of scope: Windows sleep, the battery or firmware hard resets, and the C: free
  space are the owner's power and hardware decisions. JARVIS cannot monitor while the
  host is asleep, and the fix must say so rather than claim otherwise.

## Applied 2026-10-12 (checkout; activation pending owner)

- `windows-sensor/JarvisSensor.cs`: positional resume (`Position`, `SkipForward`) with the
  XPath query kept as the fallback (`ReadEventsByQuery`). Tests are in
  `windows-sensor/tests/PositionResume.cs` and include 3,000 randomized trials. The narrow
  Windows stage, built on the installed 2026-09-18 source, is
  `~/.cache/jarvis-release-staging/native-position-20261012` (README, SHA256SUMS, rollback
  source). Live on the real channel it produced identical events in 33–150 ms, against
  1,162–1,540 ms for the old query near the newest record.
- `jarvis-reviver.ps1`: `StartGrace` (300 s, measured from the guest monotonic clock), and
  per-source kick back-off from 30 s to 600 s with no kick for partial sources.
  `jarvis-health-monitor.ps1`: "coverage degraded" is now distinct from "monitoring
  unavailable", with the same timing. Worsening to unavailable re-alerts at once, and a stale
  `stateError` is cleared. Tested in `tests/windows/supervisors.Tests.ps1` through
  `tests/test_windows_supervisors.py`. A mutation run confirmed the harness fails all 4
  injected faults.
- `.wslconfig`: `maxCrashDumpCount=3` (backup `.wslconfig.bak-2026-10-12`). It takes effect at
  the next `wsl --shutdown`.
- Full suite: 2,269 of 2,270 pass. The one failure is the pre-existing `test_decoding` on the
  untracked `jarvis/service/outages.py`, which belongs to another lane.
- Jev (jev-1.13.0), advisory only: choice of seek at 1.0; timeout-only treats the symptom
  (0.87); the accurate label keeps visibility (0.84); live measurement is still required
  (0.83). The 300 s grace is uncertain (0.63 at design, 0.66 after implementation) and
  should be tuned if a cold start ever exceeds it.

Owner steps, in order:
1. Elevated PowerShell: install the sensor stage (see its README).
2. Re-register the supervisors under their new names:
   `jarvis-reviver.ps1 -Install` and `jarvis-health-monitor.ps1 -Install`.
   Before doing this, ship them in a release, so the provenance audit compares the installed
   copies with reviewed release files.
3. `sudo systemctl disable --now systemd-timesyncd`. Optionally run `w32tm /resync` elevated.
4. `wsl --shutdown` at a convenient moment, to load the new `.wslconfig`.

Until these are done, the measured faults remain live: Sysmon read timeouts, and the
"unavailable" label applied to degraded coverage.
