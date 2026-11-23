# Independent cursor-speed monitor

Status: installed in the current Windows user's interactive session on
2026-09-28. A fresh short run is evidence of operation while this session is
awake; a reboot, sign-out and 24-hour soak have not been validated.

## What it measures

`windows-sensor/cursor-speed.ps1` is a separate process and task from the JARVIS
input hook and native collectors. It samples the on-screen cursor every 200 ms,
publishes a 10-second aggregate in
`%LOCALAPPDATA%\Jarvis\CursorSpeed\state.json`, and records pointer-setting
changes and worker restarts in `events.jsonl`. Coordinates,
clicks, keys, window names and pointer paths are never written. The event log
rotates at 2 MiB and retains one previous file.

`cursor_pixels_per_second` is screen travel divided by window time, so it also
changes when the person moves the mouse differently. `settings.pointer_speed`
is the Windows 1–20 pointer speed value. Neither value alone proves a driver,
device, remote-control or security problem. A window longer than 15 seconds is
`partial` with no speed value, preserving visible sleep or scheduling gaps.

## Supervision and checks

`windows-sensor/cursor-speed-task.ps1 -Action Install` registers one limited,
interactive-user task named `JarvisCursorSpeed`. It starts at logon and on a
five-minute repeating trigger, ignores a trigger while its worker is running,
and attempts bounded restart after a failure. It has no administrator rights.
The status action reports `fresh` only when the task is running and its latest
complete receipt is at most 30 seconds old. The monitor holds a session mutex,
continues sequence numbers across restarts in the same session, and replaces its
receipt atomically. A failed write exits the worker; the stale receipt stays
visible until a successful restart.

Run from Windows PowerShell:

```powershell
& .\windows-sensor\cursor-speed-task.ps1 -Action Status
& .\windows-sensor\cursor-speed-task.ps1 -Action SelfTest
& .\windows-sensor\cursor-speed.ps1 -SelfTest
```

`Update` verifies the installed task action and user, saves the prior script as
`cursor-speed.ps1.previous`, then restarts the task. `Remove` removes the task
and retains local measurements. The monitor is available only while that user
is signed in and Windows is awake. Task Scheduler cannot sample a suspended
machine or a signed-out desktop. A stale state after either period is a coverage
gap, not a zero-speed measurement.
At installation, Windows reported a 45-minute automatic sleep timeout on
both AC and battery. The owner approved disabling automatic sleep on AC only.
The AC timeout now reads zero, the battery timeout remains 45 minutes, and AC
automatic hibernation also reads zero. The original power setting is saved in
`%LOCALAPPDATA%\Jarvis\CursorSpeed\power-settings-before.json`; restore it with
`powercfg /change standby-timeout-ac 45` if needed. Lid closure, sign-out,
reboot and power loss still interrupt cursor observation.

## Design decision and costs

An SCM service runs in Session 0 and cannot observe the user's cursor by itself;
it needs a second interactive agent and a secure handoff. The single user task
keeps the requested monitor independent and avoids a privileged bridge. The
first live readback showed one worker at about 81 MiB working set, a fresh
10-second receipt and pointer speed 10. A later five-second sample measured
81.2 MiB and 0% of one CPU core at sample resolution. One forced worker exit
was followed by a fresh advancing receipt. Sustained CPU, disk growth, reboot and sleep
behavior still require measured validation. A
native compiled agent would be worth reconsidering if PowerShell's memory use
or sampling overhead becomes material, or if a separately supervised
multi-session service is required.

Jev received only the design choices, receipt summary and privacy limits. Its
Choice favored the interactive task (0.94 probability, 0.89 confidence), and
its Noul assigned 0.03 yes probability to a single fresh receipt proving 24/7
coverage. These are advisory; the task readback, regression checks and remaining
soak gates decide the operational claim.
