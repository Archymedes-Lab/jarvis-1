# Keeping jarvis running 24/7

Four independent layers. Each one covers a failure the layer above it cannot.

| # | Layer | Covers | Interval | Installed by |
|---|-------|--------|----------|--------------|
| 1 | `systemd` `Restart=always` + `WatchdogSec=900` | the daemon crashes, or is alive but its scheduler has stalled | continuous | `./install.sh --priority` (drop-in) |
| 2 | `jarvis-selfcheck.timer` (user unit) | the daemon is "active" to systemd but not producing snapshots; the selfcheck timer itself | every 2 min | `./install.sh --seal` |
| 3 | `jarvis-wake-watchdog.ps1` scheduled task (Windows) | the whole WSL VM stopped (`wsl --shutdown`, idle teardown, crash); the unit is down; **the interop bridge / `/mnt/c` has wedged**; the deployed copy of this script has drifted from the repo | at logon + every 5 min | `./install.sh --windows` |
| 4 | `WSL jarvis 24x7` scheduled task (Windows) | WSL not started after a Windows reboot | at logon | printed by `./install.sh --windows` |

Layers 1–2 live inside the distro and are gone the moment the WSL VM stops.
Layers 3–4 run on the Windows side and are the only thing that can bring the VM
back. Layer 3's script is staged to `%LOCALAPPDATA%\WSLKeepalive\jarvis-wake-watchdog.ps1`
(a script inside a stopped distro cannot be read); with `-RepoRoot` baked in by
`install.sh` it reconciles that copy against the checkout on every run, so a
`git pull` reaches the task without a reinstall.

## Every corrective action is two-strike and rate-limited

`jarvis-wake-watchdog.ps1` never acts on a single bad reading:

- **unit restart** — `systemctl is-active` must read unhealthy twice, 5 s apart.
- **`wsl --shutdown`** (interop rebuild) — `/mnt/c` must be unreadable on two
  consecutive runs (≈ 8 min) **and** no shutdown in the last 20 min. After that
  window it logs `needs a human` and stops trying.

State and a full log line per run: `%LOCALAPPDATA%\WSLKeepalive\`
(`jarvis-wake.log`, `interop-bad-since`, `last-shutdown`).

## Install / update

```sh
./install.sh --service --priority --seal --windows
```

Re-run it any time to re-stage everything. After the first install, changes to
`jarvis-wake-watchdog.ps1` deploy themselves on the next 5-minute tick.

## Verify

```sh
systemctl show jarvis -p WatchdogUSec -p StartLimitIntervalUSec
systemctl --user list-timers jarvis-selfcheck.timer
jarvis selfcheck
powershell.exe -Command "Get-ScheduledTask 'jarvis wake watchdog','WSL jarvis 24x7'"
```

## When the interop bridge is down *right now*

`/mnt/c` throwing `Input/output error` means the 9p server on the Windows side
has wedged. Nothing inside WSL can fix it — `wsl.exe` itself lives under
`/mnt/c`. From a Windows terminal (PowerShell or cmd, **not** inside WSL):

```powershell
wsl --shutdown
```

Layers 3–4 bring the distro and jarvis back within a minute, and 9p
re-initialises clean. Once interop is back, re-run `./install.sh --windows` once
so the self-healing copy of `jarvis-wake-watchdog.ps1` is the one deployed.
