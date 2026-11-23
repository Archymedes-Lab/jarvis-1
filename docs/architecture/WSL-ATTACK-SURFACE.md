# WSL attack surface: every way through the boundary, measured 2026-10-21

JARVIS runs inside a WSL2 distro and protects the Windows host around it. The
boundary between the two is not a security boundary: both sides run as the
same Windows user, and that user is root in the distro whenever a Windows
process asks. This document lists each way across, what was measured on this
machine, what JARVIS sees, and what this change adds. Nothing here claims the
boundary is sealed; the honest deliverable is to see every crossing and to
record every change to the boundary itself.

## Invariants this change must preserve

- Evidence continuity: nothing here deletes or rewrites recorded events; the
  checkpoint file is append-only and hash-chained; a broken chain is reported,
  never repaired silently.
- Sensor freshness: the new job is a 300 s sampler; every source reports its
  own status and an unreadable source is visibility loss, never "unchanged".
- Identity and cursor integrity: the Windows read is a registry read; the Linux
  read is file metadata and config text; no cursors are moved.
- Privacy: config values are bounded to 200 characters, no environment values,
  no command lines of other processes, no file contents beyond the two WSL
  config files; the `.wslconfig` is the owner's own.
- Bounded resource use: one PowerShell registry read (about 1 s) and a few
  small file reads every five minutes; at most 32 distributions, 16 plugins,
  32 policy values are retained.
- Recovery and rollback: the Sysmon policy additions go through the existing
  installer with its backup and readback; nothing is applied by this change.
- Explicit authority: the guard never changes WSL state. The only writer stays
  `jarvis timeline wsl-boundary --accept`, run by the owner.
- Score integrity: new findings are low when they describe a posture the owner
  has not decided on (no checkpoint, docker socket), medium or high only on a
  change or a root path.

## The ways across, and what each one gets

| # | Way | Who can use it | What it gets | Measured 2026-10-21 | Seen by JARVIS |
|---|---|---|---|---|---|
| 1 | `wsl.exe -u root` / `--system` | any process of the Windows user, no prompt | root in the distro: stop jarvis.service, edit `/opt/jarvis`, read `~/.jarvis` | `wsl.exe -u root -- id -u` printed `0`; Windows Sysmon recorded the launch with its full command line; the Linux side recorded `/usr/bin/id` as root with ParentImage `-` and ParentProcessGuid zero | **new**: Windows command-line rule (high). A Linux-side rule was evaluated and rejected: 19,882 root process starts in 20 h, 9,155 with an unresolved image and 5,458 from runc, so "root with unresolved parent" is noise |
| 2 | `HKCU\...\Lxss\{guid}\DefaultUid = 0` | any user process (user hive) | every later `wsl` is root | DefaultUid is 0x3e8 (1000); Flags 0xf; no WSL policy key | **new**: registry rule (high) + guard sample (high) |
| 3 | `HKCU\...\Lxss\{guid}\BasePath` | any user process | swap the distro disk for a prepared one | BasePath under `%LOCALAPPDATA%\wsl` | **new**: registry rule (high) + guard change (high) |
| 4 | `wsl --import` / `--install` / `--mount` | any user process | a second root distro with interop and the user's rights; a mounted disk | one distro registered | **new**: command-line rule (medium) + guard "new distribution" (medium) |
| 5 | `wsl --unregister Ubuntu` | any user process | deletes the distro disk: JARVIS, its evidence and the owner's files | not run | **new**: command-line rule (critical) + guard "unregistered" (medium) |
| 6 | `wsl --shutdown` / `--terminate` | any user process | stops the engine | not run | **new**: command-line rule (high; the owner's own `wsl --shutdown` will show and can be acknowledged) |
| 7 | `HKLM\...\Lxss\Plugins` | administrator | a DLL loaded by the WSL service as SYSTEM at every VM start | key present, empty | **new**: registry rule (critical) + guard (high) |
| 8 | `.wslconfig` `kernel=` / `kernelModules=` / `kernelCommandLine=` | any user process (file in the profile) | replace the kernel of the VM JARVIS runs in | none set; Microsoft kernel 6.18.33.1-1 | existing checkpoint facts (critical); **new**: guard posture findings (high) without needing a checkpoint, FileCreate record of `.wslconfig` |
| 9 | `/etc/wsl.conf` `[boot] command=` | root in the distro (way 1) | a root command at every boot | not set | existing checkpoint fact; **new**: guard posture finding (high) |
| 10 | `\\wsl.localhost\Ubuntu\...` | any user process | read and write every file the distro user owns: `~/.jarvis` store, `~/jarvis` checkout, `~/.bashrc`, user systemd units | reachable (the Jev review script ran from that path) | the daemon runs the root-owned release under `/opt/jarvis`, so checkout edits do not reach it; store tamper is covered by the Rust mirror and anchors; **new**: FileCreate policy record for `\wsl.localhost\` and `\wsl$\` targets (volume and path format unmeasured until applied) |
| 11 | interop sockets `/run/WSL/*_interop` (mode 0777) | any distro process | run any Windows program as the user | present | inherent to the design; Windows Sysmon records the resulting Windows processes |
| 12 | DrvFs `/mnt/c` rw as uid 1000 | any distro process | write to the user's Windows profile: Startup folder, Run keys through `reg.exe` | mounted rw | existing: startup folder, Run key and task collectors |
| 13 | loopback API `127.0.0.1:8787` | any Windows process (localhostForwarding) and any distro process | `POST /api/answer` (acknowledge a finding), `/api/fix/approve`, `/api/run`, `/api/geo/zone` | reachable from Windows (`curl.exe` got 200); a Windows-originated connection arrives with peer `127.0.0.1`, indistinguishable from a local one; non-browser clients send no Origin and pass the same-origin gate | acknowledgements stay visible as low findings with their reason; approval only records intent and `apply` stays a terminal command. Not changed here: a token or peer gate would be readable by the same user through way 10, so it adds little; recorded as an owner decision |
| 14 | docker socket, user in `docker` group | any distro process of the user | root in the distro through a container | present, `chris` in `docker`; containerd on `127.0.0.1:45905` | **new**: guard informational finding (low) |
| 15 | `wsl --debug-shell` | administrator | root shell in the system distro of the VM | not run | **new**: command-line rule (medium) |

## Design choice

Three designs were compared for seeing way 1 (root from Windows):

1. Linux-side Sysmon rule on root processes with an unresolved parent.
   Rejected on measurement (table above): docker makes it unusable.
2. Linux-side rule narrowed by `CurrentDirectory` under `/home` or `/mnt/c`
   and `TerminalSessionId` 4294967295. Rejected: both are shared with
   `wsl.exe -u chris` launches and with systemd user services, and the
   Windows side already has the deterministic fact (the command line).
3. Windows-side command-line rules on `wsl.exe` plus registry rules on the
   registration keys, with a five-minute sampler for the facts no event
   carries (`.wslconfig`, `wsl.conf`, DefaultUid, plugins). Selected: every
   fact is recorded with its writing process, the rules reuse the existing
   technique and registry machinery, and the sampler closes the gap between
   policy application and the next event.

Reconsider if Sysmon for Linux starts resolving `/init` relay parents, or if
the owner moves to a native (no-WSL) host where ways 1 to 10 do not exist.

## What is not closed

- Ways 1, 10, 11 and 13 are the same user on both sides. No software inside
  the distro can stop a Windows process of that user; it can only be seen.
  Reducing them is an owner decision: a separate standard account for daily
  use, or a native install without WSL.
- The policy additions (registry `Lxss`, `WSL` policy, `.wslconfig` and
  `\wsl.localhost\` file creates) are in the baseline file and are applied
  only through the elevated installer; until then the registry rules are
  recorded as "not seen to be recorded" by the coverage map.
- The guard has no accepted checkpoint. Run `jarvis timeline wsl-boundary`
  and, if the state is yours, `--accept`; drift findings start after that.
- A change undone within one five-minute interval is unseen by the sampler;
  the Sysmon rules are the continuous path for the registry keys.

## Owner actions

1. Apply the Sysmon policy through the existing elevated installer after the
   next release (it backs up and reads back).
2. `jarvis timeline wsl-boundary --accept` once the state reads as yours.
3. Decide on way 13: leave as is (visible acknowledgements), or ask for a
   peer or token gate knowing it is readable by the same user.
4. Optional hardening in `.wslconfig`: `firewall=true` and `dnsTunneling`
   pinned explicitly so an update cannot change them silently.
