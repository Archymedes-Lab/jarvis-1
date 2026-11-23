# JARVIS quickstart

## One command

From the checkout, inside WSL:

```bash
./quickstart.sh
```

That does, in order:

1. **`install.sh --seal`** — installs the `jarvis` CLI, a systemd **system**
   service (top CPU/IO priority, OOM-immune, 15-min watchdog, no restart rate
   limit), the out-of-daemon `jarvis-selfcheck.timer`, and the Windows
   `jarvis wake watchdog` scheduled task that restarts the distro/service/bridge if any
   of them stop.
2. **`loginctl enable-linger`** so the daemon survives logout.
3. **Waits for the dashboard** on `http://127.0.0.1:8787`.
4. **Windows hardening** via the bridge:
   - browser defaults (Safe Browsing / SmartScreen / HTTPS-only) — no elevation,
     reversible, backed up
   - one **UAC prompt** to run `harden-elevated.ps1`: firewall connection
     logging + Attack Surface Reduction rules in audit mode

Safe to re-run. Flags: `--no-windows` (Linux only), `--no-priority` (user
manager, no sudo), `--check` (health summary and exit).

## A Windows machine without WSL

Copy the checkout to a local Windows folder, install Python 3.12 or newer, and
from PowerShell in that folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\quickstart.ps1 -Native
```

This registers the `jarvis native service` scheduled task (no elevation), which
runs `python -m jarvis serve`, restarts it when it exits or stalls, and waits
for the dashboard. The Windows audits run as they do under WSL; the Linux-only
ones (`auditd`, `sysmon_linux`, `containers`) are reported as not applicable,
not as healthy. This mode is new and not yet validated on a machine without
WSL: read [what was measured and what was not](docs/architecture/NATIVE-HOSTS.md)
before relying on it.

## After the first run

| Want | Command |
|---|---|
| Health | `./quickstart.sh --check` |
| Dashboard | `http://127.0.0.1:8787` → **ops & setup** tab |
| Enforce ASR (after a few clean days) | `powershell -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\Jarvis\harden-elevated.ps1" -Enforce` |
| Undo Windows hardening | same path with `-Undo` (browsers: `.\scripts\harden\secure-internet.ps1 -Browsers -Undo`) |
| Credential Guard | Settings → Device security → Core isolation → Memory integrity = On, reboot (needs BIOS virtualization) |

## What one command cannot do

- **auditd** — Microsoft's WSL2 kernel rejects the audit daemon; Sysmon-for-Linux
  (eBPF) is the substitute and is installed by `install.sh`.
- **Credential Guard** — needs a reboot and BIOS virtualization; `harden-elevated.ps1`
  only reports its state.
- Elevated Windows steps need the UAC approval in step 4; decline it and the
  script prints the one command to run by hand later.
