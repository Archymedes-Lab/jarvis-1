# Windows connectivity guard

`jarvis-connectivity-guard.ps1` runs every minute in Windows Task Scheduler, independently
of WSL and JARVIS. Install from Windows PowerShell with an existing trusted profile:

```powershell
.\jarvis-connectivity-guard.ps1 -Install -InterfaceName 'Wi-Fi' -ProfileName 'iPhone'
```

Runtime files live in `%LOCALAPPDATA%\Jarvis\Connectivity`. The limited, interactive
task runs while the user is signed in, including on battery. Each run has a two-minute
limit and overlapping runs are suppressed. Installation does not change power settings.

Two bounded TCP/443 probes (Cloudflare and Google IPs) measure outbound reachability;
they do not prove DNS, HTTP, VPN, or every application's connectivity. After three
consecutive disconnected checks spanning two minutes, the guard requests connection
to the configured saved profile. Attempts are separated by at least five minutes,
including failed requests. A later successful probe confirms recovery. Sleep gaps
restart confirmation. Corrupt persisted state fails closed.

An adapter that remains connected but loses upstream reachability is reported without
resetting the working local link. Disabled/missing adapters are left alone. The guard
does not toggle radios, reset adapters, change DNS, bypass captive portals, choose other
saved networks, or alter firewall/VPN settings. It cannot prevent driver faults or
restore an unavailable hotspot/ISP. Update the configured profile when changing networks.

Inspect or pause from Windows PowerShell:

```powershell
Get-Content "$env:LOCALAPPDATA\Jarvis\Connectivity\state.json"
Get-ScheduledTaskInfo -TaskName 'JARVIS connectivity guard'
Disable-ScheduledTask -TaskName 'JARVIS connectivity guard'
# Resume:
Enable-ScheduledTask -TaskName 'JARVIS connectivity guard'
# Remove automation (keeps diagnostic files):
Unregister-ScheduledTask -TaskName 'JARVIS connectivity guard' -Confirm:$false
```

Pause before intentionally disconnecting Wi-Fi; otherwise the guard can reconnect
the configured profile. No network passwords are exported or stored by this tool.

Validation: `powershell.exe -NoProfile -File tests\test_connectivity.ps1`.
Reconnect uses Microsoft's documented `netsh wlan connect` command:
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan
