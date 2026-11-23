# Internet application protection

The `internet` collector runs every 120 seconds through the shared scheduler.
The dashboard's **app traffic** tab shows the latest saved socket sample per
host, with timestamps. SQLite metadata retains the last 60 successful samples
per host, capped at 2,000 endpoints per sample. Collection failures preserve
the last successful sample and raise a visibility/outage finding.
The view distinguishes `sampled`, `partial`, and `unavailable`. A failed TCP
query preserves the previous socket sample; unreadable firewall logs label
otherwise collected socket data partial. Each sample retains its original age.

The collector records app name/path, PID, protocol, local/remote IP and port,
and socket state. It stores no command lines, URLs, cookies, or packet payloads.
It checks unsafe Chromium/Electron launch flags without retaining their values.
Linux process permissions can limit attribution; Windows query failures are
reported. UDP endpoints have no inferred direction. TCP inbound direction is
an inference requiring a matching listener address, port, and owning PID.
Listening beyond loopback does not establish Internet reachability or attack.

Windows firewall log summaries cover the last 1,000 lines of each configured
log; they overlap and are not interval counts. Short connections can be missed
by socket sampling. This is not full packet inspection or complete app security
coverage. Browser policy checks inspect registry values for connected Chrome,
Brave, and Edge processes; they do not prove effective browser policy settings.

## Apply Windows protection

From Windows PowerShell, using the checkout's Windows/WSL path:

```powershell
# As the normal browser user:
.\scripts\harden\secure-internet.ps1 -Browsers
# In elevated Windows PowerShell:
.\scripts\harden\secure-internet.ps1 -Firewall
```

Browser defaults enable standard Safe Browsing or SmartScreen and HTTPS-only
defaults. Existing enhanced Safe Browsing is preserved. Recommended policies
are user-overridable; verify enforcement in each browser's policy page.
The firewall operation enables allowed/dropped traffic logging, with a 32 MB
limit per configured log. It preserves network allow/block rules and profile
enablement. The existing firewall collector reports disabled profiles.

Backups live under `%LOCALAPPDATA%\Jarvis\InternetProtection`. Restore original
values using the same switch plus `-Undo`, under the same Windows account.
Do not delete backups until the change is accepted. Recheck logs and browser
policies after applying: file permissions and managed policy can prevent use.

References: [Microsoft firewall logging](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging),
[Chrome Safe Browsing policy](https://chromeenterprise.google/policies/safe-browsing-protection-level/),
[Chrome HTTPS-only policy](https://chromeenterprise.google/policies/https-only-mode/).
