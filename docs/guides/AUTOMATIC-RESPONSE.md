# Automatic response and attention alerts

The scheduler now attempts fixed repairs before saving and notifying on findings.
`auto_remediate` defaults to true, independently of email configuration.

Supported actions:

- Restart stopped Linux Sysmon using the installed, fixed-operation sudo helper.
- Attempt the existing Windows mount repair when the bridge is down, then verify bridge availability.
- Disable orphaned local inbound firewall allow rules only for missing executable files whose parent directories remain readable. Requires an already elevated Windows token; never opens an elevation prompt. Saves a CLIXML rollback record in `%LOCALAPPDATA%\Jarvis\repairs` before changing rules. Restore selected rules using `Enable-NetFirewallRule -Name` with names from that record.

Each action is limited to one attempt per hour and three per rolling day. Attempts
are persisted before execution, so a crash or restart does not reset the budget.
The `automatic_repairs_v1` database metadata records the latest outcome, finding
keys, verification timestamp, and recent attempt timestamps for each action.
Failed repairs carry their status and reason in the finding's `remediation` field.

A successful command alone never clears a finding. The owning collector must
complete a fresh observation. Failed or incomplete verification retains the
original findings and any new evidence, and permits normal attention alerts.
Existing input-hook, connectivity, and service watchdog recovery remains active.

Unknown scripts, malware indicators, plaintext credentials, encryption, Secure
Boot, hidden accounts, and active application firewall rules still require
investigation or a specific operator decision. No detector text is executed as a
command. The automated repair list is deliberately explicit.

Email defaults to attention alerts: routine daily mail and disappearance notices
are off. Set `report_daily_enabled: true` or `alert_on_clear: true` in
`~/.jarvis/config.json` to opt in. Disappearance notices say “NO LONGER OBSERVED,”
not that remediation is proven. Critical and outage findings that remain after
repair still bypass the ordinary digest delay. Other findings retain the existing
digest and finite escalation policy. Set `auto_remediate: false` to disable the
new repair layer.

Review on 2026-09-14: the recent sent-alert ledger includes JARVIS scheduled tasks,
orphaned and active firewall rules, and filename-based intelligence matches.
These are detector observations, not a count of confirmed attacks. The independent
Windows monitor also reports an email-path failure, which remains unresolved
until delivery can be verified. Credential values were not read or logged.

Deployment verification: live configuration explicitly enables automatic repairs
and disables routine daily and clear emails. JARVIS was restarted using the
root-owned helper, and `/api/health` subsequently reported `healthy`, `live`,
`ready`, and `protection_healthy` all true. The first persisted orphan-firewall
attempt was not verified; two Edge WebView rules whose version directories are
missing remain open and are on cooldown. Their active-application counterparts
were not selected for repair. Windows PowerShell parsed the script with zero
errors. This is not a claim that all outstanding security findings were resolved.
