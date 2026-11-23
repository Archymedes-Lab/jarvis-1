# Autonomous defense

JARVIS can take reversible action against a threat on its own, but only within
strict limits and only when you turn it on. The default posture is **propose,
never act**.

## The response ladder

For every finding, `jarvis/response/defense.py` chooses one rung:

- **AUTO** — a reversible containment action fits, the finding is critical or
  high, the detector supplies action-specific corroboration, and you enabled
  that action. JARVIS captures evidence, acts, and tells you what it did with
  an undo command. If evidence capture fails, the action does not run.
- **PROPOSE** — an action fits but it is not enabled (or the finding is only
  medium). It waits for `jarvis defend approve <id>`.
- **ASK** — no action fits, but only you can judge it: it becomes a question
  (`jarvis answer <id> yes|no`).
- **WATCH** — nothing to do.

Everything AUTO does is reversible and recorded in the defense ledger, so any
action can be undone with `jarvis defend undo <id>`.

## Actions

| action | host | what it does | undo |
|---|---|---|---|
| `quarantine_file` | wsl | move a dropped file into a locked store, leave a marker | move it back |
| `block_address` | win | Windows Firewall outbound block to a flagged IP | remove the rule |
| `disable_autostart` | win | disable a suspicious task or remove one Run entry | re-enable or restore it |
| `suspend_process` | wsl | SIGSTOP a suspicious process (memory kept for a dump) | SIGCONT |

Killing, deleting and disabling accounts are **approval-only** and are added as
proposals, never run automatically.

## Turning it on

Off by default. In `~/.jarvis/config.json`:

```json
{
  "autonomous_defense": true,
  "auto_quarantine": true,
  "auto_block_ip": false,
  "auto_disable_autostart": false,
  "auto_suspend": false
}
```

`autonomous_defense` is the master switch; each action also needs its own flag.
Enable one at a time and watch `jarvis defend` to see how it behaves on your
machine before enabling more.

Current automatic confidence rules are deliberately narrow:

- the scheduler must durably record the observation before downstream response;
  a journal failure inhibits both repair and containment, and incomplete
  collection limits containment to proposals;

- quarantine runs unattended only for an exact SHA-256 malware-sample match;
  filename and path indicators remain proposals because legitimate files can
  share them;
- address blocking runs unattended only for a high-confidence feed match;
- autostart disabling runs unattended only for a critical task or Run-key
  finding carrying a structured collector target;
- process suspension remains proposal-only until a collector can bind live
  process identity to independent malicious evidence.

`jarvis incidents` preserves finding history independently of email delivery.
An absent finding becomes `not_observed` after a complete result or `unobserved`
after visibility loss; neither state claims verified remediation. See the
[Defender Engine design](architecture/DEFENDER-ENGINE.md) for the transaction,
coverage, and proposed native-broker contracts.

Windows Firewall and machine-wide scheduled-task changes require an elevated
Windows token. An unelevated daemon records a failed action and keeps the
proposal; it does not claim containment. A production Windows response broker
must independently validate a fixed request schema and run from an
administrator-owned installation, rather than elevating model or finding text.

## Commands

```
jarvis defend            what JARVIS did, and what is waiting for you
jarvis defend actions    the actions and whether each is auto or propose-only
jarvis defend approve <id>
jarvis defend undo <id>
jarvis answer            open questions
jarvis answer <id> yes   confirm as expected (acknowledges it)
jarvis answer <id> no    escalate / contain it
jarvis inspect PATH      Defender, signature, SHA-256 and available local tools
jarvis inspect PATH --yara-rules RULES
jarvis inspect --pid PID process ancestry and children
jarvis ask "what needs me?"
jarvis ask "what's my score?"
jarvis ask "explain <finding-id>"
```

Install the signed Windows investigation tools with:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\tools\install-sysinternals.ps1
```

The installer downloads Sigcheck, Autoruns, Handle and ProcDump from
Microsoft's Sysinternals host and rejects any executable without a valid
Microsoft Authenticode signature. YARA remains optional and is discovered from
the Linux `PATH`; on Ubuntu install it with `sudo apt-get install yara` and pass
an explicit rules file to `jarvis inspect`.

## Offline explanations

The dashboard chat and `jarvis ask` answer known questions directly from the
SQLite snapshots. Open questions go to Ollama at `http://127.0.0.1:11434` and
default to `llama3.2:1b`; override these with `ollama_url` and `ollama_model` in
the config. Finding text is delimited as untrusted data, the
model receives no tools, and model output has no route to acknowledge, approve,
undo, quarantine or repair anything. Explicit dashboard buttons and CLI
commands remain the mutation boundary.

## Added telemetry

The Windows Sysmon collector also reports destructive shadow-copy/recovery
commands as critical ransomware-preparation signals and adjacent unsigned DLL
loads in user-writable directories as possible DLL side-loading. These are
signals for context and containment decisions; they are not standalone proof
of compromise.

## Remaining work for unattended Windows containment

The WSL daemon cannot safely grant itself administrator rights. Automatic
Windows firewall and machine-wide persistence response therefore requires a
small native service that accepts only versioned action records, validates IP
addresses and exact task or registry identities again, writes a protected audit
record, and exposes fixed undo operations. Model text, shell fragments and raw
finding text must never cross that privileged boundary. Until that service is
installed and verified, JARVIS prepares these actions for approval and reports
failed privilege checks accurately.

Broader ransomware rollback also needs a protected copy-on-write or backup
provider. JARVIS currently detects destructive recovery commands and can
contain corroborated files; it does not claim that telemetry alone can restore
encrypted user data.
