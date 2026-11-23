# Native Windows sensor

A Windows service that reads the Sysmon, Defender and Task Scheduler event
channels directly through the Event Log API and publishes every record, in
order, as immutable batch files. No console window, no WSL or PowerShell
dependency, no network listener, no command execution. It keeps recording
while WSL is down; JARVIS catches up from the spool when it returns.

Install with `jarvis sensor install [--enable-task-log] [--sysmon-log-mb 256]`:
it hashes `install.ps1` and `JarvisSensor.cs` from the checkout before the UAC
prompt, and the elevated shell runs them only after copying them into Program
Files and matching those hashes. By hand (elevated PowerShell), pass the
SHA-256 of the `JarvisSensor.cs` you reviewed; any other source is refused
before it is compiled:

```powershell
.\install.ps1 -Install -SourceSha256 <reviewed SHA-256> -EnableTaskLog -SysmonLogMB 256
```

`.\install.ps1 -Remove` also revokes the two grants install made, the
logon-as-a-service right and Event Log Readers membership of
`NT SERVICE\JarvisNativeSensor` (by SID, so they go even if the service is
already deleted), and fails with a list of anything it could not remove.

To cut over an existing installation to three isolated SCM services, stage the
reviewed `JarvisSensor.cs`, `monitor-isolated.ps1`, `install-isolated.ps1`, and
`SHA256SUMS.json`
under the administrator-controlled `C:\Program Files\Jarvis\SensorStage`, then
run `install-isolated.ps1 -Install` there from an elevated PowerShell after
recording a live ingestion baseline. The installer refuses a user-writable
checkout as its source and verifies each staged file against the reviewed hash
manifest. It saves the legacy executable,
identity and health receipts, plus a spool ACL backup under the protected binary
directory. The old publisher is stopped and changed to manual startup before
the isolated services begin; its binary is replaced with a mode-aware build so
an accidental manual start cannot publish concurrently. The existing spool,
channel identities, sequences and acknowledgements stay in place. On failure,
the installer restores the old publisher. Explicit rollback is
`install-isolated.ps1 -Rollback` from the same protected stage.

The isolated services are `JarvisSensorSysmon`, `JarvisSensorDefender`, and
`JarvisSensorTasks`. Each has its own process, virtual account, channel spool
budget (Sysmon 384 MiB; Defender and Task Scheduler 64 MiB each), lock and
health receipt. A protected SYSTEM scheduled task checks
their state and heartbeat each minute, restarts only after two failed checks,
and stops after two attempts per hour. It records the attempts in `monitor.json`.
The installer adds an exact-path Defender ASR-only exclusion for its protected
unsigned executable if required; rollback removes only an exclusion it added.
The new services still require Windows integration and soak validation before
they can be called live protection. This architecture does not eliminate WSL
interop dependence for the separate PowerShell-backed collectors.

`-EnableTaskLog` turns on the Task Scheduler operational channel, which is
disabled by default on Windows, so scheduled-task persistence is otherwise
unlogged. `-SysmonLogMB` enlarges the Sysmon log, which wraps at 64 MB.
Records it overwrites before the sensor reads them are lost, and JARVIS
reports them as a gap.

## Contract

- **Resume point.** The last record ID published per channel, not an
  `EventBookmark`: .NET Framework keeps bookmark serialization internal, and
  the prototype that used it never compiled. A record ID can also be compared
  with what the log still holds:
  - The newest record precedes the resume point: the log was cleared. A new
    generation starts and a gap is recorded.
  - The oldest record is past the resume point: the records in between were
    overwritten before they were read. A gap is recorded with the exact range.
- **Batches.** Up to 500 records, written, flushed and then renamed into place,
  never overwritten. A pass drains up to 50 batches per channel, so a backlog
  clears at about 25,000 records a pass rather than 500.
- **Identity.** `sensor_id` (this installation), `device_id` (the machine,
  independent of its hostname), `boot_id` (Windows' boot counter), and per
  record `mono_ms` (milliseconds since boot at read time). New source builds
  also emit `read_time` separately from the provider's event `time`, allowing
  the ingester to measure read delay. Old batches retain an explicit
  event-time fallback; neither timestamp proves that no event was dropped.
- **Capacity.** At 512 MiB the sensor stops collecting and reports it. It never
  deletes unacknowledged evidence.
- **Acknowledgement.** After committing a batch to its event log, JARVIS writes
  `acks/<channel>.json` naming the batch's sequence number and SHA-256. The
  sensor verifies that digest against its own file. Only then does it reclaim
  older batches: after 24 hours, or immediately above half capacity. The
  newest batch, which is the resume point, always stays.

## Trust layout (`install.ps1`)

| Path | Writable by | Purpose |
|---|---|---|
| `C:\Program Files\Jarvis\Sensor` | Administrators, SYSTEM | The executable, compiled at install from a staged copy of the source |
| `C:\ProgramData\Jarvis\Sensor` | the service account | The spool; the JARVIS user can read it |
| `C:\ProgramData\Jarvis\Sensor\acks` | the JARVIS user | Acknowledgements only |

The service runs as the virtual account `NT SERVICE\JarvisNativeSensor` in
Event Log Readers, not as LocalSystem. A changed `JarvisSensor.cs` has no
effect until `-Install` is run again.

Known limits: the user account can forge an acknowledgement. The sensor then
reclaims its own copy of batches early, but it still requires the exact digest
of a batch that exists. A local administrator can alter anything here. The
executable is compiled locally, not signed.

## On the JARVIS side

`jarvis/platform/native/ingest.py` drains the spool into the event log
(`jarvis/core/eventlog.py`), and the daemon's `native` job runs it every minute.
To inspect the history:

```bash
jarvis timeline status          # cursors, sensor health, event mix
jarvis timeline search --sha256 <hash>   # has this ever executed?
jarvis timeline tree '<ProcessGuid>'     # ancestry and children
jarvis timeline verify          # hash chain; keep the printed head off-machine
jarvis timeline changes --seconds 120 --json  # bounded observed type counts
```

For an isolated single pass without installing:

```powershell
.\build.ps1 -OutputDirectory "$env:TEMP\JarvisSensorBuild"
Start-Process "$env:TEMP\JarvisSensorBuild\JarvisSensor.exe" -ArgumentList '--once',"`"$env:TEMP\JarvisSensorTest`"" -Wait
```

Then ingest it into a scratch log with `python3 -m jarvis.platform.native <spool> --log <dir>`.
