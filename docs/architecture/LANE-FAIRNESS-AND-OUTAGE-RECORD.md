# Lane fairness and the outage record (2026-10-11)

## What went wrong (measured on the live release 677b2a83b901)

From about 18:00 on 2026-10-10, 36 of the 51 collectors went STALE and stayed
that way: audio, input, firewall, intrusion, spy, implant, hidden, memscan,
preos, netwatch, evidence and more. The daemon was up the whole time. Three
defects reinforced one another:

1. **Sysmon fallback livelock.** With the native sensor not delivering,
   `sysmon` uses the PowerShell fallback. That reads the newest 1200 bulk events
   of a window that starts at `sysmon_last_run`. When the cap is hit, the run is
   `partial` ("event query capped or completeness unverified; cursor retained")
   and the cursor does not move. The window only grows, so every later run is
   capped too.
2. **The reviver re-queues it every cycle.** `revive-jarvis.ps1` (the
   `jarvis reviver` task, 5 s loop) POSTs `/api/run?job=sysmon` whenever sysmon
   reports `unavailable`. revive.log shows it about every 30 s.
3. **The forced queue has no fairness.** `Scheduler.force` appends without
   deduplicating. In `_due`, a forced job counts as at least `FORCED_FLOOR` (1.0)
   of its cadence overdue, multiplied by criticality (sysmon is critical: ×4) and
   by a failure bonus (×1.75). A starved hourly medium collector scores
   `overdue × 2`, where overdue is measured from `next_run`. A restart resets
   `next_run`, so six hours of real staleness counts as a few minutes.

Evidence:

- The defender journal shows 74 sysmon runs in the 18:00 hour and about one
  every 50 s afterwards.
- A 150 s poll of `/api/state` showed sysmon restarting the moment the previous
  run ended, while `next_run` was still about 597 s away. That means the run
  came from the forced queue, not the schedule.
- The governor deferral (`overdue < 3.0`) uses the same restart-relative
  lateness.

## Invariants

* **I1 Bounded starvation.** While the host is running, a collector whose
  evidence is older than STALE_AFTER × interval is preferred over any job that
  is not starving, including forced repeats of a job that just ran. No single
  job runs twice in a row while a starving job is due.
* **I2 Real lateness.** Lateness is measured from the newer of the last
  persisted evidence timestamp and this process's last attempt. It is never
  measured from a `next_run` that a restart reset.
* **I3 Retry discipline.** A failing job's attempt resets its lateness. It
  retries on its own cadence (or RETRY_S while held), and repeated force
  requests collapse into one queued request.
* **I4 Tier-0 not starved.** A critical collector that is itself starving
  competes in the same starving tier at its higher weight.
* **I5 Honest outage record.** Every collector transition between up, failing
  and stale, every daemon gap, and every WSL VM and host power event that
  Windows logs is appended to the hash-chained event log as a
  `sensor`/`state` event. Each event carries a start time, an end time, the
  duration and the cause where known. Start times come from evidence, for
  example `ts + 2 × interval` for stale, never from when JARVIS noticed.
* **I6 No duplicate and no loss across interruption.** Pending transitions are
  written to a durable spool before the event-log append. The event log's
  per-source cursor is the commit point, and a retry skips records at or below
  it. A busy writer lock leaves the spool intact for the next pass.
* **I7 Bounded cost.** A transition costs one event-log append when the
  writer lock is free. The Windows lifecycle read is one PowerShell call per
  10 min, capped at 200 records since a cursor. The spool is capped at 5000
  entries; overflow is recorded as a counted gap, never silently dropped.
* **I8 Privacy.** Outage events carry job names, levels, times, record IDs and
  short error class text. They carry no command lines and no user data.
* **I9 No authority.** The recorder never restarts, contains, suppresses or
  scores anything. It only records.

## Designs compared

| | A. Dedupe force only | B. Starving-first EDF on real lateness (chosen) | C. Per-job worker threads |
|---|---|---|---|
| Fixes the monopoly | Partly: the reviver still re-queues after each run | Yes | Yes |
| Starved collectors catch up | No: forced 1.0 × 4 still wins | Yes: starving tier first | Yes |
| Interop contention | Unchanged | Unchanged (one main worker) | Many concurrent powershell.exe launches, slower and more memory on a host already short of commit |
| CPU/memory cost | none | none (two dict lookups per pick) | one thread and process per job |
| Recovery/visibility | unchanged | unchanged; lateness becomes visible and honest | harder to reason about |

B also moves `evidence` (314 s per run, 35 % of the main lane's duty) into a
third "bulk" lane. Its time goes to DrvFS hashing, vault staging and network
anchoring; it makes one PowerShell call. That brings the main lane's duty back
under 100 %. C was rejected because of memory pressure: the WSL VM was reset by
a host out-of-memory event at 00:51:16 the same night.

**Follow-up (2026-11-03):** the five-minute collectors now have a frequent
lane of their own. After a boot they went stale behind the main lane's
1331 s sweep; see [FREQUENT-LANE.md](FREQUENT-LANE.md).

**Reconsider if:** the main lane's measured duty stays above 90 % after the
change. The next candidates for the bulk lane would be `world` and `feeds`
(network-bound).

## Outage record: sources and who can still rewrite them

| Interval | Source | Tamper evidence | Who can still rewrite it |
|---|---|---|---|
| Collector stale or failing | scheduler supervise pass → spool → event log | hash chain, sealed segments copied to the admin-only vault, OpenTimestamps anchor every 6 h | the WSL user until the segment is vaulted (≤ 5 min seal plus the 15 min broker cycle); a local admin until the next anchor |
| Daemon down | persisted heartbeat compared with process start and VM boot time | same | same |
| WSL VM down, host sleep or shutdown | Windows System, Hyper-V-Worker-Admin and Kernel-Power logs, read back when WSL returns | the Windows log itself: a standard user cannot write or clear it, and clearing it leaves event 104/1102; the copy in the event log carries the Windows record ID so it can be checked against the source | a local admin, before the logs are read back |

The record is **tamper-evident**. It is not tamper-proof. While the VM is
frozen or crashed, nothing inside it can record anything. That interval is
rebuilt from Windows' own logs when WSL comes back. If Windows itself is off,
only the gap is visible, and its cause is unknown.
