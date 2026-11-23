# Interop backpressure and page-cache release

Status: built 2026-10-25, unverified on the live daemon. Owner request: "propose a fix" for the
17:20 forced WSL shutdown, then build items 1 and 2.

## What happened (measured 2026-10-25)

- 17:06 onward: JARVIS PowerShell collectors increasingly returned "no payload"
  (`defender_runs`: backdoor, implant, scan, privacy, storage, resources, audio, controls,
  identity, hidden, netwatch); journal "WSL Relay UtilAcceptVsock: Waiting for abnormally long
  accept" rose from ~4/min to ~16/min. No OOM, no 9p errors.
- 17:10:44 and 17:20:38: the owner's watchdog `wake-jarvis.ps1` (Task Scheduler) found
  `/mnt/c` unreadable through `wsl.exe` twice, 10 minutes apart, and ran `wsl --shutdown`.
- The daemon had no limit on concurrent PowerShell launches (three lanes launch independently),
  and `ps_json` retried every empty result at once, so a slowing relay received more work.
- The daemon cgroup sat at MemoryHigh (2.5 GB): 310 MB anonymous, 1.2-1.9 GB page cache,
  12 MB of it mmapped; 6490 `memory.high` events in ten minutes; PSI some avg10 15 %. A full
  event-history verify reads 1.25 GB of sealed segments, all charged to the daemon.

## Invariants

- **Visibility.** A launch that is refused or deferred is a collection failure with its reason,
  never an empty success; a medium coverage finding stays while the gate is degraded.
- **Bounded concurrency.** At most 2 gated launches daemon-wide, 1 while degraded.
- **Bounded waiting.** No caller waits for a slot longer than its own timeout (max 60 s).
- **Bounded backoff.** After 4 consecutive transport failures new launches pause 30 s, doubling
  to 300 s; then exactly one probe; its success closes the gate.
- **No retry storm.** The empty-output retry in `ps_json` runs only while not degraded.
- **Protection first.** Launches that restore protection or wait on the owner (input-hook
  per-session start, the elevation prompt) are never gated.
- **Slots cannot leak.** Released in `finally`; a timed-out child is killed by `subprocess.run`.
- **Cache.** Sealed segments read once for verification are released from the page cache
  (`posix_fadvise DONTNEED`); repeatedly read data (the database, query reads) is not.

## Design choice

| option | verdict |
| --- | --- |
| **daemon-wide admission gate in `spawn()` + circuit breaker** | chosen: the one choke point every gated launch passes; bounded and testable |
| per-lane limits | rejected: lanes would still sum to 3+ concurrent launches |
| fewer collectors / longer intervals | rejected: loses visibility on a healthy relay to fix a degraded one |
| a long-lived PowerShell host (one process, many queries) | strongest reduction in launches; reconsider if the gate measures sustained degradation, it is a larger change to every collector |
| raise MemoryHigh | rejected for now: the cache is one-shot reads, not working set; owner sets the ceiling |
| SQLite `mmap_size=0` | rejected: mmapped pages measured at 12 MB, not the cause |

Page cache: measured on real segments, reading 59 MB packed added up to 44 MB of cache without
advice and 0 MB with it, in the same time (1.7-2.0 s).

## Validation

`tests/test_interop_gate.py` (fake clock: limit, waiter, trip, backoff doubling and cap, one
probe, recovery, degraded window, refusals not extending backoff, slot release on timeout,
`expect_output`, ungated bypass, `ps_json` no-retry, coverage finding not an outage) and
`tests/test_pagecache.py`. After deploy, measure against the 2026-10-25 baseline: `memory.events
high` rate, `memory.stat file`, PSI, `defender_runs` "no payload" rate, relay accept stalls per
minute, and whether `wake-jarvis.ps1` logs another `wsl --shutdown`.

Reconsider when: the gate is degraded for more than a few minutes a day (move to a long-lived
PowerShell host); `memory.high` events stay high after release (look for another one-shot reader).
The watchdog itself (`wake-jarvis.ps1`, owner-installed) still has only `wsl --shutdown` as a
remedy; a staged, gentler recovery for it is proposed separately and is the owner's to install.
