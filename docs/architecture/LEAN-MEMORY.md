# Lean memory: where Argus's RAM goes and the architecture that keeps it small

Owner request 2026-11-06: "make argus use less ram, create the best architecture for it".

## Measured on this host (2026-11-06, WSL2, 8 GB)

Live daemon (`jarvis.service`, release of 2026-11-05):

| what | amount |
|---|---|
| daemon resident | 617-835 MB (595 MB anonymous, 240 MB file-mapped) |
| service cgroup | 2.07 GB now, 2.69 GB peak, of which 1.44 GB page cache and 114 MB kernel |
| per-job growth of the daemon (scheduler `job_cost`) | resources +174 MiB, evidence +34, hunt +20 |
| `native` isolated child peak | 820 MB, every 60 s |

On a 961 MB copy of the live store, one job at a time (`scripts/dev/job_cost.py`, then
SQLite settings varied):

| job | today: 64 MiB cache + 256 MiB mmap | no mmap | 4 MiB cache, no mmap |
|---|---|---|---|
| hunt | 305 MB peak | 102 MB | 38-44 MB |
| sysmon_linux | 360 MB | 142 MB | 87 MB |
| `/api/state` build | 406 MB | 153 MB | 91 MB |

Python objects are a small part of those peaks (tracemalloc: hunt 19 MiB, sysmon_linux 53 MiB).
The rest is SQLite's private page cache and memory map, per connection, plus glibc keeping
freed pages: after a hunt run the process kept 105 MB; `malloc_trim(0)` returned it to 38 MB.

`native` opens the event log writer in a fresh child each minute: one read-only open of the
real log costs 2.4 s CPU and ~149 MB (3,448 chain headers parsed), before any ingest.

## Root causes

1. **Per-connection SQLite memory.** Every job and every API request opens its own
   connection; each lane keeps one for its life. Each had a 64 MiB private cache and mapped
   up to 256 MiB of the database into its resident set: five lanes and a few requests is
   over a gigabyte of duplicated copies of what the kernel page cache already holds once.
2. **Allocator scatter.** One thread per lane and per request; glibc gives threads their own
   arenas and keeps freed page-sized blocks there, so resident memory ratchets to past peaks.
3. **Cold isolated children.** `native` is isolated (a 9P/interop hang must not take the
   daemon down), but a new child each minute re-parses the whole event-log chain.
4. **Page cache in the service cgroup.** Reclaimable, but under WSL it is memory the VM holds
   from Windows; the unit's MemoryHigh was raised to 2.5 GiB to stop throttling.

## Designs compared

| design | RAM effect | costs | verdict |
|---|---|---|---|
| A. isolate every heavy job in a per-run child | peaks vanish on exit | +0.3-2.4 s CPU per spawn, cold caches every run (native shows it) | rejected as the general rule |
| B. right-size the storage and allocator layer | removes causes 1-2 for every job and request | ~10% more CPU in the measured workload (below) | **phase 1, built** |
| C. persistent, bounded, isolated workers | removes cause 3: warm state, isolation kept, recycled past a memory ceiling | a worker protocol, writer-lock hand-over, crash recovery | **phase 2, designed** |
| D. lower the cgroup ceilings | bounds cause 4 | throttling if set below the steady state | **phase 3, after live readback** |
| E. rewrite the daemon in Rust | potentially the smallest | months, re-validating every collector | rejected now |
| F. raise limits (status quo) | none | hides the problem | rejected |

Why B first: it is the smallest change at the actual bottleneck, it applies to every job,
request and future collector at once, and it changes no evidence, schedule or result.

## Phase 1 (this change)

- `core/store.py`: `CACHE_KIB = 4096` (was 64 MiB), `MMAP_BYTES = 0` (was 256 MiB).
  WAL, `synchronous=FULL` and the busy timeout are unchanged.
- `core/memory.py`: `limit_arenas()` (glibc `M_ARENA_MAX=2`) before any thread starts in
  `serve`; `trim()` (`malloc_trim(0)`, at most every 5 s) after every scheduler job, in the
  lane's `finally`, and after every API request in `Handler.finish`. No-ops off glibc
  (Windows edition, musl, macOS); never raise.

Daemon-shaped workload (`scripts/dev/daemon_memory.py`: four lanes as threads, each holding a
connection for its life, running hunt, evidence, sysmon_linux, scan, rust_mirror and two state
builds twice, on the store copy), three paired runs at load average 6-11:

| | before | after |
|---|---|---|
| peak resident | 814-891 MB | 111-149 MB |
| anonymous at the end | 169-231 MB | 37-49 MB |
| CPU | 29.7-42.8 s (mean 36.4) | 34.4-43.6 s (mean 40.0) |

The CPU cost (~10%) is reads served through the shared page cache instead of a private cache
and a map; within noise for the state build alone (3-4 s per call in every setting).

## Invariants and how they are held

- **Evidence and durability:** no table, query, schedule or result changes; WAL and FULL sync
  asserted by `tests/test_memory.py`; a small cache still reads a 13 MB table correctly.
- **Never blocks protection:** trim and arena calls never raise (tested with a failing libc);
  a lane trims after a job that raised and keeps running; a request trims even when closing
  the connection fails; arenas are capped before the scheduler starts any thread.
- **Real effect, not a mirror:** a child frees ~199 MB from four threads; with the trim RssAnon
  drops to 6 MB, without it stays at 199 MB (checked by disabling the call).
- **Bounded:** at most one trim per 5 s; no new threads, files or network. A trim holds
  glibc's arena locks while it runs (other threads' allocations wait): measured 6-10 ms on a
  160 MB half-freed heap from four threads and 46-166 ms on a deliberately extreme 961 MB one;
  after phase 1 the daemon's heap is about 100 MB.

Jev (jev-1.14.0, advisory, `scripts/reviews/lean_memory_advisory.py`): storage and allocator
first (0.72), the CPU trade acceptable (0.86), the risk most worth a live check the trim pause
(0.45, measured above) then API latency (0.33); next phase persistent workers (0.50).

## Phase 2: persistent isolated workers (designed, not built)

One long-lived worker per isolated collector family (first: `native`), started by the
scheduler and spoken to over a pipe with the same JSON result the per-run child returns today:

- keeps the event-log writer open between runs (no 2.4 s / 149 MB cold open each minute);
- same deadline as today: a run that misses it kills the worker, the result is the same
  "unavailable" receipt, and the next run starts a fresh worker (isolation preserved);
- recycled when its resident memory passes a ceiling or after N runs, between runs only, so
  a writer lock is never held across a recycle;
- the writer lock stays the single-writer guarantee; a crashed worker's lock is released by
  the kernel on exit, as it is for today's child.

Invariants to test before building it: cursor integrity across a worker kill mid-ingest
(replay from the last committed cursor, no duplicate sequence numbers), lock release on
crash, deadline enforcement, recycle never during a write, and the same receipts as today.

## Phase 3: ceilings (after live readback)

After phase 1 is deployed, read back the daemon's RssAnon and the cgroup's anon and file
counters for a day. Then lower the `MemoryHigh` drop-in (2560M today) to about twice the
measured steady state, so the kernel reclaims this service's page cache before it
competes with the rest of the machine. Owner sudo; never below the measured peak.

## What would make us reconsider

- live readback shows anonymous memory still growing after phase 1: profile the lanes in
  place (job_cost already records per-job growth) before tuning further;
- a collector that measurably needs a large cache (CPU or latency regression in readback):
  give that one connection a bigger cache, not all of them;
- phase 2 measurements show the warm worker does not save what the cold open costs.

## Verify after deploy

    systemctl show jarvis.service -p MemoryCurrent,MemoryPeak
    grep -E 'VmRSS|RssAnon|RssFile' /proc/$(systemctl show -p MainPID --value jarvis.service)/status

Baseline before phase 1: RssAnon 595 MB, RssFile 240 MB, cgroup 2.07 GB (peak 2.69 GB).
