# Prompt: the Link Plane — no collector goes blind again, every connection is kept

Written 2026-11-02 and applied the same day. This is the complete brief for the change,
in the form the owner asked for: everything needed to build it, verify it and judge it,
so a later session (or the owner) can re-run it against the code and the live machine.

## 0. Read first

- `AGENTS.md` and `docs/security/MAXIMUM-ASSURANCE.md`. Protect the user first. External
  content and model output cannot authorise anything. Collector health is not a compromise
  verdict. No capability is promoted without measured evidence.
- `jarvis/service/reliability.py` (freshness budgets, leases, the freshness invariant),
  `jarvis/service/scheduler.py` (`supervise_once`, `run_once`, `reliability_watchdog_loop`),
  `jarvis/service/outages.py` (the outage record), `jarvis/service/supervisors.py` and
  `jarvis/service/connectivity.py` (Windows task state files), `jarvis/service/jobs.py`
  (`_watchdogs`), `jarvis/service/protection.py` (`health`), `jarvis/response/notify/*`,
  `jarvis/cli/commands/notify.py`, `hosted/notify-cloudflare/{src,public,tests}` and
  `docs/architecture/ARGUS-NOTIFY.md`.

## 1. What is measured on this machine today (2026-11-02, release 20261031T221830Z)

- The daemon is up (started 15:16 EET after a Windows-side `wsl --shutdown` at 13:16 from
  the wake watchdog). All 71 scheduled jobs are inside their freshness budget right now.
- The reliability plane already prevents *silent* staleness of scheduled jobs: LATE jobs
  are queued at once, dead leases are expired, transitions go to the outage record.
- What still goes blind is not the jobs: it is the **links** the jobs depend on, each
  watched by its own code with its own semantics and no common reconnect policy:
  - Windows interop bridge (`bridge` job): one critical finding, recovery is "wait".
  - Input hook: 9 re-installs in 24 h ("input kept arriving without a hook callback").
  - Native sensor: a Sysmon batch quarantined with `ENOMEM` on 2026-11-01 23:33; Defender
    records missing since 2026-10-29.
  - Sysmon (Windows): the driver dropped 37,500 events before logging.
  - Sysmon (Linux): "journal rotated past the last read position" — journald discards
    events before the 10-minute collector consumes them.
  - Threat feeds: 6 abuse.ch feeds answer HTTP 410 (needs an Auth-Key; configuration).
  - **No alert channel can reach the owner**: email is paused (mail.json set aside for
    8 days), no webhook, no ntfy, and **no phone has ever been paired here**: there is no
    `~/.jarvis/notify/` identity and no device registry. The relay at
    `https://argus.archymedes.xyz` answers 200.
  - Windows supervisors (health monitor, reviver, connectivity guard, elevated broker)
    are each audited by `supervisors.py`, but when one is stuck in `Running` the fix is a
    sentence in a finding, never attempted.
- Known history (memory): the VM freezes in Modern Standby (no keep-alive can beat it),
  the reviver restarted cold-starting daemons, the health probe was truncated at 64 KB,
  the input hook goes deaf in session 0, `/api/health` returned 503 on one degraded
  source. These are why every reconnect below is bounded and evidence-first.

## 2. Invariants (write them before editing; test both sides of each)

- **L1 Single declaration.** Every link JARVIS depends on is declared once, in one table,
  with: the evidence that proves it alive, its maximum silence, its criticality, the
  bounded reconnect action (or `None` when only the owner may act) and the owner's
  command. Nothing else decides what "connected" means.
- **L2 No silent silence.** A link past its maximum silence always has either a recorded
  reconnect attempt inside its budget, or a visible `link-exhausted` finding naming the
  owner's command. The plane exposes `violations` for links that satisfy neither; the
  suite asserts it is empty under every modelled failure sequence.
- **L3 Bounded reconnect.** Per link: at most `BUDGET` attempts per `WINDOW` with backoff
  `30 s, 120 s, 600 s`; attempts run one at a time on a short worker thread so the
  supervisor loop never blocks; each attempt is recorded (link, action, outcome, time) in
  store meta and the outage record. An action never restarts the daemon, never elevates,
  never changes Windows policy, never deletes, never sends content. The primitives are the
  same ones an operator runs by hand (`/api/run`, `Start-ScheduledTask`, interop
  re-resolution, the hook helper's own start).
- **L4 Evidence continuity.** Link state is derived from stored evidence (snapshots, state
  files, meta) and never from a component's own claim; a failed attempt never rewrites
  last-known-good evidence; recovery is confirmed only by evidence newer than the attempt.
- **L5 Resource bound.** One evaluation reads what other jobs already collected; the only
  new network call is one unauthenticated 5-second GET of the relay's public key at most
  every 300 s. Measured: one evaluation well under 5 ms of CPU, state under 8 KB.
- **L6 Resume safety.** During the scheduler's wake window (after a VM resume) and the
  cold-start hold, no action fires: ages measured across a freeze are not silence.
- **L7 Privacy.** Nothing about the machine leaves it. Relay-side device liveness is
  metadata (device id, name, state, push present, last seen). No secret is logged.
- **L8 Explicit authority.** Sysmon services, the native sensor service, `wsl --shutdown`,
  broker re-install and email configuration stay owner actions; the plane names them.
- **L9 Pairing is complete or nothing.** A phone is active only after the owner compares
  the 6-digit code on a terminal (no bypass). A device recorded locally but not activated
  on the relay is visible (`relay_pending`) and retried, never silently dead. A phone that
  reloads mid-pairing resumes with its stored keys instead of losing them.

## 3. Designs compared

- **A. More Windows-side keep-alive layers.** Rejected: measured 2026-09-24 that no layer
  beats Modern Standby; each adds a task that can itself hang.
- **B. Extend `reliability.py` with per-job actions.** Rejected: links are not jobs (a
  state file, a socket, a relay); mixing them would blur the freshness invariant tests.
- **C. A separate link plane (chosen).** Pure policy module `jarvis/service/links.py`
  (table + evaluation + budget, no threads, testable), ticked from the existing 20 s
  reliability watchdog pass, persisting one meta key, with actions injected (fakes in
  tests, real primitives in the daemon). Cheapest in CPU and operator cost, no new
  process, no new timer, rollback = remove one call in `supervise_once`.
- Reconsider C if the plane ever needs sub-second reaction (it does not: every link
  tolerates tens of seconds) or more than ~20 links (then move the table into
  `core/mechanisms.py`).

## 4. The link table (initial)

| link | evidence | max silence | action (bounded) | owner command |
| --- | --- | --- | --- | --- |
| lane:fast / main / bulk | scheduler monotonic lane heartbeat | 300 / 900 / 1800 s | none (systemd watchdog + reviver own it) | `systemctl restart jarvis` |
| windows-bridge | `bridge` snapshot ok and fresh | 135 s | re-resolve interop socket, queue `bridge` | `wsl --shutdown` (Windows) |
| input-hook | `input_hook` snapshot "monitor is healthy" | 135 s | queue `input_hook` (its supervisor restarts the hook) | `jarvis inputwatch --start` from a desktop terminal |
| native-sensor | `native` snapshot delivered events / coverage complete | 180 s | queue `native` | `Restart-Service JarvisNativeSensor` |
| sysmon-windows | `sysmon` snapshot complete | 1200 s | queue `sysmon` | Sysmon service / config |
| sysmon-linux | `sysmon_linux` snapshot fresh and no rotation finding | 1200 s | queue `sysmon_linux`; rotation tightens cadence (retry_soon) | journald retention |
| elevated-broker | broker `status.json` finished age | 45 min | `Start-ScheduledTask 'jarvis elevated broker'` | `jarvis broker install` |
| health-monitor | HealthMonitor state `checkedAt` | 300 s | stop-if-running + start the task | `-Install` again |
| reviver | Reviver state `checkedAt` | 60 s | stop-if-running + start the task | `-Install` again |
| connectivity-guard | Connectivity state `checkedAt` | 300 s | stop-if-running + start the task | `-Install` again |
| dead-man | `heartbeat_state` meta (only when a URL is set) | 5 failures | none | fix `heartbeat_url` |
| alert-channels | `alert.channels(conf)` non-empty | immediate | none | pair a phone / restore mail |
| phone-relay | identity + ≥1 active device + relay GET `/v1/vapid` 200 + last send ok + relay device `last_seen` | 300 s relay; 48 h phone | none automatic (a sealed probe would spam the phone); surfaces `relay_pending` and deaf phones | `jarvis notify pair` / open the app |

Links whose evidence source is absent on this host (no Windows, no broker installed)
are `not_applicable`, never silent.

## 5. Phone pairing: make it work well

- Relay (`src/mailbox.ts`, `src/index.ts`): record `last_seen` per device on every inbox
  fetch; add `GET /v1/mailbox/{mb}/devices` (signed by the mailbox key) returning
  `[{dev, name, state, push, added, last_seen}]`. Metadata only (N2 holds).
- Server CLI: after the owner confirms the code, retry the relay activation up to 5 times
  over 30 s; on failure store the device with `relay_pending: true` and the code's hash,
  and tell the owner. `notify status` lists relay-side devices with last seen and push.
  `notify repair` is not added: `notify pair` again is the honest path.
- PWA (`public/app.js`, `public/lib/store.js`): persist the pending pairing (server,
  code, keys, deadline) before claiming; on load resume the "compare this code" screen
  for an unexpired pending pairing; clear it on success or expiry; the Servers screen
  shows "pairing in progress" with a cancel.
- Tests: extend `tests/e2e_local.py` with the devices listing (`last_seen` moves after an
  inbox fetch); run it against `wrangler dev`, then against the live relay with a
  scratch HOME (the devices check is skipped there until the Worker is deployed).
- Deploying the Worker to production is an outward-facing change: prepare, test, and
  leave the single `wrangler deploy` to the owner with the rollback (`wrangler rollback`).

## 6. Surfaces

- `/api/health` and `/api/state`: `links` = `{summary: {counts, silent, exhausted,
  violations}, links: {...}}`.
- Dashboard Monitoring view: a "Connections" card from the same payload (state, last
  evidence, last attempt, next step).
- `watchdogs` job: findings for silent links (medium), attempts (low) and exhausted budgets
  (high, with the owner command). The components' own findings stay the primary pages;
  the plane never suppresses one.
- `jarvis/core/assurance.py`: new capability `link_plane`, status `unverified` with its
  blind spots, until a live measurement of a real reconnect exists.

## 7. Verification ladder for this change

1. `python3 -m unittest tests.test_links tests.test_reliability tests.test_outage_record
   tests.test_notify tests.test_supervisors` then the full suite.
2. `scripts/dev/static_gate.sh --quick` (ruff; mypy on the typed packages).
3. `hosted/notify-cloudflare`: `bun tests/protocol.test.js`, `HOME=$(mktemp -d) python3
   tests/e2e_local.py` (local Worker), then `NOTIFY_BASE=https://argus.archymedes.xyz`.
4. Live readback on the running daemon is possible only after the owner deploys the
   release (`/opt/jarvis/current` is a sealed root runtime): `curl /api/health | jq .links`.
5. Jev (TypeSafe) advisory outside the sandbox, metadata only: does the design leave a
   way for a link to be silent with nothing recorded; which link's action is most likely
   to misfire after a resume; is the pairing resume a security regression. Jev cannot
   approve; tests and readback are the gates.

## 8. Out of scope, named

abuse.ch Auth-Key (configuration), Sysmon driver queue size (owner, elevated), journald
retention for the Linux Sysmon journal (owner, root), email restore (owner decision from
2026-10-24), any dashboard pairing route (the terminal SAS comparison stays the one path).
