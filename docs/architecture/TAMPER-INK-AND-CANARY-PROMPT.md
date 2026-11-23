# Prompt: tamper-evident "permanent ink" + canary tokens that alert the owner

Goal, in the owner's words: if the machine is infiltrated, make whatever JARVIS
recorded impossible to quietly rewrite ("ink it with permanent ink"), and plant
bait that, when an intruder takes and opens it, raises the alarm to the owner —
"a signal that reaches the attacker's world and comes back to us."

This is two defensive capabilities. Read the hard line first, because it decides
what is in scope.

## The hard line (what this must never become)

The signal acts on the **owner**, never on the attacker. JARVIS must not, now or
later, contact, scan, exploit, beacon to, or run any code on attacker-controlled
infrastructure or a third-party machine. There is no "hack-back". A canary token
is **inert data**: a fake credential string, or a document carrying a URL that
points only at infrastructure the owner controls. The only thing that ever
"reaches" the attacker is bait sitting still; the only thing that comes back is a
log entry the attacker's own client produced by voluntarily opening the bait.
Anything that would act on the attacker's side is refused, whatever it is called.

## Part A — the permanent ink (tamper-evident evidence ledger)

A hash-chained, append-only ledger. Each record carries its monotonic sequence,
its content hash, and the hash of the previous record. Deleting, editing, or
reordering any record breaks the chain at a verifiable point. The chain is
replicated append-only off this box (a second host or object-lock/WORM store the
daemon can add to but not erase), and the chain head — just the top hash, its
sequence and time — is anchored externally on a schedule (the existing OTS
anchor path). That external anchor is the real indelible mark: a short
fingerprint the attacker cannot retract, that later proves exactly what the
ledger said at that moment. Invariants: no gap in the sequence without a recorded
reason; a verify pass detects any edit, deletion or reorder and names the first
broken link; the anchor commits to the head the owner actually held; the ledger
only appends (a writer that truncates or rewrites is a bug the tests must catch).

## Part B — the canary tokens (bait that alerts the owner)

A planter generates uniquely-identified inert bait — a plausible fake AWS-style
key, a watermarked document carrying a unique owner-controlled tracking URL, a
decoy credential file — and records each token (id, type, planted path, content
fingerprint) **in the Part A ledger**, so an intruder cannot quietly delete the
record of what bait existed. Two independent detections, both raising findings
through the normal collector path:

1. **On-box tripwire.** When bait is read, opened or copied on this machine,
   JARVIS notices through telemetry it already collects (Sysmon FileCreate / file
   access, the native sensor) and raises a high finding naming the token.
2. **Off-box callback (owner's own listener).** The tracking URL resolves only to
   infrastructure the owner controls. When the attacker opens the bait elsewhere,
   their client fetches that URL; the owner's listener records the connection
   metadata the client reveals (source IP, user-agent, time, token id) and
   nothing else. JARVIS ingests those hits and raises a critical finding: this
   bait left the machine and was opened — data was exfiltrated. JARVIS does not
   host the listener as an exposed service by default; it ingests hits the owner
   has collected.

Invariants: a token is inert and runs no code anywhere; its callback target is
owner-controlled and configured, never defaulted to a third party; the token
registry lives in the tamper-evident ledger; a tripwire finding is never raised
by JARVIS's own legitimate access to the bait (the planter and verifier are
excluded); absence of a callback is never read as "safe" (it only ever confirms,
never clears). Metadata only: no attacker payload is fetched, stored, or executed.

## Validation

Write tests for both parts before trusting them: ledger append/verify including a
deliberately edited, deleted and reordered record; the anchor committing to the
right head; token generation and registry round-trip; the on-box tripwire firing
on bait access and staying silent on the planter's own access; callback ingestion
raising the critical finding and tolerating malformed/replayed hits. Run the full
unit suite. Get a bounded, metadata-only Jev advisory on the design and the
implementation — advisory only, no authority over the hard line above.

## Built 2026-10-12 (checkout; not yet live)

- `jarvis/core/canary.py`: inert token generation (`file_decoy`, `doc_url`,
  `credential`), the append-only hash-chained journal (`CanaryJournal` with
  `append`/`verify`/`head`/`state`), the on-box fingerprint tripwire
  (`onbox_trips`), owner-listener callback ingestion (`read_callbacks`,
  metadata-only, bounded), and external anchoring of the head (`anchor_head`,
  injected submit, OTS by default).
- `jarvis/collectors/host/canary.py`: the `canary` job — verify, tripwire,
  ingest, anchor-when-due, findings. A broken chain is critical and halts
  further writes. Registered in `schedule.py` (300 s) and `jobs.py` RUNNERS.
- `tests/test_canary.py`: 27 tests, all passing — chain verify incl. edited /
  deleted / reordered records; inert token generation; tripwire modified /
  removed / weak-access; callback ingestion incl. malformed / oversized /
  deduped; anchoring incl. interval, failure-stays-advisory, network-off;
  collector end to end incl. tamper-halts-writes.
- Jev (jev-1.13.0), advisory only: defensive-only 0.96, tamper-evident 0.95,
  metadata-only callback 0.93, atime-off-by-default 0.89, live run still
  required 0.95.

### What is NOT done (honest blind spots)
- No live run on the daemon yet, and no owner-facing planting command. Plant
  today from a Python shell on the box:
  `python3 -c "from jarvis.core import canary; print(canary.plant('file_decoy', 'ssh key', path='~/.ssh/id_rsa_BACKUP'))"`
  (point it at a *decoy* file you created, never a real key).
- The off-box callback needs the owner's own listener: a tiny web endpoint on a
  host you control that appends `{"hit_id","token","ip","ua","at"}` lines to a
  file, and `canary.callback_inbox` in `~/.jarvis/config` pointing at that file
  (reachable from here). JARVIS only reads that file; it hosts nothing and
  contacts no one.
- On-box read-detection today is fingerprint drift (modified/removed) plus an
  optional weak atime signal. Catching a pure *read* or *copy* reliably needs a
  Sysmon FileCreate(11)/RawAccessRead(9) lane — a follow-up in `sysmon.py` +
  `sysmon_policy` baseline.
- `assurance.py` is intentionally not updated: this capability has no measured
  live evidence yet. Update it only after a live planting + daemon run + a
  verified trip, per the Maximum Assurance directive.

### The hard line held
Nothing here contacts, scans, exploits, or runs code on an attacker or third
party. The token is inert; the only outbound thing is a 32-byte anchor digest to
the OpenTimestamps calendars; the callback is the attacker's own client fetching
the owner's URL, read back from the owner's own log. No hack-back.

### Suite status
Full suite after this slice: all green except the one pre-existing
`test_decoding` failure on `jarvis/service/outages.py` (an untracked file from
another lane, failing before this work). The canary slice added four contracts
and satisfies them: layer order (core imports no platform; the collector takes
config from `jobs.py` rather than importing `response`), a `JOB_COMMANDS` entry,
a score area ("Monitoring"), and lenient journal decoding (a corrupt byte is a
reported chain break, never a crash).
