# Persistent forensic history book

## Invariants recorded before implementation (2026-10-01)

1. Existing canonical event bytes, sequence, cursor and segment hashes stay unchanged. No automatic removal of sealed evidence, even at the storage limit. A previously pruned range stays an explicit historical gap.
2. An exhausted storage budget refuses a new batch before writing or advancing its cursor. Native source acknowledgments must not advance past an uncommitted batch. Existing collection and protection continue with explicit history failure.
3. A process observation is a sampled observation, never an invented start/exit event. Keep host, PID, start identity, parent PID, image and observation time; omit command lines, communications, document content and environment values.
4. Query and export consume committed events only. Readers never repair the evidence or mutate the index. Sequence order remains authoritative when source clocks disagree; preserve source and receipt times separately.
5. Case exports include original committed event records, sequence range, source gaps, chain head and content digests; publish a completion manifest only after data are durable. Never overwrite a prior export. An interrupted export is visibly incomplete and cannot verify as complete.
6. Resource bounds are explicit: history space budget, process count, query scan/output limits, export byte/event limits, bounded lock retries. Reaching a bound is partial/blocked evidence, never an empty successful result.
7. Local hashing and an administrator-only vault are not administrator-proof immutability. No remote upload, cloud account configuration, irrevocable retention, encryption-key change or privileged filesystem policy change is implied by this feature.
8. Tests cover restart, torn writes, missing/modified records, exhausted capacity, source acknowledgment, lock contention/retry exhaustion, privacy and query/export limits. Live readback must distinguish checkout code from deployed service code.

## Design comparison

| Design | Benefits | Costs / limitations |
|---|---|---|
| Keep the existing canonical log, forbid pruning, bounded sampled observations, read-only history/query/export | Preserves source identities and custody, reuses indexing/vault/anchors, no new daemon/database authority | Snapshot blind spots remain; disk capacity requires operator attention; local administrator can alter files |
| Second full history database | Convenient relational queries | Duplicated authority and retention, more writes, index/evidence disagreements, still deletable |
| Immediate remote WORM as sole store | Independent retention against local administrators | Provider/account/key dependency, privacy transfer, irreversible retention choice, network outage path required |

Choose the first design, with independently retained case exports and future WORM archival. Reconsider if measured scan/write latency, disk growth, or offline backlog exceeds the bounds. Do not claim remote durability from a local export or a hash.

## Forensic research

- [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final): centralized collection, integrity checks, reliable long-term formats, retention and operational review. The 2023 revision is an initial public draft, not a final replacement.
- [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final): preserve original evidence and timestamps, verify copies with digests, document collection/handling, examine copies rather than modify originals. A hash is evidence of byte consistency, not proof that the source told the truth.
- [Amazon S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html): WORM protection applies to object versions. Compliance retention prevents deletion/shortening even by the account root during the period (account deletion is an exception). Governance can be bypassed by specifically permitted actors; legal holds can be removed by an authorized holder. Version IDs, retention receipts, independent access controls and preserved encryption keys are needed for recoverability. This is a researched deployment option, not configured protection.

The existing JARVIS custody job stages sealed segments to the administrator-only Windows vault and uses OpenTimestamps digest witnesses. Actual vault permissions, copy completeness, timestamp confirmation and surviving independent witnesses must be measured; their presence in source code does not establish durability.

## Deployment and measured results

Local protected vault chosen by the owner; no external evidence storage configured.

History scope: supported existing native Windows events plus new sampled WSL/Windows process-presence records. Other collectors' current-state database rows and dashboard trend points remain rebuildable/retained on their existing policies; they are not a promise of complete canonical coverage. No key/text/communications collection was added.

Segments become seal-eligible after five minutes (monotonic progress in a live writer, checked on ingest/scan passes). The existing custody job runs every 15 minutes. Active/unvaulted tails remain vulnerable to local deletion until copied. Offline/sleep/scheduler outages can extend that lag; no fixed end-to-end guarantee is claimed.

Commands:

```sh
jarvis history status
jarvis history query --source-host wsl --after 0 --limit 100
jarvis history query --image firefox --since 2026-10-01T00:00:00Z
jarvis history verify
jarvis history export --after 880000 --until 880500 --case /absolute/new-case-directory
jarvis history verify-case --case /absolute/new-case-directory --anchor MANIFEST_SHA256
```

Queries return `next_after` and `truncated` for bounded pagination. Default query output omits raw records, command lines and arbitrary attributes; `--raw` explicitly includes original local data. Source timestamps filter records but never reorder ingest sequence. A case includes complete overlapping source segments and the committed active prefix, so it can include adjacent private records. Keep it owner-only. Keep its manifest digest on an independent device for meaningful rewrite detection. Exports never overwrite a prior case; incomplete copies remain marked incomplete by the absence of a final manifest. A case is a documented copy of observed evidence, not a substitute for disk acquisition or complete court-admissible custody procedures.

Measured predeployment: live history had 125 sealed segments, ~239 MB sealed data and no pruning; custody receipt reported 125 vaulted, no divergence, 18 confirmed independent timestamp proofs and 1 pending. Read-only 20-row query took 0.254 s. Initial real 500-event case took 22.5 s / ~314 MiB peak RSS; streaming refinement produced a separate real 100-event case in 17.3 s / ~51 MiB peak RSS, including full retained source verification, and verified against its manifest digest. The two case copies are retained under `~/.jarvis/cases/`. Source-segment copies include adjacent events, hence 14–16 MB exported for these narrow ranges. Three isolated snapshots of the real inventory's 398 process metadata rows produced 1,197 canonical records, used 0.128 CPU seconds / 0.908 wall seconds, ~21 MiB peak RSS, and compressed to 65,423 bytes. This is a microbenchmark, not sustained service overhead.

Jev was called with engineering metadata only: Choice selected canonical-log reuse with concentration 1.0; Noul probability 0.98 that administrator deletion remains a limitation. Advice supported the selected design and its explicit boundary, not deployment authorization. A final implementation review and deterministic verification remain required.

Existing event history is not backfilled with invented process snapshots. A process that starts and exits between snapshots remains outside snapshot coverage. The scan can reuse a recent provider cache; snapshot receipt time does not independently attest source freshness. Case validation digests were generated locally; passing them back tests byte consistency, not independent off-device custody.

Validation: the permitted host full checkout suite passed 1,908 tests; the final focused history/native/layer checks passed 64 tests, including backward-clock sealing. The sandbox suite failed with 91 errors and 8 failures caused by restricted filesystem, interop, ownership and host-path fixtures; it was not used as product evidence. Final Jev implementation review again selected canonical reuse (Choice concentration 1.0), with Noul 0.97 for the administrator-deletion limit and 0.96 for incomplete forensic coverage.

## Completed handoff and pending activation

The exact narrow candidate passed **1,692 tests** on the host. Candidate directory: `~/.cache/jarvis-release-staging/20261001-history-book`. It is the running sealed base plus ten reviewed files; unrelated checkout changes are excluded. Stage base: `sha256:db8fb2bdb4b2b972c82804257c9fbd646ba10222231eeafeae0e7aaa19f118f5`.

Administrator activation was attempted only through the documented release path. `sudo -n` returned `sudo: a password is required`; no release switch/restart occurred. The existing service remains active/running, PID 226, zero restarts, healthy/ready/protection_healthy and fresh scan/native/bridge receipts. This is an authentication requirement from the host, not an automatic approval-review rejection.

Before touching the protected history, the installed release's existing evidence-hold/prune behavior was validated on an isolated log. A finite hold was then appended to the real history for **sequences 1 through 883,572**, preserving records already committed from automatic retention. Existing 125 sealed segments, head hash and zero historical pruned ranges were retained. This protects the selected existing range against JARVIS retention; it neither protects future records outside the range nor prevents manual/administrator deletion. The finite hold reserves existing evidence rather than silently enabling unlimited legacy recording.

The new capacity guard, five-minute monotonic sealing and scheduled process snapshots are **staged, not live**. The checkout's history review commands and verified case copies work, but do not imply that the old daemon is running the new preservation policy. Source indexes/dashboard trends/Rust mirror remain projections with their existing retention; canonical custody does not magically fill unsupported sensor gaps.

Run in the owner's WSL terminal (enter the password there, never in chat):

```sh
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
  --source ~/.cache/jarvis-release-staging/20261001-history-book \
  --checkout ~/jarvis \
  --expect-base sha256:db8fb2bdb4b2b972c82804257c9fbd646ba10222231eeafeae0e7aaa19f118f5 \
  --skip-tests
```

If the base changed meanwhile, restage rather than bypass the gate. Then use `scripts/reviews/history_book_readback.py` through the permitted host path to verify the new release, old head ancestry, fresh observations on both hosts, no recording-blocked finding, and custody readback. Trigger the existing evidence job after new segments seal if a bounded fresh receipt is needed. Verify several scan/native intervals; rollback with the documented `--rollback` path if health or evidence continuity regresses. No new scheduled-service or vault-custody success is claimed before that readback.
