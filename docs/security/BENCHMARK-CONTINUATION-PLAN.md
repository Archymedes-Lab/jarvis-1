# Benchmark continuation plan (2026-11-10)

Purpose: complete the interrupted detection work without mistaking text replay for
live protection or treating community content as authority.

## Invariants before edits

- Privacy: inspect local bytes read-only; retain metadata and findings, never content.
  Reject symlinks in every path component and special files, including replacement races.
- Identity/freshness: cache verdicts only for the same device, inode, ctime, mtime,
  size and rule generation. Unreadable, changed and unvisited evidence stays unknown;
  prior positive findings survive an interrupted pass.
- Bounds: discovery as well as reading has entry, byte and elapsed-time limits.
  Never evaluate negative conditions against a partial file as if it were complete.
  Report omitted, oversized and inaccessible evidence explicitly.
- Authority: every community finding remains advisory after storage round trips.
- Recovery: benchmark actions run only on disposable infrastructure; attempt cleanup
  only for attempted actions, even on partial failure; report failed undo and collector
  failures, and return failure for incomplete measurements.
- Evidence: preserve the pinned replay corpus and report reproducible counts. No
  promotion to deployed, live-tested or containment-validated without measured evidence.

## Designs compared

Keep prefix scans with three-valued condition evaluation, or skip oversized files.
Choose skipping: simpler exact semantics, lower CPU/memory cost, explicit visibility
loss. Reconsider if measured dropped-file sizes justify streaming or a maintained engine.
Keep pathname-only opens, or anchor each component with O_NOFOLLOW directory descriptors.
Choose descriptors: prevents ancestor-link traversal and bounds descriptor lifetime.
Keep metadata cache, or hash every file every pass. Choose identity plus change-time and
rule-generation cache: bounds recurring disk reads; a privileged metadata-forging adversary
remains outside this cache's trust boundary. Discovery remains capped and explicitly
incomplete rather than claiming all files were enumerated or guaranteeing eventual coverage.

## Work and acceptance

1. Audit scanner, compiler, script-block collector and benchmark gates; fix directly.
2. Add adversarial regression checks for path races, cache replacement, rule changes,
   partial reads, discovery exhaustion, interruption and cleanup failures.
3. Register the content collector conservatively and refresh the benchmark document.
4. Run focused tests, complete scratch-HOME suite, static and ASES gates, pinned replay,
   and a bounded metadata-only Jev review. Record failures and limitations.
5. Commit and open a reviewable PR; merge only with required CI green. Run real attacker
   actions solely in the disposable CI workflow after safety review, never on this host.

## Audit fixes and measured checkpoints

- Fixed ancestor-link traversal, replacement/rule-generation cache invalidation,
  partial-file absence evaluation, discovery exhaustion, missing rule/root visibility,
  stale-positive continuity and oversized-file handling.
- Removed PowerShell's process-id-based ten-minute allowance; partial blocks stay
  explicit gaps and do not participate in absence-based matching.
- Compiler now refuses files containing global gates, rejects malformed token tails,
  accepts explicit approved licence labels and verifies the clean input commit.
  This yields 215 rules rather than the interrupted 326-rule build. Updated both
  the licence source snapshot and its generated notices, plus the assurance sample.
- Scanner runs in the governed isolated bulk lane and has its own CLI entry point.
- Live runner now requires network isolation, uses an explicit observation allowlist,
  unique per-run markers, whole-action process-group termination on timeout,
  attempted-action cleanup and explicit failed-cleanup/incomplete-measurement status.
- Pinned replay: 707/1745 matches, Windows 642, Linux 65, benign 0/24, no crashes;
  hash and floor passed. This is replay evidence only.
- Real service dispatch smoke test (`run_job('content', ...)`) on a scratch dropped
  fixture with the shipped rules: one attributed finding, 2.897 s including imports;
  persisted snapshot retains the community marker. This is not a throughput or soak
  measurement and does not promote the capability.
- Jev called through the project client on host networking, fixed metadata only:
  Choice skip-large probability 0.89 (concentration 0.83); Choice live execution as
  validation priority 0.74 (concentration 0.61); Noul production detection established
  by replay 0.03. Advice reinforces the conservative design, changes no authority.
- Follow-up continuity audit: clearing/recreating the PowerShell log could leave
  the old cursor above every new record indefinitely. The reader now returns the
  newest log id; a sequence reset triggers a validated reread from zero with an
  explicit gap. Failed rereads preserve the old cursor. Logging-off remains visible
  even while retained old records are being processed. Regression tests cover both.
- Read-only Windows smoke of the updated reader, scratch store only: two passes
  took 5.06 s and 1.49 s; cursor advanced from 29157869 to 29158113. First pass
  reported a visibility gap, second had no findings. No script content was printed,
  retained in the scratch metadata or sent to Jev; no logging setting changed.
- Live benchmark review also found broad pkill could kill the cleanup shell and
  detached launches could be counted despite failing on noexec shared memory.
  Background scenarios now verify liveness, use /tmp, record their pid and bind
  cleanup to the per-run executable marker. All shell scripts are syntax-checked
  without executing scenarios in the unit suite.

## Local acceptance

- Full scratch-HOME module run completed: 314/317 passed initially. The remaining
  three passed on focused reruns: bulk-lane registration after adding the scanner;
  provenance with a shorter private scratch path (AF_UNIX pathname limit); native
  isolated-channel handoff alone (overlapping checks had caused WSL accept4 timeout).
  No test or product gate was weakened. Final continuity/harness tests ran separately.
- Runtime smoke is read-only/scratch only. Real attack execution remains pending the
  manually dispatched disposable workflow; no result is inferred from workflow source.
- Workflow environment review: sudo filters the runner identity variables, so the
  live step now forwards just GITHUB_ACTIONS and RUNNER_ENVIRONMENT explicitly to
  the isolation gate. A regression check prevents an always-refused live workflow.

## Follow-up: ProgramData registry provenance

Measured read-only ACL metadata on 2026-11-10 disproved the blanket exclusion:
standard user groups have Write rights on the ProgramData root, but only read
rights on the checked Defender vendor folder. No ACL or policy was changed.

Invariants before editing: a pathname cannot establish trusted writer identity;
report security-family changes without reading registry values; retain existing
family deduplication, medium severity ceiling, and bounded tables. Never grant an
exception based on an executable or vendor name an attacker can copy.

Compare a conservative unknown-provenance finding, a bounded independent signature
plus ACL resolver, and blanket suppression. Choose the conservative finding as the
smallest safe immediate fix. It may report legitimate vendor engines; any later
suppression needs measured independent identity and ACL evidence and explicit
failure behavior. The earlier zero-noise claim is superseded, not preserved by
hiding a writable path. Validate arbitrary ProgramData writers, Defender lookalikes,
case/path variants, missing identity, value privacy, and the pinned attack replay.

## First disposable workflow result: refused, not measured

Run 42884753488 was green but uploaded only an empty live.txt and no JSON. Logs
show the isolation gate refused before any action: /sys/class/net belongs to the
host's existing sysfs mount, even after unshare --net. The implicit workflow shell
also masked the benchmark's nonzero exit through tee.

Invariants before fixing: query the calling process's network namespace, fail
closed on query errors, preserve every gate, propagate refused/failed benchmark
status, and never accept an empty/missing measurement artifact. Use the standard
socket interface enumeration (current namespace), explicit bash pipefail and a
nonempty JSON artifact check. Add failure-path tests without executing attacks.
- Jev comparison (jev-1.14.0, fixed metadata only) favored immediately reporting
  unknown provenance: probability 0.97, concentration/confidence 0.96; verified
  exclusion 0.03, blanket suppression 0.00. It grants no trust or response authority.
- Disposable scenario audit also fixed an empty-crontab failure under set -e;
  the fixture test runs the action against a fake crontab executable and scratch
  state, so it verifies the shell path without touching the host's crontab.

## First executed measurement and empty-socket baseline fix

Run 42885855204 applied all 16 actions, named 8 through new findings, and reported
no cleanup failures. It correctly failed because hidden's baseline mistook valid
empty socket tables for unreadable tables. Result is provisional/incomplete, not a
production detection score. Misses: loader preload, profile script, listener, PHP
web shell, root crontab, hidden executable, shell-history redirection and rc.local.

Invariants before editing: retain fresh socket reads and inode identity, distinguish
complete empty observations from denied/malformed/truncated observations, preserve
first-sighting evidence on failed recheck, allow absent IPv6 tables only, and cap
strict reads. Choose an opt-in strict reader for attribution checks rather than
changing the legacy best-effort mapping API for every consumer. A complete empty
read is valid; read errors remain unknown and must never become clean attribution.
- The provisional run omitted the existing Linux preload detector (`implant`) and
  process/network scanner. Reviewed both service paths: they observe local Linux
  state, use no model/network enrichment by default and persist only to the scratch
  store. Added them to the explicit allowlist. Report collector names and a separate
  high/critical count, because generic new-process inventory alone is not attack proof.
- Strict socket reader: 22 attribution and 14 observation tests passed in private
  scratch homes; real host read-only smoke parsed 18 rows. Jev Choice preferred the
  strict evidence-status design (probability/concentration 1.00), advisory only;
  deterministic malformed, denied, over-budget, empty and failed-recheck tests gate it.
- Full local follow-up run completed 316/317 modules green. One existing campaign
  cleanup test hit ESRCH while reading a process that had just been reaped; it
  already accepts ENOENT and zombie state as successful termination. Treat ESRCH
  identically, preserving the timeout and descendant-liveness assertions. This is
  a test race correction, not a production behavior or containment promotion.

## Completed disposable measurement

Run 42887094655 (source a260548) applied 16/16 scenarios: 11 marker-linked findings,
10 high/critical, 10 reviewed observers, 41.8 s. Baseline errors, after errors,
cleanup-command failures and execution errors all empty. Preserve report at
`docs/security/evidence/live-detection-2026-11-10.json`. This is controlled Linux
state observation, not a score over the public 1,745 tests; marker linkage does not
prove the intended mechanism was identified, and successful cleanup commands are
not independent containment/recovery validation. No production deployment.

Five recorded misses remain: profile script, PHP web shell, root crontab,
shell-history redirection and rc.local. Do not remove or rewrite these cases to
raise the count. They are next coverage work, with success and benign controls
needed before broadening detection. The content-rule subset missed the PHP fixture.
- Final CI ran 4,928 tests and caught the new strict text-open at the repository's
  decoding gate. Preserve that gate: read bounded binary bytes, then explicitly
  decode the kernel's ASCII protocol. Invalid bytes remain unavailable evidence,
  while the collector's outer handler reports the gap. Add a non-ASCII failure
  fixture; do not weaken the source guard or replace invalid bytes into valid rows.
