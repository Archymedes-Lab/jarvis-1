# One interface and update contract

## Invariants written before implementation

Browser, desktop, CLI and mobile-facing views consume one daemon-owned contract
for refresh cadence, current/latest releases, update policy and operation state.
Platform shells may identify their installed component, but may not independently
interpret version ordering, choose download hosts or silently enable installation.
Every interface exposes the same unavailable/stale/disabled/failure states.

Live refresh has one in-flight request per resource, a bounded deadline and retry
backoff, pause/resume on visibility/network changes, and idempotent setup/cleanup.
Out-of-order replies cannot replace newer evidence; stale retained data stays
marked stale. A stream is an invalidation hint, never authorization or freshness
proof. No refresh performs an install or privileged action.

Software updates require explicit owner policy, pinned publisher signatures,
expected current release and component identity, bounded HTTPS downloads,
no arbitrary paths/commands from a manifest, staged immutable bytes, durable
intent before an install, post-install readback and a retained rollback artifact.
Interrupted and unverifiable effects stop automatic retries and remain uncertain.
No downgrade, replay, expired metadata or changed base may install automatically.
Automatic policy never creates privilege or weakens release validation. Missing
platform installation support is shown identically as unavailable by all clients.

Compare independent client updaters with a shared service controller. The latter
keeps authority, version semantics, rollback and status coherent; the former
already caused the browser to miss the desktop-only update notice and duplicated
Rust/Python version parsers. Use a shared service controller and shared frontend
transport/refresh code. Reconsider only if measured availability requires a
separately verified offline installer; do not duplicate policy in clients.

Implementation and validation are tracked with the security completion work.
No live deployment or automatic policy enablement is implied by adding this code.
