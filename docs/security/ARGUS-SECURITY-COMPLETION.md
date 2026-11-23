# Security campaign completion work

## Invariants written before implementation

The second phase preserves all prior campaign invariants and unrelated edits.
Scanners are installed into a separate development toolchain with version and
artifact hashes, with no production credentials, global installation or deployment.
The campaign never silently provisions or trusts an arbitrary executable. Scanner
findings remain failures even when the scanner or the product has a known gap.

Native instrumented tests use synthetic inputs and scratch storage. Binary analysis
reads a bounded regular artifact and never executes it. Proofs identify their exact
source functions, supported syntax and assumptions; unsupported code is incomplete,
never translated optimistically. Counterexamples and negative controls must exercise
real behavior. Review packets bind findings to source/artifact digests and cannot
self-approve. Human review remains a human action.

VM probes use the existing network-less container/KVM lab, verified immutable base
image, copy-on-write disks and synthetic identities/data. No host sharing, production
services, sensor state or protected-user data. Refusals, missing prerequisites,
interruption, malformed guest receipts and incomplete runs remain explicit. Cleanup
and bounded CPU/memory/time are mandatory; do not loosen the existing lab boundary.

Design comparison: extending the existing adapters/lab is smaller and safer than a
second VM lifecycle or custom scanner implementation. A local dependency patch is
narrower than replacing the Svelte plugin's merge semantics. Reconsider if real
scanner results, negative controls, builds or lab measurements invalidate these
choices. Tool installation is an explicit setup operation, separate from execution.

The source-bound proof currently covers `defense._enabled` only, over normal
configuration dictionaries and Action string fields. It rejects unsupported AST
constructs and checks an inverted-guard mutation is satisfiable. This is a
refinement proof for that predicate, not for the whole response state machine.
The local deepmerge patch changes data-property writes in source, CommonJS and
UMD outputs; behavior is checked against the installed import and the original
poisoning behavior is a negative control. Version-based audit findings remain
visible; a local patch does not manufacture an upstream patched release.
