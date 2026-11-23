# ARGUS-1 open-source transition

Status updated 2026-11-17: PR #50 merged AGPL preparation at
`1334ba3d37e8de223c1237dd73417e240f191b0d`; those earlier grants remain valid.
The owner has now selected **noncommercial source availability plus paid
commercial permission**, prepared as PolyForm-Noncommercial-1.0.0. This new
license is not open source. GitHub currently reports PRIVATE and anonymous
source retrieval returns 404. No visibility change was performed by this work.
See [the current readiness report](READINESS-2026-11-17.md) and
[current licensing scope](../../LICENSING.md). The dated entries below preserve
the earlier AGPL preparation history; their old license decision and pending
states are historical, not the current publication decision.

## Invariants recorded before editing

- Preserve contributor copyright, third-party notices and existing license grants.
  Do not claim ownership transfers or contributor consent without evidence.
- No credentials, protected-user data, customer configuration, private incident
  evidence or embargoed advisories may become public through files, Git history,
  issue attachments, releases or Actions logs/artifacts.
- Preserve the signed release trust chain, explicit release authority, rollback,
  recovery and deny-by-default installer content checks. Source publication is a
  separately reviewed surface, never an exemption for installers.
- Do not modify the running service, sensor freshness, evidence identities,
  cursors, assurance claims or response authority. No deployment is in scope.
- Bound audit time, per-object size and total bytes; interrupted, failed, skipped
  and exhausted scans remain incomplete. Never log matched secret values.
- A license conversion does not itself establish publication readiness, correct
  detection, validated containment, or reproducible binary builds.

## Alternatives and decision

A permissive license permits closed derivatives. GPL adds distribution copyleft.
AGPL also addresses modified versions used to serve remote users. AGPL-3.0-only
was selected because reciprocal source availability best matches the
owner's request; competitors and commercial use remain permitted. Trademark
policy addresses confusing official identity separately, without restricting
software license rights. Reconsider if the owner changes the selected license or
rights/dependency review identifies incompatibility.

For publication, an existing-repository visibility change preserves public
attribution and history but exposes historical blobs and collaboration surfaces.
A separately reviewed source repository avoids exposing private operational
history, at the cost of maintaining private provenance and public attribution.
Prepare the existing repository first; do not flip visibility while any gate is
open. If private history cannot safely be published, select a new public home
with the owners and preserve the original private repository and provenance.
No force-push, deletion of evidence or wholesale history rewrite is authorized.

## Required publication gates

Maintainers record the exact reviewed commit, refs, reviewer, time and evidence
for each gate. Empty entries are blocking, never implicit approval.

| Gate | Required evidence | State |
| --- | --- | --- |
| Rights | Both cofounders confirm authority to relicense their work; review other contributors and imported assets/data; no fabricated corporate assignment | Pending |
| License | Owner selects license; manifests, notices and packaging agree; third-party terms reviewed | AGPL selected; metadata and notice checks pass |
| Current source | Secret scanner plus human privacy review of every public file; local examples use synthetic values | Pending |
| History | Fetch intended remote refs, full-history secret scan and private-data review; rotate/revoke exposed credentials before release | Pending |
| Collaboration surfaces | Issues, PRs, discussions, wiki, attachments, Actions logs/artifacts/caches, Releases, LFS and submodules reviewed | Pending |
| Disclosure | Draft advisories checked against shipped fixes and coordinated disclosure | Pending |
| Release compliance | Complete corresponding source, required build/install scripts and dependency source obligations for each distributed binary; durable tag/commit and source access verified | Pending |
| Hosted use | Modified AGPL network deployments offer corresponding source to remote users as required by section 13 | Pending |
| Governance | Owner review for trust anchors; outside contributors have a safe PR CI path; branch/tag protections read back on GitHub | Pending |
| Validation | Full unit suite, static gate, standards check and scoped security campaign; failures and host-only gaps recorded | Pending |
| Publication | Only after every gate passes: merge reviewed PR, change visibility, verify anonymous source access and release identity | Blocked |

## Initial read-only findings, 2026-11-16

Initial GitHub readback reported Archymedes-Lab/argus-1 PRIVATE; later readback
reported PUBLIC at the same main commit d06ccd8393fe. Initial local base: 32216b6; preparation rebased onto current org/main.
The working checkout contains unrelated ongoing work; preparation is isolated in
branch docs/open-source-20261116. This agent changed no visibility or live deployment. The owner selected AGPL-3.0-only.
Live GitHub readback found active main and release-tag rulesets; zero required
cofounder approvals is the existing owner decision, which this change preserves.

Tracked review candidates include docs/guides/baselines/, docs/reports/,
docs/security/ operational reviews, .container-release-overlay-20260930/ and
docs/security/advisories/*-draft.md. Their presence is a privacy/disclosure review
requirement, not proof of credential leakage. Existing standards secret scanning
skips docs/ and tests/ and does not scan history; it cannot certify publication.

The existing binary pipeline refuses source in installers. Keep that protection.
Before distributing AGPL binaries, separately validate complete corresponding
source availability and all dependency source obligations; a repository URL or
GitHub auto-generated source archive alone is not proof of completeness.

Do not publish old proprietary releases as if they were built under this change.
Commercial strategy and historical review documents describe prior decisions;
the root licensing policy governs the new source distribution after adoption.

## Measured preparation checks

The initial local-history pattern audit completed 5,714 blobs / 94,672,232 bytes
in 27.857 seconds with no skipped oversized blobs. It reported 104 generic
assignment-pattern blobs and two AWS-pattern blobs. These are review candidates,
not confirmed credentials: the current AWS match is an intentional synthetic
release-gate fixture. The audit does not suppress documentation or tests and
never prints matched values. The independent pinned Gitleaks history-secrets step passed with redacted
output and stable source; this does not complete the broader security campaign. Local reachable refs are not all remote publication surfaces.

New regression cases cover deleted historical secrets, clean histories without
publication authority, exhausted time/byte budgets, oversized objects,
interruption, timeout without retry and changed refs. Focused licensing,
packaging and source-hygiene tests pass. The rebased static gate passes all
three stages (including 57 verification checks), and standards checking passes.
Full-suite and campaign results are recorded in the final validation handoff;
no live protection capability changed or was promoted.

Jev was called with metadata only (Choice design fit and priority; Noul
readiness). The final implementation review favored AGPL (choice 0.88, concentration 0.84),
prioritized rights review (0.68, concentration 0.60), and assigned readiness yes
probability 0.02.
This supports keeping the rights/privacy gates explicit; it grants no authority.
Question definitions are in scripts/reviews/open_source_advisory.py.

Live GitHub metadata readback found 187 Actions runs, 24 retained artifacts, no
Releases returned, issues enabled, and wiki/discussions disabled. These counts
are an inventory, not a privacy review of the contents. Main still uses the
proprietary EULA (GitHub license detection NOASSERTION) until the AGPL PR lands.
Public visibility is not itself an open-source license grant.

The audit compared one Git subprocess per object with a checked batch stream.
The first exhausted 120 seconds after 2,432 blobs; batching completed the same
local scope in 27.857 seconds while retaining digest/ref identity and scan
bounds. Per-blob reads are capped at 8 MiB, metadata at 16 MiB, total selected
content at 256 MiB and object count at 100,000; the private spool is discarded.
CPU and peak RSS were not measured. This narrow pattern inventory complements
the existing pinned scanner; neither detects all private prose or unknown keys.

## Final local validation, 2026-11-16

Full `python3 -m unittest discover -s tests -v` ran 5,081 tests in 640.811 seconds
on the host with a scratch HOME: 5,053 passed, 17 skipped, three failed and eight
errored. All 11 failing/error cases then passed on suitable isolated scratch
paths (four ordinary-path/cache cases; seven private-ancestor cases). The full
run therefore remains nonzero; do not describe it as an unqualified green suite.
The fixtures deliberately reject code under /dev and staging under world-writable
ancestors such as /tmp or /dev/shm. No security gate was weakened to fix a test.

Focused license/audit/collaboration tests passed (28); combined focused
license/audit/release/source-hygiene checks passed (54). Required static gate and
standards checks passed. No production service or installed app was changed or
claimed live-verified. The broader security campaign and human reviews remain
incomplete despite the passing history-secret step.

The preparation branch and full diff remain local. Automatic approval review
rejected pushing the unresolved rights/privacy preparation to the public remote.
The owner directed leaving the repository public; publishing this specific
branch and creating a draft PR still require explicit approval after review.
