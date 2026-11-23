# ARGUS-1 publication readiness, 2026-11-17

## Scope and verified baseline

PR #50 merged AGPL-3.0-only preparation into main at
`1334ba3d37e8de223c1237dd73417e240f191b0d` on 2026-11-16.
GitHub readback on 2026-11-17 reports the official repository **private**.
An older checkout still containing the EULA does not describe current main.
The earlier transition log records historical preparation, not current visibility.
The owner subsequently selected noncommercial source availability plus separate
paid commercial permission in this session. The new preparation uses the
unmodified PolyForm Noncommercial 1.0.0 text; it must not be advertised as open
source. Earlier AGPL grants are retained. No runtime capability changes.

## Revised licensing invariants, before editing

- Change only the terms offered for the new distribution. Do not revoke,
  rewrite or narrow valid AGPL grants to earlier recipients or third-party
  licenses. Existing AGPL forks can continue commercial use under those terms.
- Use a standard software license, not a Creative Commons content license or
  an improvised noncommercial clause attached to AGPL.
- Preserve PolyForm's explicit permitted organization uses, including government
  institutions. A commercial payment requirement cannot override those grants.
- Commercial permission requires an actual agreement from the authorized rights
  holder; an entitlement key alone is not a new legal agreement.
- Required Notices must travel inside every binary package. The existing
  THIRD-PARTY-NOTICES.txt is already packaged everywhere; render the project's
  Required Notice lines there from NOTICE, and fail if they are absent or the
  notice input exceeds its bound. This avoids adding a file while preserving
  the binary content gate and keeps the notice source centralized.
- DCO alone is not a grant to commercially relicense someone else's contribution.
  Do not merge externally copyrighted contributions without documented commercial rights
  under an approved agreement. Do not invent a signed CLA or assignment.
- The owner separately confirmed both original coauthors authorize the revised
  noncommercial and paid commercial arrangement. Record this as owner-reported
  consent; do not invent an assignment, executed CLA or incorporation.
- Publishing full history would also expose the historical AGPL source snapshot.
  A reviewed source-only publication surface can avoid republishing private
  history, but cannot withdraw already distributed AGPL copies or grants. Do not
  force-push or rewrite shared history to pretend those grants did not exist.

AGPL permits competitors' commercial use, so it does not meet the revised goal.
PolyForm Noncommercial preserves source inspection/modification/distribution for
its permitted purposes while reserving other commercial permission. A custom
license could change the government exception but adds drafting and adoption
cost; no such change is made here. Reconsider if the owner needs government use
itself to require a paid license, rather than paid deployment and support.

## Invariants before implementation

- Public PR code receives no production secrets, writable repository token,
  protected-host execution, release authority or persisted checkout credential.
- The required `python`, `desktop-ui`, and `desktop-rust` checks execute on PRs;
  event filters must not create a skipped-success route around those checks.
- Preserve pinned actions, bounded jobs, main-only shared Rust cache writes,
  signed binary releases, source obligations, rollback and branch/tag protections.
- Sensor freshness, evidence continuity, identities, cursors, privacy and recovery
  are unaffected. Do not deploy or change the assurance register.
- Preserve unrelated work in the original checkout; use an isolated worktree.
- Publication remains blocked on undocumented rights or privacy review. Missing
  evidence, failed checks and interrupted scans remain explicit.

## CI alternatives

1. Keep push-only CI: cheap, but forks cannot establish required PR checks.
2. Run every push and every main-targeting PR: choose this. It preserves the
   ASES DEV-11/DEV-13 every-push requirements and gives forks the same required
   jobs. Internal PRs can duplicate branch runs; bounded job timeouts and
   cancellation on new revisions limit waste but do not eliminate that cost.
3. Run PRs plus main/explicit-test pushes only: fewer duplicate runs, but this
   drops the current every-push gate and needs a separately reviewed standards
   policy change. Do not broaden this licensing-readiness task to weaken it.

Never use `pull_request_target` to execute contributor code. Never skip required
PR jobs merely because an internal branch has a separate push run: a skipped
success could satisfy a required check before the real test has finished.
Manual dispatch supports a maintainer's explicit pre-PR check. Reconsider the
selected routing if measured Actions usage exceeds the team budget; agree the
standard and routing together, without silently weakening required checks.

## Publication evidence still required

| Gate | Current evidence / remaining work |
| --- | --- |
| Rights | Owner explicitly confirmed both original coauthors' authority and separately confirmed the revised noncommercial and paid commercial arrangement. This is owner-reported; no assignment or executed CLA is asserted. Future outside contributions still need their own commercial grant. See docs/commercial/CONTRIBUTOR-RIGHTS.md. |
| License | Main contains AGPL-3.0-only. This branch prepares unmodified PolyForm-Noncommercial-1.0.0, all six manifests, SBOM identity, retained Required Notices and revised contribution/commercial policies. Earlier grants and third-party terms remain valid. |
| Privacy | Review current files and full intended history, including operational baselines, internal reports and draft advisories. Pattern scans cannot clear private prose. |
| Hosting surfaces | API inventory reports 22 retained Actions artifacts and no GitHub Releases. All 22 were downloaded into a private local directory and bounded ZIP parsing succeeded; 21 JSON members were structurally inspected. Content, run-log and cache privacy/disclosure review is still pending. Do not delete evidence to simplify publication. |
| GitHub policy | Main and release-tag rulesets active. Default workflow token read-only; PR approval by Actions disabled. Readback is not proof a fork run has succeeded. |
| Source compliance | Preserve license, Required Notices, exact source identity and third-party obligations in future packages. Earlier AGPL distributions retain corresponding-source and applicable section 13 obligations. |
| Commercial sales | Verify the actual contracting entity and its rights over every covered contribution before offering a commercial permission contract. Activation keys do not establish that agreement. |
| Dependencies | GitHub reports seven open moderate alerts: six in development security-tool dependencies (mcp/opentelemetry-api) and one in desktop/Cargo.lock (glib). No dependency remediation is claimed by this licensing change. |
| CI execution | Branch run 44101716107 did not start required jobs: GitHub reports account payment/spending-limit issues. Do not change billing, waive checks or merge around the block. |
| Launch | Unauthenticated retrieval of main's LICENSE.txt returned HTTP 404 on 2026-11-17, consistent with private API visibility. No visibility change, public release or service deployment is performed by this preparation. |

## Validation

Results are recorded below after execution. CI routing tests and metadata review
do not establish actual fork execution; a maintainer-approved external-fork PR
must demonstrate all three required checks before that path is called verified.

- Focused contributor-CI, licensing, publication-audit and collaboration checks:
  36 tests passed. Eight new cases parse the actual workflow and preserve event,
  permission, runner, token, cache, mandatory-check and command-safety boundaries.
- Static gate passed: ruff, mypy on 60 source files, 57 verification checks.
- Standards check passed with zero findings; dependency notices and whitespace
  checks passed. Issue forms parsed as valid YAML with required structure.
- Gitleaks 8.30.1 `git --redact=100` completed with exit 0. This checks known
  patterns in its Git scope, not private prose or every hosting surface.
- The broader bounded history pattern audit completed 5,748 blobs /
  95,224,235 bytes in 20.27 seconds, with no oversized objects skipped or byte
  exhaustion. It exited 1 for review candidates: 104 generic assignment-pattern
  blobs and two AWS-pattern blobs. The current AWS match is in a synthetic
  release-gate fixture; historical matches still require review. A completed
  inventory with detections is not a passed publication gate.
- New issue forms request synthetic reproductions and direct vulnerability
  reports to SECURITY.md. The PR template requests DCO sign-offs and retained
  third-party notices; automated DCO enforcement is not claimed.
- Initial full `python3 -m unittest discover -s tests` ran 5,089 cases in
  1,371.486 seconds at the contributor-CI preparation state: 5,061 passed,
  17 skipped, four failures and seven errors. Ten environment-sensitive cases
  passed when rerun with short private scratch paths and an initialized cache.
  The eleventh was the old push-only CI cost contract; it now tests bounded
  push/PR/manual routing while preserving timeout/cache ceilings. The original
  full run remains nonzero, never an unqualified pass.
- Revised noncommercial licensing, Required Notice packaging, contributor CI,
  cost, audit and collaboration checks: 48 tests passed. The official license
  text is hash-checked; government grants, old AGPL terms, commercial rights
  limits and all six manifests are exercised. Missing, empty, malformed and
  exhausted notice input fails closed.
- The all-module run used `fasttest.py --all --jobs 4` with fresh private scratch
  homes and no unchanged-module skips: 5,093 test receipts across 327 modules,
  325 modules passed, two failed, 9.7 minutes wall time. The original run remains
  nonzero. Final notice-boundary cases are also included in the focused 48 above.
- The two all-module failures exposed fixture defects, now corrected. Cache
  filtering now checks paths relative to the fixture root so a `.cache` ancestor
  does not erase its dependency list. The worldwatch fake now supplies decompressed
  CSV, matching `feeds.fetch`, and also asserts successful parsing; it had supplied
  timestamp-dependent ZIP headers to the CSV parser. No file-cap, no-repeat or
  cache-invalidation assertion was removed. Both repaired modules passed together:
  56 tests. The four cache tests also passed under both temporary-root layouts.
- The final static gate passed after Required Notice handling: lint, types and
  57 verification checks. A final focused check covers the small fixture edits.
  No production runtime, installed app or external-fork execution is claimed.

Jev was called through the existing client, with fixed CI-design metadata only.
The final Choice favored preserving every-push plus PR checks (0.93 probability
mass, 0.91 concentration). Noul publication-readiness yes probability was 0.05.
Choice favored observing a real external-fork run as the missing CI validation
(1.0 mass/concentration). The advice supported explicit gaps; deterministic
standards and tests decided the implementation. No probability is permission,
customer demand evidence or a correctness guarantee.

After the owner's change, a second metadata-only design review favored
PolyForm plus separate commercial permission (Choice mass/concentration 1.0).
Noul yes probabilities were 0.06 for revoking earlier AGPL grants and 0.08 for
DCO alone establishing commercial relicensing rights. Those answers reinforced
preserving old grants and requiring an actual additional contribution grant;
the standard license text and deterministic package/metadata tests are the
independent evidence. Jev cannot establish legal authority or publication readiness.
The final implementation review, after the owner confirmed the revised rights,
again chose PolyForm (1.0 mass/concentration); the two Noul yes values were 0.07
and 0.07. Only design/validation metadata was sent, never source patches,
credentials, private contract contents or security evidence.

GitHub's [fork approval guidance](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/approve-runs-from-forks)
requires reviewing workflow changes before approving untrusted execution.
[Visibility guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility)
also identifies Actions logs as a public disclosure surface when visibility changes.
