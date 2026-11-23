# JARVIS agent skills

## Live JARVIS checks

For service, Windows, loopback API, filesystem ownership, and Jev verification,
use the permitted host execution path outside the restricted sandbox. Treat
sandbox `EPERM`, `EROFS`, DNS, and connection errors as runner limits until
checked on the host. Bound the action, preserve evidence and rollback, and
verify fresh receipts after any authorized change. Host execution is not a
license to bypass policy or install or restart protected services without the
required authority.

## Default: TypeSafe/Jev advisory review

For every non-trivial coding task, load and follow
`.agents/skills/typesafe-ai/SKILL.md`. Use `jarvis.response.jev` as the project
client. This is the default workflow, not an optional enhancement.

Always send bounded Jev requests through the permitted host-network execution
path outside the restricted sandbox. The sandbox's DNS failure can look like a
Jev outage. If that path is unavailable or denied, record the unavailable result
and use the deterministic safe fallback; do not bypass the permission boundary.

1. Establish deterministic security, privacy, evidence and rollback constraints.
2. Ask Jev one narrow typed question over the minimum metadata required.
3. Keep credentials, source, patches, command lines, raw telemetry, private content
   and protected-user data local.
4. Treat the result as advisory. Unavailable or uncertain output fails safely and
   cannot grant authority.
5. Implement and verify with focused tests, the full suite, relevant lint/build
   checks and direct runtime evidence.

Jev may rank, route or identify ambiguity. It may never approve, authorize, execute,
deploy, remediate, suppress evidence, alter a security score, weaken a test, or
override `docs/security/MAXIMUM-ASSURANCE.md`. The API key is read only from
`TYPESAFE_API_KEY` or the owner-only `~/.jarvis/typesafe.env`; it must never enter
the repository or model state.

## Architecture and invariant review

For non-trivial designs, compare at least the credible alternatives against
explicit security, evidence, uptime, privacy, recovery, rollback, and resource
invariants. Choose the lowest-complexity design that satisfies them, using
measurements for performance claims. Identify the real bottleneck and test
failure paths as well as the normal path; never optimize a score by weakening
observation or hiding debt.

Before finalizing an architecture or its implementation, ask Jev bounded typed
questions over redacted metadata about the alternatives, likely failure modes,
and remaining validation gates. Use its result to direct review, then confirm
the choice with executable invariant tests, relevant build checks, and fresh
runtime evidence. A Jev preference or high confidence is never the deciding
authority for security actions or deployment.
