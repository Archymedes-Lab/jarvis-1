# ARGUS-1 security verification campaign

## Invariants and design (written before implementation)

- Test evidence names the method, scope, result, elapsed time and output digest.
  A missing tool, timeout, skipped test or pending human review cannot pass.
- Adversarial tests use synthetic data and a temporary HOME, USERPROFILE and XDG
  directories. No production endpoint or arbitrary target argument is accepted.
  This is environment isolation, not a sandbox for hostile executables.
- Test processes receive an allowlisted environment without user credentials,
  proxy settings or Argus configuration. No raw tool output enters the report.
- Every subprocess has a deadline and output bound. Interruptions kill its process
  group; there are no retries. Reports already written survive later failure.
- No install, deployment, service restart, containment or policy changes. Sensor
  freshness, evidence cursors, identity and recovery state remain untouched.
- Results are scoped observations, never proof of absence of vulnerabilities.

Compared designs: a new universal scanner would duplicate mature analyzers and
create misleading coverage; an unbounded shell script would hide missing stages
and leak scanner output. The selected design uses fixed argument lists, installed
analyzers, existing production-path regression tests and explicit gaps, serially.
Reconsider when measured campaign latency justifies bounded concurrency. Each step
records wall latency and output size; CPU/RSS are not yet measured per scanner.
The default 300-second step deadline and 1 MiB output cap bound operator wait and
memory; incomplete expensive checks must be run separately with reviewed budgets.

## Run

    python3 scripts/security/campaign.py --list
    python3 scripts/security/campaign.py --method dast --method iast
    python3 scripts/security/campaign.py

Reports are created in a new private directory under the system temporary
folder; its path is printed. Each completed step is written atomically. Exit 0
means all selected steps completed without reported findings or skipped tests;
1 means a failing check; 2 means incomplete coverage. A subset passing does not
mean the campaign passed. Tool stdout/stderr are hashed and counted, never copied
into JSON. Re-run the failing fixed command in an isolated lab for diagnostics.
Reports hash tracked and non-ignored untracked checkout files before and after
execution (256 MiB content budget); a changed or unreadable tree is incomplete.
The snapshot is a local provenance aid, not a signed attestation or a substitute
for a sealed immutable release. Interrupted reports name the active step.
Only use trusted, independently provisioned tools. This runner never downloads
or installs tools. Networked SCA sends dependency identities to advisory services;
run it only in an environment permitting those requests. A snapshot of dependency
advisories is time-dependent; record the campaign timestamp.

## Methods and limits

| Method | Executable integration | Scope and remaining work |
| --- | --- | --- |
| SAST | Bandit plus existing AST policy regression checks | Python only; desktop and Windows need independent review |
| Taint | Semgrep local taint rules | Python direct assignments/source-to-sink; not whole-program or cross-language flow |
| DAST | Real loopback HTTP API hardening tests | Disposable server, tokens and database; no production scan |
| IAST | Profile actual handler calls during HTTP tests and assert denied requests never reach parsing/scheduling | Entry/authentication observations, no claim of full instrumentation |
| Runtime sanitizers | CPython debug allocator/dev mode boundary regressions; Rust nightly AddressSanitizer adapter | Python allocator checks are not ASan/UBSan/TSan; native race and Windows sensor checks remain pending |
| Model checking | Existing production-backed bounded model tests and negative controls | Explicit finite abstractions in VERIFICATION-LADDER.md |
| Formal verification | Z3 checks a response-authority specification and a deliberately false claim | Specification only, no refinement proof of Python, scheduler or evidence chain |
| Manual code review | Required review record below | Human review cannot be replaced by tool success |
| Binary analysis | Existing release content/archive tests | Gate regression only; actual built ELF/PE hardening and reverse engineering pending |
| SCA | pip-audit pinned runtime requirements, cargo-audit lockfile, Bun audit for every Bun manifest | Build requirements and bundled native libraries still need SBOM review |
| Secret scanning | Gitleaks redacted repository-history scan plus ASES checks | Scanner rules can miss unknown secret formats; no secret values in reports |
| Configuration | ASES and Argus service/network regression tests | Checkout definitions, not deployed permissions or cloud account state |
| Penetration testing | Synthetic exploit regressions for API and archive/parser boundaries | Full attack chains in a disposable deployed VM pending |
| Threat modeling | Trust-boundary analysis below | Human validation of coverage and new features remains required |

Manual review and threat review deliberately remain `pending`; no file or flag
can automatically certify a human review. Native sanitizer and binary review gaps
also prevent claiming that all fourteen methods have been completed.

## Threat model and review record

Assets: owner authority, API credentials, evidence history and cursors, privileged
broker, signed releases, personal data, recovery and essential availability.
Trust boundaries: browser to loopback daemon; external logs and model output to
collectors; daemon to privileged broker/Windows; checkout/build to signed artifact;
agent integrations to remote effects; dependency feeds to build tooling.

Review priorities and independent evidence:

1. Unauthenticated/cross-origin/cookie API calls: real HTTP denial tests; inspect
   every new route and token delivery. Same-user malware remains a known limit.
2. Attacker-controlled text selecting action identity: source attribution property
   tests and response ladder models; inspect indirect identity and expiry paths.
3. Archive traversal, source/secret disclosure and resource exhaustion: release
   gate exploit regressions, fuzzing and output/time limits; inspect all formats.
4. Stale evidence, replay and interrupted effects: model/property suites and ledger
   tests; inspect actual commit points and fail-closed recovery behavior.
5. Dependency/build compromise: lockfile audits, secret scan and configuration
   checks; verify signed artifact provenance separately on an isolated build.
6. Prompt injection: model output is advisory; deterministic policy and human
   authorization control effects; inspect every new path from model to action.

Human sign-off must name reviewer, exact commit and dirty-tree digest, date,
files/boundaries reviewed, findings and disposition, assumptions, and evidence.
Penetration-test scope must name disposable VM/network, allowed effects, duration,
synthetic assets, stop conditions and rollback; never use the owner's data.
No review has been signed off by this document.

## Initial measurements (2026-11-09)

The campaign's own 14 regression tests and four live loopback boundary tests
passed. The existing static gate passed all 57 verification tests, lint and typed
checks. Under concurrent full-suite load, the 34-test HTTP hardening module took
about 70–75 seconds and the 36-test paired-client module about 75 seconds. Their
combined step exceeded the initial 120-second deadline; the suites now have
separate steps with a fixed 300-second deadline. No automatic retries were added.

Bandit, Semgrep, Gitleaks, pip-audit, cargo-audit and Z3 were not provisioned on
this host, so those integrations were not validated against their actual tools.
The local taint rules and SMT specification must be validated by provisioned
analyzers before relying on them. The native sanitizer recipe was not run.

Existing uncommitted release-gate fixes cause three `expectedFailure` tests in
`tests.test_fuzz_findings.ReleaseGateFindings` to report unexpected successes
(FZ-11, FZ-12 and FZ-13). The campaign preserves those failures and the preexisting
edits; it does not rewrite test expectations to obtain a passing report. Other
existing suites skip environment-dependent cases, so their campaign steps remain
incomplete. A skipped case is not evidence that its invariant holds.

## Dependency finding remediation invariants (before manifest edits)

The initial Bun audit reported one low desktop build dependency advisory in
`deepmerge@4.3.1` (GHSA-gcqx-w48m-w2h4, no upstream patched version listed) and
20 advisories (8 high, 9 moderate, 3 low) in the shared hosted development tree:
`wrangler -> miniflare -> sharp@0.35.2 / undici@7.29.0`.
These are dependency advisories, not measurements of exploitable Worker behavior.

Compare upgrading Wrangler/Miniflare versus exact patch overrides. The latter
keeps Worker source, public interfaces, deployment definitions, top-level pins,
secrets and existing unrelated edits intact and avoids a broad toolchain change.
Override sharp to 0.35.5 and undici to 7.30.1 in the three hosted packages; regenerate
integrity-locked Bun files without install scripts. Reconsider if the real audit,
Worker tests or type checks reject these versions. No automatic waiver or
suppression of the unresolved desktop finding is permitted. No remote deployment,
account access or privileged runtime change is part of this remediation.

References checked 2026-11-09:
- https://github.com/advisories/GHSA-gcqx-w48m-w2h4
- https://github.com/advisories/GHSA-rgj7-g3m4-5g8c (sharp 0.35.4)
- https://github.com/advisories/GHSA-w293-vg96-wgc3 (undici BalancedPool)
- https://github.com/advisories/GHSA-2m5v-pch6-74hx (undici Agent; 7.30.1)
- https://github.com/advisories/GHSA-wq5f-xc86-pv6w (sharp 0.35.5 is required
  for the separate librsvg issue; 0.35.4 does not clear the audit)

## Final validation of the implementation

- New campaign and HTTP boundary regressions: 19 tests passed (15 runner tests,
  4 real loopback tests), with no skipped cases. The runner additionally treats
  expected failures as open security findings and reports unexpected successes.
- Full regression run: `python3 scripts/dev/fasttest.py --all --jobs 4`, the
  isolated per-module equivalent of `python3 -m unittest discover -s tests`:
  306 modules passed, one failed, 18.5 minutes wall time. The sole failing module
  is the three preexisting FZ-11/12/13 expected-failure annotations described above.
  Some existing tests skip environment-dependent cases; these are not coverage.
- Hosted dependencies now pin `sharp@0.35.5` and `undici@7.30.1`. All three
  integrity-locked frozen installs with scripts disabled, Worker suites,
  TypeScript checks, Bun audits and real Wrangler dry-run builds passed. Each
  hosted audit now reports no known vulnerabilities; this does not establish
  that its dependencies or Workers have no vulnerabilities. No deployment ran.
- The desktop build tree still reports the one low deepmerge advisory, without
  a listed upstream patch; it is unresolved, not waived.
- Jev was called for design and implementation using fixed metadata only. Its
  Choice concentrated on bounded adapters (1.0); Noul assigned 0.95 to needing
  independent review/deployed validation and 0.80 to needing the real Wrangler
  build path as well as tests/types/audits. This reinforced the explicit gaps and
  dry-run build requirement. No judgment authorized an effect or replaced a test.

The campaign is intentionally incomplete until absent tools and the native,
formal-refinement, independent-review and disposable-deployment gaps are addressed.
No runtime capability has been promoted. `assurance.SECURITY_TESTING` records
partial development verification outside the runtime scoring registry.

## First run with provisioned analyzers (2026-11-10)

`scripts/security/provision.py` built the pinned toolchain (hash-verified Python
tools, Gitleaks 8.30.1 archive digest, cargo-audit 0.22.2 from its locked crate;
cargo-audit took about 15 minutes on 2 jobs). Every tool binary is recorded in a
private receipt that the campaign checks before use.

Analyzer results on this tree, scoped observations only:

- **Semgrep taint:** 0 results, no errors; both rule controls pass.
- **pip-audit:** no known advisories in `release/requirements-runtime.txt`.
- **Gitleaks (full history):** 28 hits, each reviewed: detector and parser test
  vectors, licence/notify vectors generated with fresh per-run test keys, the
  RFC 6455 sample nonce, the public Ubuntu image signing-key fingerprint, a
  synthetic VM-test marker, a VAPID *public* key and a synthetic OpenSSH body
  used to build an attack-map sample. They are recorded in `.gitleaksignore` as
  exact `commit:file:rule:line` fingerprints, each with a reason.
  `SourceHygieneTests` refuses globs, unexplained entries and entries outside
  test paths or the four reviewed files. A new secret still fails the scan.
- **FZ-14 fixed:** the campaign's skipped FZ-14 test exposed that the release
  gate held every archive member in memory. Members now share a 256 MiB budget
  (~2.9x the largest real artifact); later members are listed as `over-budget`
  without being read, and refused. Nested zips check the budget before reading.
  The real 2026-11-09 release folder gives the same verdict as before (its only
  refusal is the NSIS Setup needing 7z, absent here), 62 s, +26 MB peak RSS.
- **Bandit:** 410 results, mostly low-severity classes (`subprocess` use with
  fixed argv, `try/except/pass`, asserts). Medium/high reviewed:
  - XML parsing (B314): Sysmon/event records, `pom.xml` from scanned codebases,
    OVAL feeds and Sysmon configs. Measured on the bundled expat 2.6.1: a
    billion-laughs `pom.xml` is refused in 0.29 s by expat's amplification
    limit and an external entity is never resolved. This depends on expat >= 2.4.1
    in the shipped runtime; `worldwatch` additionally refuses DTDs.
  - SQL construction (B608): all interpolations are constant identifiers,
    placeholder lists or Python keyword names from code; no data reaches SQL text.
  - Trojan source (B613): `jarvis/collectors/host/toolchain/agents.py` held raw
    bidi/invisible code points inside the very regex that detects them. Rewritten
    as `\u` escapes (proven equivalent over the BMP) and guarded by a test that
    no tracked file contains bidi controls (fails on the old file).
  - `shell=True` only in the VM guest harness with fixed commands; the
    provenance private key is created 0400 with `O_EXCL|O_NOFOLLOW`.
  Bandit's step stays failing: the low-severity classes are not suppressed.

### Windows binary hardening (PE support added to `binary_review.py`)

`binary_review.py` now parses PE32/PE32+ headers (bounded, never executes the
input) and disassembles the entry point with objdump. Measured on the shipped
artifacts:

| Check | `argus-desktop-windows-x64.exe` (2026.10.31) | `ARGUS-INSTINCT-Setup-windows-x64.exe` (2026-11-09) |
| --- | --- | --- |
| Effective ASLR | yes | **no**: DYNAMIC_BASE set, relocations stripped |
| High-entropy ASLR / DEP | yes / yes | yes / yes |
| No W+X section, entry in code | yes | yes |
| Control Flow Guard | **no** | **no** |
| Authenticode directory | **absent** | **absent** |

The installer finding is the known NSIS stub limitation (stubs are linked
without relocations; there is no makensis switch, and projects that patched the
stub hit mandatory-ASLR failures). Severity is low: the installer requests
user-level execution, installs under `%LOCALAPPDATA%`, reads only its own
payload and exits. Fixing it means a different installer format (owner
decision). Missing Authenticode means SmartScreen/WDAC cannot attribute the
binaries to the publisher; integrity today rests on the SSH-signed SHA256SUMS.
The desktop app is built on a Windows MSVC runner, so `release/build_desktop.py`
now passes `-Ccontrol-flow-guard=checks` (our crates; the prebuilt std is not
instrumented) and refuses to test or hand off an .exe whose headers lack
effective ASLR, high-entropy ASLR, DEP, W^X sections, an entry in code, or CFG.
The flag change rebuilds the cached crates once. Whether MSVC emits GUARD_CF for
this build is measured only by the native Windows job, not on this host.

### Campaign run with the toolchain (2026-11-10, before the fixes above)

Full campaign, all 14 methods, source tree stable across the run (6 minutes):
17 steps passed (Semgrep and its controls, DAST, IAST, bounded models, Z3
authority spec and `_enabled` refinement, pip-audit, cargo-audit, three hosted
Bun audits, Gitleaks after dispositions, ASES, service definitions). Failed:
Bandit (unsuppressed low-severity classes) and the desktop Bun audit (the
known, unwaived deepmerge advisory). Incomplete: three steps whose modules
skipped tests, FZ-14 (now fixed) and a Windows Python DLL case that needs a
Windows runtime. Pending, by design: native sanitizers, built-artifact review
of a named sealed artifact, human review, deployed VM attack chains, threat
review sign-off. The campaign is still not complete.

Jev (`scripts/reviews/argus_scanner_findings_advisory.py`, metadata only):
exact-fingerprint dispositions 0.99. A first call stated the installer runs
elevated, which was wrong (`RequestExecutionLevel user`); corrected, the next-step
Choice split between VM attack chains (0.41) and installer ASLR (0.37) at 0.21
concentration, so it did not set priority. No answer authorized or passed a step.
