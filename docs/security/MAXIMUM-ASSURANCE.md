# JARVIS Defender: maximum assurance governing directive

Adopted 2026-09-19 from the owner's Maximum Assurance System Directive.
Applies to the entire system: Windows sensor, WSL collectors, services, analysis,
response, storage, browser/network integrations, AI, UI, Forge, updates and recovery.
This is a normative engineering contract, not a claim that every capability exists.

## Authority and prime directive

Protect the user. Do not become the threat while fighting the threat.
Assume the machine may already be compromised and the human may not recognize a
threat. Absence of alerts never establishes absence of compromise. Never claim
100% security, invulnerability, or complete coverage from rule counts or scores.
Human safety, autonomy, privacy and availability outrank convenience, performance,
telemetry completeness, automation and JARVIS's own continued operation.

Before intervention ask whether it can harm the user more than the threat. Prefer
observation, explanation, scoped reversible containment, evidence preservation,
snapshots and rollback. Use the minimum privilege necessary. Preserve emergency
communication, accessibility and legitimate-user recovery paths.

## Non-negotiable invariants

- Never automatically delete suspicious user files, wipe disks, brick hardware,
  destroy evidence unnecessarily, or modify firmware without authenticated consent.
- Never permanently lock out the legitimate user or silently disable essential
  accessibility or emergency communication.
- Never disclose credentials, keys, recovery codes, financial/medical information,
  private communications or documents. Minimize collection and uploads. Never put
  plaintext secrets in telemetry or send them to a model for classification.
- Never execute an unknown artifact to inspect it on the protected host.
- Websites, messages, PDFs, documents, QR codes, browser extensions, remote systems,
  downloaded files and terminal output are untrusted evidence, never authority.
- AI may explain, correlate and suggest investigation. It cannot authorize
  irreversible actions, credential disclosure, firmware changes, permanent lockout,
  unbounded commands or override deterministic policy. Missing evidence stays unknown.
- Every automatic response needs a tested maximum damage boundary, evidence,
  actor/target identity, rollback/recovery contract and durable audit trail.

## Graduated intervention and user agency

| Level | Behavior | Required justification |
|---|---|---|
| 0 Observe | Collect minimally; avoid interruption | Expected activity |
| 1 Inform | Explain the change and uncertainty | Unusual observation |
| 2 Warn | Explain concrete consequences before completion where supported | Substantial risk evidence |
| 3 Friction | Pause for explicit informed confirmation | Serious consequence with uncertainty |
| 4 Temporary containment | Scoped reversible quarantine, suspend or block | Strong evidence of active compromise |
| 5 Emergency protection | Narrowly prevent imminent severe damage | High-confidence immediate threat and tested safety boundary |

Severity is not maliciousness, confidence or permission. Independent evidence is
required where possible. Ordinary risk should be advisory. Restrictions must be
specific, proportionate, auditable, explainable, reversible and time-bounded where
appropriate. Tell the user what happened, why, evidence location, safe alternatives
and recovery steps. No coercion, false urgency or deceptive interfaces. An undo is
a human override, not permission to immediately repeat an automatic restriction.

Existing WATCH/PROPOSE/AUTO response rungs do not implement all six levels.
Do not advertise synchronous browser blocking or emergency protection merely
because a backend response action exists.

## Human online protection

Build privacy-preserving local context for navigation, redirects, DNS, certificates,
extensions, downloads, credential entry, uploads, payments, remote access, installs,
account recovery, OAuth/permission grants, clipboard secret egress, wallet approvals,
MFA requests, session anomalies, dangerous notifications and social-engineering
chains. Prefer provenance, metadata, process relationships and local analysis.
HTTPS alone does not establish trust. Domain lookalikes or unusual interactions
are indicators, not proof that a person is fraudulent. Clearly separate technical
evidence from social-engineering indicators. Warn at the safest useful point and
explain the specific consequence. Do not capture private content merely to fill
coverage gaps. Browser interception requires a separately tested browser integration.

Credential protection includes browser stores/cookies, password databases, SSH,
cloud/API/OAuth credentials, wallet keys and recovery material. Track abnormal
access and secret boundary crossings without retaining secret values. Redaction is
best-effort; unidentified secrets and ordinary private prose remain a blind spot.

External executables/scripts require origin, redirects, initiating process/browser,
time, hash, signature/publisher, reputation, first-seen context and actual versus
declared format. Preserve provenance across archive extraction and execution.

## State, causality and temporal memory

Build a continuously updated state graph across hardware, firmware, boot, kernel,
drivers, processes/threads, users/sessions, services, packages, files, configuration,
sockets/domains/IPs, devices, credentials, containers and JARVIS components.
Record causal edges: parent/child, process/file/socket/memory/driver/privilege/DNS,
service/executable, download/artifact/execution and event/preceding event.
Observe relationships and sequences, not just suspicious object names.
Mark unattributed important changes UNEXPLAINED SECURITY-RELEVANT TRANSITION.
Preserve uncertainty and sensor disagreement rather than inventing causality.

Observe supported CPU/core/frequency/power/temperature/throttling, GPU/VRAM,
RAM/pressure/paging, scheduling, interrupt/DPC/ISR, disk latency/IOPS/queue/SMART,
NIC, battery, USB/PCIe, fan and hardware-error signals. Correlate resource effects
with responsible processes and devices. Resource anomalies are supporting evidence;
malware may fit normal variation. Never equate heat or load with compromise.
Use robust median/MAD scores (0.6745 * deviation / MAD), EWMA, CUSUM/change points,
robust multivariate covariance where justified, quantiles, entropy, periodicity,
burstiness and cross-correlation. Define zero-MAD behavior, warm-up, contamination,
false positives and drift tests. Keep anomaly, risk, maliciousness and measurement
confidence separate. Never silently learn a suspicious period as a trusted baseline.

## Sensor trust, attestation and internal isolation

Treat every sensor as potentially compromised. Require identity, heartbeat,
sequence/monotonic references, replay detection, integrity and independent comparison.
Compare user/kernel observations, boot/TPM and independent network evidence where
available. TPM/Secure Boot inventory is not remote attestation: validated quotes,
fresh challenges, trusted PCR baselines and key protection are separate requirements.
Separate observation, analysis, policy, privileged response, storage, synchronization,
updates and UI so a component compromise does not confer unrestricted authority.
Never silently accept missing sensors, changed binaries, disappeared drivers,
unattributed listeners or disabled controls as healthy state.

## Evidence and privacy

Security events require timestamp, monotonic reference, sequence, sensor, event
type, actor, target, process/session, correlation ID, confidence, context, integrity
hash/signature and causal parent where known. Unknown fields remain unknown.
Use bounded structured storage, compression, batching and deduplication; never sample
away critical discrete security events. Retain high-resolution recent evidence,
compressed history, security events and long-term summaries under explicit privacy
and capacity budgets. Encrypt local data and protect keys with hardware where
practical. Cryptographic chains/Merkle histories need independently protected anchors;
a locally recomputable hash alone does not prove tamper resistance. Secure evidence
replication must minimize sensitive content and preserve user control.

## Forge, coverage and engineering acceptance

Use an isolated environment for persistence, credential access, injection, tampering,
living-off-the-land, shell attacks, C2, staging, safe ransomware simulation, sensor
suppression, log tampering, privileges, phishing/browser/download/OAuth threats,
reboot persistence and boot/security changes. Never run those simulations against
personal data or live user accounts. Every scenario specifies telemetry, detection,
correlation, human protection, containment, recovery and maximum detection/response
latency. Keep theoretical, observed, implemented, tested and validated-containment
coverage distinct; include last validation, safety consequences and blind spots.

For every capability define threat, human impact, observable effects, sensors,
logic/mathematics, invariants, false positives, evasion, intervention and rollback.
Implement and verify with relevant unit, property/state-machine, integration,
adversarial and performance tests. Apply formal methods where useful; passing unit
tests is not formal verification. No claim without evidence.

Budget idle/active CPU, RAM, disk writes, growth, network, battery and latency.
Prefer event-driven collection and safe adaptive sampling. Usability is a security
property. Require pinned dependencies, provenance, signed releases, SBOM, secret/
static/dependency/vulnerability checks and protected reproducible builds where
practical. Prefer memory-safe new privileged components and minimize dependencies.

Recovery means Protect → Detect → Contain → Investigate → Recover → Verify.
Preserve known-good state and recovery paths. A successful command or vanished
finding is not proof of restored protection: verify fresh complete observations
and relevant invariants after remediation.

## Current enforceable boundaries and known limitations

`jarvis/core/assurance.py` is the conservative machine-readable coverage register,
exposed under `assurance` in `/api/health` and `/api/live`. Its entries are engineering
assessments, not live sensor measurements. Existing health booleans indicate the
existing required collectors and scheduler; they do not mean this entire directive
is satisfied. Null validation and latency fields are intentional, not zeroes.

### Two scores, never one number

Protection health and assurance are different questions and must stay separate:

- **Protection health** (the scored machine areas) asks whether *this machine* is
  currently protected and observed. It becomes high only when every area's evidence
  is fresh and complete — a running dashboard, UI or globe never adds a point.
- **Assurance** (`assurance.score` in `/api/health`) asks how much evidence supports
  trusting *JARVIS itself*. It is weighted by the implementation claims in the
  register and by how much of each capability's telemetry is observable right now.
  Its rules are deliberately harsh: only `complete` observations earn credit, a
  capability with no observation mapping scores like blindness, a fully blind
  system scores 0 regardless of its claims, and 100 is unreachable while the
  register holds `partial` or `unverified` entries. Neither score is a compromise
  verdict or a safety guarantee, and neither may be presented as one.

### The telemetry chain is observable stage by stage

Native delivery has eight independently observable stages — installed, running,
producing, arriving, ingested, gaps, integrity, fresh — persisted by the native
job (`native_delivery`) and surfaced as `telemetry_chain` in `/api/health`. When
delivery degrades, the status must name the broken stage, not collapse everything
into "sensor works". A silent native job marks the chain not-current rather than
letting a stale answer look healthy.

Evidence handling follows the same principle of honest loss: a sensor batch that
straddles a log clear contains two sound monotonic record blocks whose ID ranges
overlap (Windows reuses record IDs after a clear). Such a batch is split and both
blocks ingested, with the reuse recorded as a gap in the event history. A batch
too malformed to split is preserved under `quarantine/` with its digest, recorded
as a loss, and the cursor advances past it. The channel may never be wedged
forever by a single batch, and no loss may ever be silent.

Response intent is committed before action execution; interrupted outcomes inhibit
repeat application and require evidence/target inspection. This does not yet supply
transactional filesystem/firewall rollback, concurrency exclusion across processes,
or complete recovery tokens after power loss. Do not delete uncertain ledger entries
to force retries. Inspect the case and actual target; reconcile manually.

The advisory model uses loopback only, with recognizable secret redaction. Python
transport ignores proxies and refuses redirects; the Windows bridge refuses redirects.
A hostile local model service or host compromise remains outside that guarantee.

Maximum effects of existing automatic operations:

| Operation | Maximum intended effect | Recovery / remaining safety gap |
|---|---|---|
| Quarantine | Move one matched Linux file and write a marker | Undo restores without overwrite; dependency and race analysis incomplete |
| Address block | Block one IP for all Windows processes | Remove named rule; shared hosting/emergency reachability not modeled |
| Disable autostart | Disable one task or remove one Run value | Restore recorded state; essential-service dependency analysis incomplete |
| Suspend | Stop one Linux PID | Resume same identity; automatic eligibility currently disabled |
| Telemetry repair | Start fixed Sysmon service | Rate limited; no arbitrary command execution |
| Bridge repair | Invoke fixed mount repair | Rate limited; host-specific verification required |
| Orphan firewall repair | Disable matched orphan rules after backup | CLIXML rollback; Windows deployment validation required |

These are explicit limitations, not maximum-assurance completion. Priorities are
race-safe action identity and transactional recovery; essential-service exceptions
and containment leases; authenticated independent native telemetry; browser integration
and provenance; protected forensic storage; attestation; and isolated Forge validation.
