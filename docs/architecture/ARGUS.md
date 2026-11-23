# Argus: a reference monitor for deployed AI agents

Rebuilt 2026-10-23. The original of this document and of `jarvis/argus/monitor.py`
were lost; the design intent survives in `scripts/reviews/argus_advisory.py` (the
alternatives, the evidence considered and the eight invariants) and in the
docstrings of `labels.py`, `policy.py` and `journal.py`. This text restates that
intent and records what the rebuilt code does and does not establish.

Argus applies the JARVIS contract (external content is evidence, never authority;
a human stays in authority over consequential actions; every decision leaves a
tamper-evident record) to AI agents that act on the web, on data systems and
toward people.

## Threats

- Indirect prompt injection through tool output, web pages, documents, email and
  other agents.
- Tool poisoning and rug-pull: an MCP server changes a tool's description or
  schema after the owner approved it.
- Exfiltration to an attacker-chosen destination (the EchoLeak class).
- Irreversible actions: deletion, overwrite, deploy, payments, credential and
  permission changes.
- Credential and privilege abuse; cascading failures and runaway agents.

## Design chosen: B, a session reference monitor

Three alternatives were compared (see `argus_advisory.py`):

| | Design | Strength | Cost |
|---|---|---|---|
| A | Per-value capability tracking (CaMeL style): Argus owns the planner and an interpreter | strongest; provable on a large share of AgentDojo tasks | ~2.8x tokens; only for agents built on Argus |
| **B** | **Session reference monitor**: every tool call passes one deterministic gate; session taint high-water mark; argument provenance labels; Rule of Two forces confirmation | works around black-box agents via an SDK hook or MCP gateway | coarser: over-blocks some benign tasks |
| C | ML guardrail detectors | easy to deploy | measured adaptive attacks bypass them |

B is the enforcing core because Argus must protect agents it does not build. A is
a possible stricter mode later. C is admitted only as an advisory detector that
can add friction and never permission.

Reconsider when: Argus hosts the planner itself (A becomes available), or a
measured benchmark shows B's over-blocking makes confirmations routine enough
that humans approve without reading (approval fatigue defeats the gate).

## How a call is decided

`Monitor(policy, journal, clock=time.time)` guards one agent session.

```
Call(tool, args, arg_labels, manifest_digest)   # frozen
Monitor.check(call, detectors=()) -> Decision(verdict, reasons, call_digest, seq)
Monitor.observe(label)                           # fold an input or tool result in
Monitor.approve(call_digest, approver) -> grant  # raises ApprovalError
Monitor.kill(reason)
Verdict: ALLOW < CONFIRM < DENY
```

Rules only raise the verdict; the single path from CONFIRM to ALLOW is a grant.

1. **DENY, final**: kill switch engaged; unknown tool; live manifest digest differs
   from the pinned `ToolSpec.digest`; a budget exhausted; a SECRET-labelled
   argument to an OUTBOUND (egress/communicate) call; any internal failure; and
   any decision the journal could not record.
2. **CONFIRM**: an ALWAYS_CONFIRM effect (irreversible, spend, identity); the Rule
   of Two (session plus arguments untrusted AND at least PRIVATE, with an
   EXTERNAL effect); an outbound call whose declared destination arguments are
   not all in `Policy.destinations` (or that declares none); any detector signal
   other than ALLOW, or a detector that raised.
3. A CONFIRM becomes ALLOW only with an unexpired, unused grant for exactly that
   call digest.
4. On ALLOW the monitor spends budget and folds the tool's result into the session
   as untrusted (PRIVATE when `reads_sensitive`), without waiting for the
   integration to call `observe`.

An argument without a label is given the session's label joined with `UNKNOWN`:
whatever the session saw may have shaped it. An integration that knows better
(the owner typed it) labels it explicitly. Integration code is trusted; the
model's output is not, so labels must never be taken from the model.

## Invariants and their evidence

Evidence is `tests/test_argus_monitor.py` (44 tests; classes below are named without their `Tests` suffix) against the real
hash-chained `Journal` in a temporary directory, plus `tests/test_layers.py`
(argus sits at rank 1 and imports only `jarvis.core`).

| Invariant | Tests (class.method) |
|---|---|
| External content is evidence, never authority | ExternalContent.untrusted_text_claiming_approval_is_not_authority, .unlabelled_argument_is_untrusted_and_carries_the_session, .non_label_observation_counts_as_unknown |
| Approval only from a registered human, bound to the exact call, single use, expiring | Approval.* (registered allows once, unregistered/malformed refused, swapped arguments refused, unseen digest refused, expiry, no carry across sessions, unrecorded approval not granted) |
| Rule of Two; taint is a high-water mark | RuleOfTwo.* (all three legs confirm; any two alone allow; untrusted argument as a leg; sensitive tool taints by itself; observe(OWNER) never cleans; label join monotone, commutative, idempotent over every level pair) |
| SECRET never reaches an outbound call, even with approval or a detector's blessing | SecretEgress.* |
| ALWAYS_CONFIRM effects always ask; unapproved destinations ask | AlwaysConfirmAndDestination.* (lists with one bad entry, missing, non-string and empty destinations; reasons never echo the destination) |
| Any monitor failure denies | FailClosed.* (unknown tool, undigestable or NaN values, non-Label label, non-dict args, broken policy) |
| No allow without a durable record; journal holds digests, not values | Journal.* and AllowAndRecord.journal_holds_digests_never_argument_values (broken journal, unwritable location, confirmation not offered for approval when unrecorded, edited/deleted/corrupt records named by `verify()`, corrupt tail denies further calls) |
| Bounded budgets and a kill switch | BudgetAndKill.* (calls, external, irreversible even with approval, denied/pending calls do not spend, kill denies granted and pending calls and refuses approval, kill holds when the journal is down) |
| Changed manifest denied until re-pinned | Manifest.* |
| Detectors only add friction | Detector.*, FailClosed.failing_detector_adds_friction_not_permission, SecretEgress.detector_cannot_release_a_secret |

The tests were also run against nine hand-made mutants of the monitor (grant not
consumed, no expiry, no Rule of Two, secret egress allowed, detector downgrade,
unlabelled arguments ignoring the session, no manifest pin, journal fail-open, no
kill switch); every real mutant failed at least one test.

## Design notes

- **Detector failure** gives CONFIRM, not DENY: a detector is advisory and an
  outage should cost a human glance, not the agent's whole session. Monitor
  failures proper (policy, labels, digests, journal) deny.
- **Digests are keyed per session** (HMAC with a random in-memory key), so the
  journal cannot be used to test guesses of a low-entropy argument offline. The
  consequence: argument digests correlate within a session only.
- **Approvals are journaled before they exist**; an unrecordable approval is
  refused. Only digests the monitor itself returned as CONFIRM can be approved.
- Agent-controlled names (tool, argument) are clipped to 128 characters in the
  journal; denial reasons name arguments, never values or destinations.
- Detectors receive the `Call`, including argument values. A detector backed by a
  remote model (Jev) must reduce it to metadata itself; the AGENTS.md rule that no
  private content goes to a model applies to the detector, not to the gate.

## What is NOT claimed

- **No live agent integration is measured.** There is no SDK hook or MCP gateway
  in this tree; nothing here has gated a real agent.
- **No protection claim.** A measured adversarial benchmark (attack success rate
  and benign utility on AgentDojo-style tasks against a real agent) is still
  required before saying Argus protects agents. Unit tests show the gate's rules
  hold; they do not show the rules are the right ones or that over-blocking is
  tolerable.
- Session taint is coarse: once a session reads untrusted private content, every
  external effect asks. The expected over-blocking is unmeasured.
- Labels are only as good as the integration that assigns them. A tool that
  returns secrets but is declared `reads_sensitive` is folded as PRIVATE, not
  SECRET, unless the integration observes a SECRET label; an explicitly
  mislabelled argument is believed.
- The journal is a locally recomputable hash chain. It detects editing, deletion
  and reordering by anyone who does not rewrite the whole chain; without an
  independently protected anchor it does not prove tamper resistance.
- Session state is in memory: a restarted monitor starts clean (budgets, taint,
  grants). A durable session store is not built.
- The kill switch is per monitor; there is no fleet-wide switch.
- `Policy` is mutable operator configuration and is trusted by construction; its
  own integrity (who may pin a tool or add an approver) is outside this module.
- Jev was not consulted for this rebuild (no network calls were permitted).
