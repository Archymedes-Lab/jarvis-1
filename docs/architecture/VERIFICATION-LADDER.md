# Verification ladder (2026-10-21)

The owner asked for JARVIS to become static-analysis based, with levels of formal
verification. This records the ladder, what each rung proves and does not prove, what was
built today with its measurements, and the order for the rest. The
[Maximum Assurance directive](../security/MAXIMUM-ASSURANCE.md) still governs: a proof about
a model is evidence about the model, never a compromise verdict about the machine.

## Invariants the ladder guards

Written before the code, from the existing design documents:

| Id | Invariant | Where it was prose | Rung |
| --- | --- | --- | --- |
| V1 | Score is in 0..100; a blind area reads 0; losing a collector never raises the score | score-integrity, SCORE-STABILITY-REVIEW | L1 |
| V2 | Adding a finding never raises the score; the same fact twice counts once | score.py docstrings | L1 |
| V3 | Stale or incomplete observations never count as evidence and are listed as degraded | SPYWARE-REASONING #1 | L1 |
| V4 | Adding positive evidence never lowers a verdict | SPYWARE-REASONING #5 | L1 |
| V5 | A valid signature never raises an input watcher's severity; exit never launders it; JARVIS's own supervised hook never counts | watchers.py docstring | L1 |
| V6 | Under a declared privacy seal, any reopen, policy override or use is reported high by the next collection; an intact seal never alarms; nothing is reported without a seal | PRIVACY-SEAL | L2 |
| V7 | A release staged on a base that is no longer live is refused; rollback restores the previous release | DEPLOY, EVIDENCE-FABRIC P1/P5 | L2 |
| V8 | A due fast-lane job never waits behind a main-lane job; protection jobs are in the fast lane | LANE-FAIRNESS | L2 (abstract) |
| V9 | Every collector is declared once with a complete contract (scored or unscored with a reason, budgets below interval, no governed tier 0 or fast-lane job, lane duty under 0.8); every mechanism primitive names existing code and tests | MECHANISMS | L1 (declarations; files where tests/ ships) |
| V10 | A health source reads unavailable only when its collection failed; a successful read with a named coverage gap reads partial; nothing with an error or gap reads complete (2026-10-30: one Sysmon start gap made a working `scan` read unavailable) | protection._state, collection.py | L1 (`tests/test_source_status.py`) |
| V11 | The interop gate always recovers: slots stay in 0..2, backoff never exceeds 300 s, a refusal needs an open window, a probe or full slots, and from every reachable state finished launches plus one success close the gate | INTEROP-GATE | L2, drives the real `interop_gate.Gate` (`jarvis/verify/models/interop_gate.py`) |
| V12 | Collectors, the service and core launch Windows programs only through the gated `platform.windows` path; each exception names why it cannot wait | INTEROP-GATE | L0 rule S1 (`jarvis/verify/static.py`), `tests/test_windows_launch_gate.py` |
| V13 | A containment action is applied only by a human approval or by the automatic rung with its flags, high severity and complete coverage; automatic actions stay under their cap; a time-bounded action carries an expiry and is lifted only by a verified undo; after a human undo a recurrence is only proposed | defense.py, ban_source.py (2026-10-30) | L2 model driving the real `defense` code (`jarvis/verify/models/response_ladder.py`), tests |
| V14 | An elevated shell runs only inline code fixed at launch, or files it verified in an administrator-only folder; no command line goes through a shell; launchers start PowerShell by full path | sensor/broker/posture installers (2026-10-30) | L0 rules S2-S4, `platform/elevation.py` tests |
| V15 | Text the observed party controls never chooses a containment target | ban_source.py, bruteforce.py (2026-10-30) | L1 property, driven end to end through the real collector and action |

## The rungs

**L0, static analysis (built).** `scripts/dev/static_gate.sh`.
ruff now selects pyflakes, syntax, import order, bugbear and pylint-error classes
(`pyproject.toml`). Fixing the gate found two real defects: a closure capturing an `except`
target after the clause ends (`fixdraft.py`, would have raised NameError on the failure path)
and a duplicated entry in a vetting set. mypy runs on the pure packages (`core/reasoning`,
`core/execution`, `response/reporting`, `verify`) with transitive imports followed silently, so
the typed set grows package by package. Six type errors were fixed on the way. Both gates
read clean at the end of the day.

**L1, property checks (built).** `jarvis/verify/props.py`, `tests/test_verify_props.py`.
Standard library only: a seeded generator, a fixed number of cases, replayable by seed and
index, no shrinking (cases are kept small by construction instead). Jev put "adequate first
rung rather than a reason to add Hypothesis" at 0.84. Ten properties over V1 to V5, 150
cases each. The first run **falsified an over-claim**: points in the reasoning engine are not
monotone, because a capture capability explained by the subject's own publisher turns its
autostart and network companions into "part of being that product", so the chain points drop
while the verdict rises. The documented invariant is about the verdict; the property now
states exactly that, and points-monotonicity only for non-capture evidence.

**L2, exhaustive model checking (built).** `jarvis/verify/mc.py`, `jarvis/verify/models/`.
A breadth-first explicit-state checker: every reachable state, every invariant, shortest
counterexample path, bound reported rather than hidden, optional deadlock freedom.
Self-tests plant a violation and check the path. Three models:

| Model | Drives real code? | States | Transitions | Result |
| --- | --- | --- | --- | --- |
| privacy seal lifecycle (V6) | yes: `privacyseal._seal_findings` | 71 | 283 | exhausted, no violation |
| release switch (V7) | yes: `deploy_root_runtime.check_expected_base`, `release.release_id` | 57 | 152 | exhausted, no violation |
| scheduler lanes (V8) | no: policy model; membership asserted against `scheduler.FAST` | 98 | 165 | exhausted, no violation |

A planted-bug test weakens the seal detector (ignores a reopened desktop value) and the
checker produces the counterexample `seal, reopen_desktop, collect`. Jev rated driving the
checker through the real pure functions as the stronger evidence at 0.82, and the abstract
lane model as adding meaningful assurance at only 0.64, which is honest: it pins the shape
of the claim, not the code.

**L3, model-checked specifications (not built).** TLA+ or Alloy for the real scheduler
selection (lateness, starvation, forced cooldown, governor deferral), the broker handshake,
and the evidence hash chain with its cursor commit points. Java is present on this machine,
so TLC can run locally; the specs would live beside the models with the same invariants.
Jev's pick for the next rung was the scheduler model (0.43, low concentration).

**L4, refinement proofs (not built).** Dafny or Lean for the pieces where a bug is a safety
bug: response-ladder gating (auto versus propose), the severity lattice, the hash chain. The
Python stays the tested twin of the verified artefact.

**L5, boundary contracts (partly in place).** The PowerShell and ETW parsers cannot be
proven; they get schema validation on output (`_valid` in each collector) and measured
positive controls. Today's polling-keylogger probe is the pattern: the claim "1003 is
visible" is held only by a measurement, re-runnable by anyone.

## What the ladder does not say

A clean L0 gate is not type safety for the whole tree; only the listed packages are typed.
A property that passes 150 seeded cases has not been proven; it has survived a search. An
exhausted model proves the model, within its abstractions, each listed in the model's
docstring: one capability, bounded uses, discrete ticks, no filesystem, no lock. None of it
observes the live machine; the register in `assurance.py` keeps that distinction.

## How to run

```
scripts/dev/static_gate.sh            # ruff, mypy, L1 and L2 tests
scripts/dev/static_gate.sh --quick    # ruff and mypy only
python3 -m unittest tests.test_verify_models -v
```

## Order for the rest

1. Widen `TYPED` in the gate script one package at a time, fixing as it goes (Jev 0.25).
2. Scheduler model against the real `_due` with injected clock, reliability and governor, in
   the in-tree checker first; promote to TLA+ when the state space outgrows it (Jev 0.43).
3. Response ladder model: every action's auto-eligibility across severity, coverage and flag
   combinations, exhaustively (Jev 0.15).
4. Hash chain and cursor commit model (Jev 0.11).

## 2026-10-22: the ladder ships inside the product

Owner request: static analysis and formal verification in Argus (the public build of
JARVIS) by default. What changed:

- **The property catalogue lives in the package** (`jarvis/verify/properties.py`, eleven
  properties over V1 to V5, 150 cases each). `tests/test_verify_props.py` now runs that
  catalogue; the catalogue is the single definition.
- **A runner and command**: `python -m jarvis.verify [--json PATH] [--cases N]` runs every
  property and exhaustively checks the three models over the installed files, prints a
  report and exits 1 on any failure. Standard library only, 0.3 s on this machine
  (11/11 properties, 1650 cases; 3/3 models, 226 states).
- **A daily `verify` job** (`jarvis/service/verifyjob.py`, bulk lane, governor-deferrable,
  Monitoring area) repeats the run and records it in the store (`code_verification_v1`).
  A failure is a *high visibility* finding about JARVIS itself ("Installed code violates
  a verified invariant"), never a verdict about the machine. The job loads
  `jarvis.verify` at run time because that package sits above every layer it exercises
  (`tests/test_layers.py`).
- **Argus build gate** (`~/archymedes-site/scripts/argus/build.py`): every build runs ruff
  and mypy (the same selection as `scripts/dev/static_gate.sh`) and `python -m argus.verify`
  over the renamed tree, refuses to package on failure, and records the results under
  `verification` in `manifest.json`. `--skip-verify` packages anyway and records the
  failure; `--worktree` builds the working copy as a tree object without a commit.
- **Install-time gate**: the Windows and Linux installers run `python -m argus.verify` over
  the files they just installed and refuse (Linux: keep the previous install) when it
  fails; the report is kept beside the program. `-SkipVerify` / `--skip-verify` override.

What a pass means: this copy keeps the eleven stated properties on the generated cases and
no reachable state of the three models breaks its invariant. It says nothing about
inputs or states the catalogue leaves out, and nothing about the machine being monitored.
Still not built: L3 (TLA+/Alloy specifications) and L4 (refinement proofs).

## 2026-10-30: the framework that powers Argus-1

Owner request: a formal verification framework, invariants and static analysis that
Argus-1 runs on itself. The ladder above becomes one framework with three additions,
all standard library and shipped in the package, so `python -m argus.verify`, the daily
`verify` job, the build gate and the installers all run them with no new wiring.

**The invariant registry** (`jarvis/verify/invariants.py`) is the single list of what is
guarded. Each invariant names its checks (`property:`, `model:`, `static:`, `membership:`,
`test:`). Conformance fails when an invariant has no executable check, when a named check
does not exist, when a check proves an invariant nobody registered, or when this table
drifts from the registry (`tests/test_verify_invariants.py`). The report prints it.

**Shipped static rules** (`jarvis/verify/static.py`) for this product's own bug classes,
each born from a defect found in it: S1 (V12) launches outside the interop gate; S2 (V14)
an elevated shell started on a script file; S3 (V14) command lines through a shell; S4
(V14) `.cmd` launchers calling PowerShell by bare name. There is no list of tolerated
violations: S2 found three live ones (`broker.py` twice, `posture/collect.py`), and they
were fixed before the rule shipped, all through one helper, `platform/elevation.py`
(copy into Program Files, match a SHA-256 fixed before the prompt, run only that copy).
Jev put "record known violations and fail only on new ones" at 0.35, the safe reading
of which is what was done. A copy without sources (the sourceless Linux release) reads
"not applicable", never a pass. The rules take 0.8 s over 563 files; each has a fast
exit on text it needs to match at all.

**V15 as a property**, driven through the real brute-force parsing and the real
`ban_source.match`. Its first version did not catch the defect it was written for (four
exact words in order never arose from single tokens in 150 cases); a planted-bug test
(`tests/test_verify_props.py`) now restores the old pattern and requires the property to
fail, and the generator writes whole clauses in the detector's shape.

What it does not say: the rules are syntactic (a `-File` argument passed in from another
function, or a literal split mid-token, is not seen); the hashes that guard elevation are
taken by the same unprivileged user, so they close the staging-to-prompt window, not a
modified checkout (release signing would; Jev 0.82 as the next gap).

**V13 as a model of the real response ladder** (`jarvis/verify/models/response_ladder.py`).
Each step rebuilds a ledger store from the state and calls the shipped `defense.process`,
`approve`, `undo` or `expire` with one synthetic time-bounded action (cap 1, two sources,
four flag combinations, a lift that can fail, a clock of three ticks). Invariants:
authority (a collection pass applies only with both flags, high severity and complete
coverage), the cap on automatic actions, an expiry on every applied action with the world
matching the ledger, and human override. 14,773 states, 139,104 transitions, 8.4 s.

**Its first run found a real defect in the ladder**, present for every automatic action:
after a person undid an automatic action, the next recurrence became a proposal, and the
one after that applied it again (`configure > collect > undo > collect > collect`). The
module promised the opposite. The proposal now carries an `override` mark that keeps it a
proposal on every later pass until a person approves it, which clears the mark
(`tests/test_defense.py` reproduces the old behaviour with the real quarantine action).
Restoring the old line in memory makes the model fail with exactly that path. Planted
defects in the flags, the cap and an undo that lies are each found
(`tests/test_verify_ladder_model.py`).

Its abstractions, also in the model's docstring: evidence capture and apply always
succeed; interrupted actions (`reconcile`) are not modelled; bookkeeping the ladder never
reads back in these paths (timestamps, attempt counters) is folded, and `applications` is
capped at the last TTL rung, which the code cannot tell apart; tests use a one-tick
window, the shipped run three ticks.

Next, in order: runtime monitors that evaluate the same predicates over the live ledger
in the daily job; the interrupted-action paths in the ladder model; then L3 for the
scheduler.
