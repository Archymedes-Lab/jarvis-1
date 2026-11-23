# Architecture, limitations and evaluation

Start with the [Defender Engine architecture](../architecture/DEFENDER-ENGINE.md),
[Maximum Assurance limits](../security/MAXIMUM-ASSURANCE.md) and the
[verification ladder](../architecture/VERIFICATION-LADDER.md).
[jarvis/core/assurance.py](../../jarvis/core/assurance.py) is the conservative
capability register. Its claims require measured evidence; this open-source
transition changes no capability status.

On a disposable development machine, record the commit, OS, tool versions,
command, elapsed time, exit code, skipped checks and output digest. Keep raw
results private if they contain machine details. Publish synthetic fixtures
and redacted summaries that another developer can reproduce.

```bash
python3 scripts/dev/fasttest.py --all  # scratch HOME per worker
scripts/dev/static_gate.sh
python3 scripts/dev/standard_check.py
python3 scripts/security/campaign.py --list
```

The [security campaign](../security/ARGUS-SECURITY-TESTING.md) documents bounded
methods, prerequisites and gaps. Run adversarial methods only in its isolated
environment. Inspect the selected methods before execution. Do not run live
attack simulations against personal data or an installed production service.

Unit, property and model checks establish only their tested invariants. Replay
of detection fixtures measures fixture matching, not live attack detection.
A running collector does not prove freshness, complete sensor delivery,
containment safety or absence of compromise. A reproducible test run does not
establish reproducible binary builds. Report unsupported platforms, unavailable
tools, missing live measurements, false positives, resource costs and recovery
gaps explicitly. New benchmark claims need public synthetic inputs, precise
counting rules and both successful and missed cases.
