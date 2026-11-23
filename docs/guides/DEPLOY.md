# Deploying a JARVIS release

## Owner decision (2026-09-24)

Deploy with `--skip-tests`, and judge the release by real results on this machine.

The deploy script used to run the whole unit suite inside the root deploy, as a gate. On
2026-09-24 a test that made a wrong assumption about that environment (its parent process was
unreadable) refused a correct release. The owner decided that the unit suite runs **before**
staging, as part of development, and that the deploy itself proceeds on live evidence.

## What still guards a deploy

`--skip-tests` removes only the unit-suite run. These checks remain:

- The stage is the live sealed release plus named, reviewed files (`jarvis release stage --file …`),
  never the dirty checkout.
- `--expect-base` refuses the deploy if another release was switched in after staging.
- The deploy lock allows one writer at a time.
- The built tree must pass the sealed-release check (`code_tree_problems`); otherwise it is removed.
- The previous release is kept, and `--rollback` switches back to it.
- The unit suite (`python3 -m unittest discover -s tests`) must still pass in development before
  anything is staged. Skipping it at deploy time does not mean skipping it altogether.

## Command

```
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
  --source ~/.cache/jarvis-release-staging/<stage> \
  --checkout ~/jarvis \
  --expect-base <release_id printed by `jarvis release stage`> \
  --skip-tests
```

Always keep `--checkout ~/jarvis`. Without it, the JARVIS watchdog tasks read as critical.

Rollback:

```
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py --rollback
```

## Before deploying

1. Record a baseline: the overall and per-area scores, plus the findings of every job the release
   touches, with each snapshot's timestamp.
2. Write down what the release is expected to change, finding by finding. The live readback is
   compared against these expectations, not just against the score.
3. Never delete or replace a stage that a deploy may be using. Put a new stage beside it.

## Verify on real results (the deploy's acceptance gate)

1. The service is running the new release: `readlink -f /opt/jarvis/current`,
   `systemctl show jarvis.service -p ActiveState -p NRestarts` (active, 0 restarts), and
   `/api/health` reports `healthy`, `ready` and `protection_healthy`.
2. The journal since the restart has no tracebacks. Startup lines, such as `provenance authority:`,
   read as expected.
3. Every affected job has produced a **fresh** snapshot, taken after the restart, without errors.
   Force one if needed: `curl -X POST "http://127.0.0.1:8787/api/run?job=<name>"`.
4. Compare each fresh snapshot with the baseline, finding by finding. Every finding that disappeared
   or dropped in severity must be explained by the change. A score gain from lost visibility is a
   regression (see `docs/security/MAXIMUM-ASSURANCE.md`).
5. Read the score back over several collector intervals, not once.

## Roll back when

- the service fails to start, restarts repeatedly, or health is not `ready`;
- a collector the release touched errors or goes stale;
- findings disappear without an explanation from the change, or coverage drops;
- anything else behaves differently from what was written down before the deploy.

Record the outcome, measured before/after with timestamps, in the relevant `docs/security/`
review. Do not report a release as working from its deploy output alone.
