# Fuzz harness

Standard library only (Python 3.12+, `sys.monitoring` line coverage), so it runs where the
release gate runs. Findings: `docs/security/FUZZ-FINDINGS-2026-11-04.md`; their regression
tests: `tests/test_fuzz_findings.py`.

    python3 -m tests.fuzz.run --list
    python3 -m tests.fuzz.run --budget-seconds 60          # all targets, budget split evenly
    python3 -m tests.fuzz.run --target gate.deb --per-target 30 --seed 3 --out /tmp/fz

Each target runs in its own child process with `HOME`, `TMPDIR` and XDG dirs in a new temp
directory and a hard kill at budget + grace; the input being run is written to
`<out>/<target>.current` first, so even a hang stuck in C code leaves a reproducer.
Results: `<out>/<target>.json` and `<out>/summary.json`. Exit status is 1 when a finding not
listed in `known.json` appears (remove an entry once its fix lands).

## What counts as a finding
- `crash`: an exception the target did not declare in `Target.expected`;
- `hang`: one input past `timeout_s` (SIGALRM) or the hard kill;
- `slow`: one input past `slow_s`, twice in a row (the machine is loaded);
- `oracle`: an `AssertionError` from the target's property, i.e. a blind spot or misreport.

## Targets
`targets/release_gate.py` (ar/.deb, zip, scan_bytes, nested archives, Windows name
equivalence, version tags), `targets/collectors.py` (sshd failure attribution, journal JSON,
Linux Sysmon and Windows event XML, sshd_config, authorized_keys, winget/apt/snap/choco/brew),
`targets/web.py` (`_json_body`, client tokens, request tokens; handler methods called on an
object built without a socket).

## Adding a target
Write `run(data)` in a module under `targets/`, append `Target(name, run, seeds, ...)` to its
`TARGETS` (add the module to `targets/__init__.py` if new). Seeds are synthetic, built from the
formats in `tests/` fixtures, never from real logs or `~/.jarvis`. Prefer a property over
"does not crash": state what the parser must report (the address sshd wrote, every row after an
odd one, a denied name wherever it sits). Never start the daemon, open sockets, run PowerShell
or read system logs from a target.
