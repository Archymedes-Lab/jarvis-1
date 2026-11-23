# Jarvis restructure prompt

Paste everything below the line into a fresh Claude Code session at the repo
root. It runs in phases and stops for approval between them, so the same
prompt can be reused: say "continue from phase N" to resume.

---

You are restructuring **Jarvis**, a host security monitor (WSL2 + Windows
bridge, Python stdlib, SQLite store, CLI + web dashboard, systemd units,
PowerShell helpers). Goal: the best achievable code quality — clear sections,
strict compartmentalization, measured performance — **without changing what
Jarvis detects, reports, or repairs.**

This is a security tool. A refactor that silently drops a detection is worse
than no refactor. Every rule below exists to prevent that.

## Lessons from the first run (2026-09-14): read before starting

The layered layout already exists (`docs/architecture/TARGET.md`), and
`tests/test_layers.py` enforces it with no exceptions. Later runs work *within*
that layout. Don't re-derive it.

- **The live daemon runs from this checkout.** `jarvis.service` executes
  `python3 -m jarvis serve` in this directory, and some imports and paths
  resolve lazily at runtime. After any commit that moves files, run
  `sudo -n /usr/bin/systemctl restart jarvis.service`, then check
  `SELECT kind, error FROM snapshots` for errors once jobs have run. Skipping
  this once produced a real "input-hook helper script is missing" alert.
- **Three scripts must stay at the repo root:** `wake-jarvis.ps1`,
  `deadman-jarvis.ps1`, `connectivity-jarvis.ps1`. Installed Windows task copies
  self-sync from `<RepoRoot>\<name>`, and a moved file makes them silently
  stop updating.
- **The freeze check is a tool:** `python3 scripts/dev/behavior_snapshot.py
  <dir> [--compare <before>]` diffs CLI help and every string literal. Run it
  before and after each step, and account for every difference.
- **Lint:** `uvx ruff check` (pyflakes + syntax) must stay clean.
- **Moves:** regenerate import statements from the AST while preserving every
  bound name (`from jarvis.platform import windows as collect_windows`), and
  rewrite dotted `mock.patch("jarvis....")` targets. A lazy import that a test
  patches at its source module stops seeing the patch once hoisted, so grep
  the tests before hoisting.
- **Verify behavior on real data** where you can. Run the old code from a
  `git worktree` of the previous commit and the new code against the same
  copy of `~/.jarvis/jarvis.db` (`sqlite3 … ".backup <scratch>"`), then compare
  outputs.
- **Open follow-ups** are in `docs/architecture/FOLLOWUPS.md`, and they're the
  natural next work.

## Non-negotiables

1. **Behavior is frozen.** Finding `category`, `severity`, `title`, `detail`
   shape and `host` values stay identical. `response.alert.finding_key` derives
   alert identity from `category|title|where`, so a renamed title or `where`
   re-alerts, resets escalation, and orphans repair history. The same applies to DB schema, `~/.jarvis/config.json` keys,
   meta keys (e.g. `automatic_repairs_v1`), and CLI subcommands/flags used by
   systemd units, `*.sh`, `*.ps1`, and `jarvis/static`.
2. **Never weaken a guard.** Don't loosen thresholds, allowlists, or severity
   to make something pass. Leave in place any check that says "unknown is not
   proof" (dpkg, signatures, interop availability, coverage accounting).
3. **Untrusted data stays data.** Feed indicators, log lines, process names
   and paths are never interpolated into shell or PowerShell. Pass them as
   argv lists or base64 JSON. `subprocess` always gets an argv list and a
   timeout.
4. **Keep the comments that explain why.** Most modules carry reasoning about
   false positives and edge cases ("the first live run produced 1500 findings
   for wslhost.exe…"). Move those comments with their code. Never delete them
   as "noise".
5. **Stdlib-only runtime.** Don't add runtime dependencies. Dev-only tooling
   (ruff, import-linter) is fine if configured to be optional.
6. **Small, reversible steps.** Each commit is one kind of change: *move*,
   *rename*, *extract*, *simplify*, or *optimize*, never a mix. A move commit
   changes no logic, so `git diff -M` shows pure renames plus import edits.
7. **Green at every commit.** Run `python3 -m unittest discover -s tests` (pytest
   isn't installed). Any failure blocks the next step. Don't edit a test's
   expectations unless the test pinned a private path that moved; say so in the
   commit.

## Phase 0: Safety baseline (do first, then stop)

- Run `git status`. The tree has a large amount of uncommitted work. **Don't
  stash, reset, or discard any of it.** Ask the user whether to commit it as a
  baseline or branch first. Do all restructuring on a branch
  (`restructure/<date>`).
- Record the baseline: test count and pass state, `python3 -m compileall -q
  jarvis`, and `python3 -m jarvis --help` plus `--help` for every subcommand
  (save the outputs to the scratchpad).
- Build a **golden finding snapshot**: for each collector, run its pure
  rule/analysis functions over the fixtures the tests already use (and any
  captured sample inputs), and serialize the sorted
  `(category, severity, title, host)` tuples. Re-run and diff after every
  phase. Where no fixture exists for an important collector, add a
  characterization test *before* moving it.
- Report the baseline and stop.

## Phase 1: Map (read-only, then stop for approval)

Produce `docs/architecture/CURRENT.md` containing:

- **Inventory.** Every module in `jarvis/` (about 49 flat modules plus the
  subpackages) with lines of code, a one-line responsibility, its layer (see
  the target below), and who calls it (CLI, server, scheduler, other modules,
  scripts).
- **Import graph.** Real edges, including cycles. Call out the known smells:
  - About 44 imports of **private** names across modules (e.g.
    `from .control import _ps_json` in `hunt.py` and `remediation.py`). Each
    one marks a missing public API in the wrong place.
  - About 54 **function-local imports**. Classify each: breaks a cycle, avoids
    startup cost, or is just habit.
  - Collectors importing other collectors.
- **Duplication.** Repeated helpers: `_finding` factories, `_aslist`,
  path normalizers, PowerShell runners, severity ordering, dpkg lookups.
- **Dead or legacy code.** Candidates only (e.g. the `cli_legacy` rename). Grep
  `*.ps1 *.sh systemd/ jarvis/static/ windows-sensor/ tests/ *.md` before
  calling anything dead.
- **Root clutter.** About 22 top-level `*.ps1`/`*.sh` scripts and about 10 dated
  or topical `*.md` reports. For each, record who invokes it (docs, other
  scripts, systemd, the user by hand).
- **Hot paths.** How a scan cycle runs: which collectors run on what schedule,
  and how many subprocess/PowerShell calls and SQL queries each makes.

Then write `docs/architecture/TARGET.md`: the proposed layout, dependency
rules, and an ordered migration plan of small steps, each with risk and
verification. **Stop and wait for approval.**

## Target architecture (starting proposal; refine it from the map)

```
jarvis/
  core/          store, migrations, config, util, collection (observation
                 accounting), finding model, severity, time. Imports nothing
                 above it.
  platform/
    linux/       procfs/ss/journal/dpkg/auditd access
    windows/     the ONE PowerShell/interop runner (public API), win/*.ps1
                 payloads, bridge availability
  collectors/    one package per domain, each exposing collect(store, conf)
    network/     firewall, netwatch, internetwatch, connectivity, sniffing
    persistence/ asep, startup, control, controlwatch, implant, backdoor
    execution/   sysmon, sysmon_linux, auditd, detect, memscan, hidden, evasion
    identity/    bruteforce, secrets, impersonation
    threat_intel/ feeds, intel, hunt, vet
    host/        posture, resourcewatch, spyware, inputwatch, webshell,
                 intrusion, toolchain, protection
  response/      alert, remediation, repair, fixit, ledger, retention, deadman
  reporting/     digest/advisory rendering, evidence, pixel/flash
  service/       monitor loop, scheduler, sdnotify, selfcheck, coverage
  interfaces/
    cli/         parser + commands (thin: parse → call → render)
    web/         server + static
scripts/
  install/  harden/  repair/  windows/   (root keeps only install.sh,
                                          quickstart.sh, quickstart.ps1)
deploy/systemd/  deploy/sysmon/  windows-sensor/
docs/  architecture/  guides/ (QUICKSTART, CONNECTIVITY…)  reports/ (dated reviews)
tests/  mirroring the package tree, plus tests/golden/
```

**Dependency rules** (enforce with an import-linter contract or a small
`tests/test_layers.py` that walks the AST):

- `core` ← `platform` ← `collectors` ← `response`/`reporting` ← `service` ←
  `interfaces`. Arrows point at what may be imported. Nothing imports upward.
- Collectors never import each other. Shared logic moves down into `core` or
  `platform`.
- Nothing imports a leading-underscore name from another module. Promote it to
  a public function in the right layer instead.
- One finding contract: a `Finding` TypedDict or frozen dataclass with a
  `to_dict()` that produces exactly today's dict, and one `finding()` factory
  in place of the per-module `_finding` copies.
- One collector contract: `collect(store, conf) -> list[Finding]`, registered
  in a single registry the scheduler, CLI and coverage all read, replacing
  scattered job lists.

**Moving modules safely:** update every reference (Python imports, `python -m
jarvis.x` in systemd/scripts/docs, `Path(__file__)` lookups such as
`win/*.ps1`, static asset paths, test patches like
`mock.patch('jarvis.hunt._active')`). Leave a re-export shim at the old import
path only if something outside the repo uses it. Otherwise don't leave one.
Shims get a `# TODO(remove after <date>)` comment.

## Code quality standard (applied module by module, after the moves)

- **Sections.** Each module reads top-down: docstring (what it answers and
  why), constants and tuned lists, pure rule functions, I/O and collection,
  then the public entry point. Mark sections with short comment headers when a
  module exceeds about 200 lines.
- **Size.** Soft cap of about 400 lines per module and about 60 per function.
  Split along responsibilities (parsing / rules / I/O), not arbitrarily.
- **Purity.** Rule logic takes parsed data and returns findings, with no
  subprocess, file, or DB access inside. This is what makes golden tests
  possible.
- **Boundaries.** Type hints on public functions and on the finding/collector
  contracts. Internals can stay unannotated.
- **Errors.** No bare `except:`. Catch narrowly. A collector that can't observe
  reports that through `collection.failed(...)` and never returns an empty
  "all clear".
- **Naming.** Modules are nouns for domains, and functions are verbs.
  `check_*` returns findings, `collect_*` gathers raw state, and `parse_*` is
  pure.
- **Consistency.** Pick one quote style and formatting via ruff config
  (`pyproject.toml`). Apply formatting in its own commit per package, never
  mixed with logic changes.

## Phase: Optimize (measure, change, measure)

- Profile one full scan cycle (`cProfile` plus wall-clock per collector). Count
  subprocess and PowerShell launches and SQL statements per cycle.
- Likely wins, all of which need numbers first: batch PowerShell calls
  (process startup costs about 300–800 ms each), cache dpkg ownership per cycle,
  add SQLite indexes for hot `WHERE` clauses (check with `EXPLAIN QUERY PLAN`),
  avoid re-reading unchanged logs, and bucket indicator lookups.
- Report before/after for every optimization. Revert anything that doesn't
  measurably help or that changes the golden snapshot.

## Verification after every phase

1. Full unittest suite passes, and the count is at least the baseline.
2. The golden finding snapshot is byte-identical.
3. `compileall` passes, and every CLI `--help` output matches the baseline
   except for intended help-text improvements.
4. The layer test passes (once it exists).
5. `grep -rn` for every moved module name across `*.ps1 *.sh systemd/ docs/
   jarvis/static/` finds no stale references.
6. `systemd-analyze verify` on the unit files, if they changed.

## How to work

- Use a todo list per phase. Commit after each green step with a message that
  names the kind of change (`move:`, `extract:`, `simplify:`, `perf:`,
  `docs:`).
- If a step would change behavior, stop and ask, stating exactly what would
  change.
- Don't expand scope. A detection bug found along the way gets noted in
  `docs/architecture/FOLLOWUPS.md` and is not fixed inside a refactor commit.
- End each phase with a short report: what moved, what got simpler (lines
  removed, cycles removed, private cross-imports remaining), verification
  results, and the next step.
