"""`jarvis fix` — human-in-the-loop self-fix: JARVIS asks, you decide.

    jarvis fix                    proposals waiting on you
    jarvis fix list [--all]       open proposals (or every recent one)
    jarvis fix show <id>          full proposal: problem, evidence, patch draft
    jarvis fix propose --title T --problem P
                                  file a proposal yourself
    jarvis fix approve <id>       approve Ollama directive + OpenCode drafting
    jarvis fix judge <id>         advisory Jev assessment (records opinion only)
    jarvis fix draft <id>         retry a failed approved drafting run
    jarvis fix authorize <id>     separately authorize the reviewed patch
    jarvis fix reject <id>        reject with an optional reason
    jarvis fix apply <id>         apply the approved patch, test-gated, reverting
                                  on failure
    jarvis fix rollback <id>      reverse an applied patch and retest
    jarvis fix email <id>         re-send the proposal email (rate-limited)
    jarvis fix check              run the daemon-side scan now and mail anything new

Only this command — run by you at a terminal — may invoke opencode or apply
a patch. The scheduler never calls anything here. Approval by email reply is
impossible by construction: no inbound mail path exists, and `approve` takes
only an explicit proposal id from your shell (or the equivalent click on the
local dashboard, which is the same explicit act through the same-origin gate).
"""

import hashlib
import json
import re
import shutil
import subprocess
import time

from jarvis.core.util import iso
from jarvis.response import alert, fixdraft, selffix

from ..output import color, is_tty

PID_RE = re.compile(r"^fx-[0-9a-f]{8}$")

# `git apply` first, tests after. The default is the same suite AGENTS.md
# requires for any change; callers (and tests) may pass a smaller command.
DEFAULT_TEST_CMD = ["python3", "-m", "unittest", "discover", "-s", "tests"]

APPLY_TIMEOUT = 900


def _valid_pid(pid):
    return bool(pid and PID_RE.match(pid))


def _print_proposal(entry, full=False):
    t = is_tty()
    print(color(f"{entry['id']}  [{entry['status']}]  {entry.get('title', '')}",
                "bold", t))
    print(f"  problem: {entry.get('problem', '')}")
    for line in entry.get("evidence", []):
        print(f"  evidence: {line}")
    if entry.get("suggested"):
        print(f"  next: {entry['suggested']}")
    if full:
        print(f"  risk: {entry.get('risk', '')}")
        print(f"  rollback: {entry.get('rollback', '')}")
        print(f"  verify: {', '.join(entry.get('verify', []))}")
        print(f"  generation: {entry.get('generation_state', 'not started')}")
        if entry.get("generation_error"):
            print(f"  generation error: {entry['generation_error']}")
        if entry.get("directive"):
            print("  --- validated Ollama directive (untrusted context) ---")
            print("  " + json.dumps(
                entry["directive"], indent=2, sort_keys=True).replace("\n", "\n  ")[:8000])
        if entry.get("patch_draft"):
            print("  --- patch draft (not applied) ---")
            print("  " + entry["patch_draft"].replace("\n", "\n  ")[:4000])
        if entry.get("jev") or entry.get("jev_validation"):
            print("  --- Jev assessment (advisory only) ---")
            print("  " + json.dumps(entry.get("jev") or entry.get("jev_validation"),
                                    indent=2, sort_keys=True).replace("\n", "\n  ")[:2000])
        if entry.get("apply_log"):
            print("  --- apply log ---")
            print("  " + entry["apply_log"].replace("\n", "\n  ")[-2000:])
        if entry.get("decision_history"):
            print("  --- decision history ---")
            for event in entry["decision_history"][-12:]:
                print(f"  {iso(event.get('at', 0))} {event.get('event')} "
                      f"by {event.get('by')}: {event.get('detail', '')}")
    print(f"  created {iso(entry.get('created_at', 0))}"
          + (f" · emailed {iso(entry['emailed_at'])}" if entry.get("emailed_at") else ""))


def cmd_fix(args, store):
    action = args.action
    if action in (None, "list"):
        entries = list(selffix.list_open(store)) if not args.all else \
            sorted(selffix._load(store).values(), key=lambda e: e.get("created_at", 0),
                   reverse=True)[:20]
        if not entries:
            print("no fix proposals waiting on you.")
            return 0
        for entry in entries:
            _print_proposal(entry)
            print(f"    decide: jarvis fix approve {entry['id']}  |  "
                  f"jarvis fix reject {entry['id']}  |  jarvis fix show {entry['id']}")
        return 0

    if action == "show":
        if not _valid_pid(args.id):
            print(f"no proposal {args.id}")
            return 1
        entry = selffix.get(store, args.id)
        if entry is None:
            print(f"no proposal {args.id}")
            return 1
        _print_proposal(entry, full=True)
        return 0

    if action == "propose":
        if not args.title or not args.problem:
            print("give both --title and --problem")
            return 1
        entry, created = selffix.propose(
            store, f"manual-{int(time.time())}", args.title, args.problem,
            evidence=[args.evidence] if args.evidence else [],
            suggested=args.suggested)
        print(f"{'proposed' if created else 'already open'} {entry['id']}: {entry['title']}")
        return 0

    if action == "approve":
        if not _valid_pid(args.id):
            print(f"no proposal {args.id}")
            return 1
        ok, message = selffix.approve(store, args.id)
        print(message)
        if not ok:
            return 1
        ok, message = fixdraft.generate(store, args.id)
        print(message)
        return 0 if ok else 1

    if action == "authorize":
        if not _valid_pid(args.id):
            print(f"no proposal {args.id}")
            return 1
        ok, message = selffix.authorize_apply(store, args.id)
        print(message)
        return 0 if ok else 1

    if action == "reject":
        if not _valid_pid(args.id):
            print(f"no proposal {args.id}")
            return 1
        ok, message = selffix.reject(store, args.id, args.reason)
        print(message)
        return 0 if ok else 1

    if action == "draft":
        return _draft(args, store)

    if action == "judge":
        return _judge(args, store)

    if action == "apply":
        return _apply(args, store)

    if action == "rollback":
        return _rollback(args, store)

    if action == "email":
        if not _valid_pid(args.id):
            print(f"no proposal {args.id}")
            return 1
        err = selffix.send_email_for(store, alert.load_conf(), args.id)
        print(f"not sent: {err}" if err else f"sent proposal {args.id}")
        return 0 if not err else 1

    if action == "check":
        from jarvis.service.schedule import JOBS
        result = selffix.maintain(store.path, store.get_snapshots(), JOBS)
        print(f"scan complete: created {result['created'] or 'nothing'}; "
              f"mailed {result['mailed'] or 'nothing'}")
        return 0

    print(f"unknown fix action {action}")
    return 1


def _judge(args, store):
    """Run advisory Jev judgments over a proposal and persist them.

    Human gates are untouched: this records an opinion for review, it
    authorizes nothing and changes no status.
    """
    from jarvis.response import jev as jev_mod
    if not _valid_pid(args.id):
        print(f"no proposal {args.id}")
        return 1
    if not jev_mod.available():
        print("TYPESAFE_API_KEY is not configured — nothing to judge with.")
        return 1
    entry = selffix.get(store, args.id)
    if entry is None:
        print(f"no proposal {args.id}")
        return 1
    from jarvis.response import cascade as cascade_mod
    if not jev_mod.available():
        # Without Jev the cascade still runs its local leg; a missing key
        # only removes the escalation path, never the command.
        print("note: TYPESAFE_API_KEY not configured — local model only.")
    entry = selffix.get(store, args.id)
    if entry is None:
        print(f"no proposal {args.id}")
        return 1
    started = time.time()
    result = {"at": int(started), "route": "cascade",
              "proposal": cascade_mod.judge_proposal(entry, alert.load_conf())}
    if (entry.get("patch_draft") or "").strip():
        result["validation"] = cascade_mod.validate_patch(entry, alert.load_conf())
    result["latency_s"] = round(time.time() - started, 2)
    proposals = selffix._load(store)
    item = proposals.get(args.id)
    if item is None:
        print(f"no proposal {args.id}")
        return 1
    item["jev"] = result
    item["updated_at"] = int(time.time())
    selffix._history(item, "jev_assessed", "operator",
                     f"proposal={result['proposal'].get('route', '?')}:"
                     f"{result['proposal'].get('recommendation', '?')}"
                     + (f"; validation={result['validation'].get('route', '?')}:"
                        f"{result['validation'].get('recommendation', '?')}"
                        if "validation" in result else ""))
    selffix._save(store, proposals)
    print(f"Cascade assessment recorded for {args.id} "
          f"({result.get('latency_s', '?')}s, advisory only — no status changed).")
    print(json.dumps(result, indent=2, sort_keys=True)[:3000])
    return 0


def _draft(args, store):
    """Retry the approved, bounded Ollama-to-OpenCode drafting pipeline."""
    if not _valid_pid(args.id):
        print(f"no proposal {args.id}")
        return 1
    entry = selffix.get(store, args.id)
    if entry is None:
        print(f"no proposal {args.id}")
        return 1
    if entry.get("status") not in ("approved", "draft_failed"):
        print(f"{args.id} is {entry.get('status')}; approve investigation first")
        return 1
    ok, message = fixdraft.generate(store, args.id)
    print(message)
    return 0 if ok else 1


def _git_status():
    try:
        proc = subprocess.run(["git", "status", "--porcelain"],
                              capture_output=True, text=True, errors="replace",
                              timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def _apply(args, store, test_cmd=None):
    """Apply an approved patch: snapshot, patch, test, revert on failure.

    Preconditions (all must hold or nothing happens): proposal approved,
    patch draft present, inside a git checkout, tree clean. On test failure
    every touched file is restored and new files removed, and the proposal is
    marked failed with the log tail.
    """
    pid = args.id
    if not _valid_pid(pid):
        print(f"no proposal {pid}")
        return 1
    entry = selffix.get(store, pid)
    if entry is None:
        print(f"no proposal {pid}")
        return 1
    if entry.get("status") != "apply_approved":
        print(f"{pid} is {entry.get('status')}: review and separately authorize it "
              f"(`jarvis fix authorize {pid}`)")
        return 1
    patch = entry.get("patch_draft", "")
    if not patch.strip():
        print(f"{pid} has no patch draft yet (`jarvis fix draft {pid}`)")
        return 1
    expected_hash = entry.get("apply_patch_sha256", "")
    actual_hash = hashlib.sha256(patch.encode("utf-8", "replace")).hexdigest()
    if not expected_hash or expected_hash != actual_hash:
        print("stored patch changed after authorization — refusing; review and "
              f"authorize it again (`jarvis fix authorize {pid}`)")
        return 1
    if not shutil.which("git"):
        print("git not found — cannot apply safely.")
        return 1
    before = _git_status()
    if before is None:
        print("not in a git checkout — refusing to apply.")
        return 1
    if before.strip():
        print("working tree is dirty — commit or stash first; refusing to apply.")
        return 1
    base = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                          capture_output=True, text=True, errors="replace",
                          timeout=30)
    base_commit = base.stdout.strip() if base.returncode == 0 else ""
    check = subprocess.run(["git", "apply", "--check", "-"], input=patch,
                           capture_output=True, text=True, errors="replace",
                           timeout=60)
    if check.returncode != 0:
        print(f"patch does not apply cleanly:\n{check.stderr.strip()[:1000]}")
        return 1
    applied = subprocess.run(["git", "apply", "-"], input=patch,
                             capture_output=True, text=True, errors="replace",
                             timeout=60)
    if applied.returncode != 0:
        print(f"git apply failed:\n{applied.stderr.strip()[:1000]}")
        return 1
    touched = _touched_files(before)
    cmd = test_cmd or (args.test_cmd.split() if getattr(args, "test_cmd", "") else None) \
        or DEFAULT_TEST_CMD
    print(f"patch applied at {base_commit or '?'}; running: {' '.join(cmd)}")
    try:
        test = subprocess.run(cmd, capture_output=True, text=True,
                              errors="replace", timeout=APPLY_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        _revert(before)
        _record(store, pid, "failed", f"test runner failed to start: {exc}")
        print(f"could not run tests ({exc}) — patch reverted.")
        return 1
    log_tail = ((test.stdout or "") + "\n" + (test.stderr or "")).strip()[-3000:]
    if test.returncode != 0:
        _revert(before)
        _record(store, pid, "failed",
                f"tests failed at {base_commit}; patch reverted.\n{log_tail}")
        print("tests FAILED — patch reverted, proposal marked failed.")
        print(log_tail[-1500:])
        return 1
    _record(store, pid, "applied",
            f"applied at {base_commit}; tests passed.\n{log_tail}",
            base_commit=base_commit, touched=touched)
    print(f"applied {pid} at {base_commit or '?'} — tests passed.")
    print(f"touched: {', '.join(touched) or 'none tracked'}")
    print("verify fresh evidence next:")
    print("  jarvis coverage -v            # collectors whose errors this was meant to fix")
    print("  curl -s http://127.0.0.1:8787/api/health | head -c 600")
    print(f"  rollback retained: jarvis fix rollback {pid}  (reverse-applies the stored patch)")
    return 0


def _touched_files(before):
    after = _git_status() or ""
    return [line for line in after.splitlines()
            if line.strip() and line not in (before or "").splitlines()][:50]


def _rollback(args, store, test_cmd=None):
    """Reverse the exact recorded applied patch, restoring it if tests fail."""
    pid = args.id
    entry = selffix.get(store, pid) if _valid_pid(pid) else None
    if entry is None:
        print(f"no proposal {pid}")
        return 1
    if entry.get("status") != "applied":
        print(f"{pid} is {entry.get('status')}; only an applied patch can be rolled back")
        return 1
    patch = entry.get("patch_draft", "")
    expected = entry.get("apply_patch_sha256", "")
    if not patch or hashlib.sha256(patch.encode("utf-8", "replace")).hexdigest() != expected:
        print("stored rollback patch is missing or no longer matches its authorization hash")
        return 1
    before = _git_status()
    expected_paths = set(entry.get("applied_paths") or _patch_paths(patch))
    dirty_paths = {line[3:].strip().split(" -> ")[-1]
                   for line in (before or "").splitlines() if len(line) > 3}
    if before is None or not dirty_paths or not dirty_paths.issubset(expected_paths):
        print("working tree does not contain only this applied patch — refusing rollback")
        return 1
    check = subprocess.run(["git", "apply", "--reverse", "--check", "-"], input=patch,
                           capture_output=True, text=True, errors="replace", timeout=60)
    if check.returncode != 0:
        print(f"patch cannot be reversed cleanly:\n{check.stderr.strip()[:1000]}")
        return 1
    reversed_patch = subprocess.run(["git", "apply", "--reverse", "-"], input=patch,
                                    capture_output=True, text=True, errors="replace", timeout=60)
    if reversed_patch.returncode != 0:
        print(f"rollback failed:\n{reversed_patch.stderr.strip()[:1000]}")
        return 1
    cmd = test_cmd or (args.test_cmd.split() if getattr(args, "test_cmd", "") else None) \
        or DEFAULT_TEST_CMD
    try:
        test = subprocess.run(cmd, capture_output=True, text=True,
                              errors="replace", timeout=APPLY_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        test = None
        failure = f"rollback test runner failed: {exc}"
    else:
        failure = "" if test.returncode == 0 else (
            "rollback tests failed:\n" + ((test.stdout or "") + "\n" +
                                           (test.stderr or ""))[-3000:])
    if failure:
        restored = subprocess.run(["git", "apply", "-"], input=patch,
                                  capture_output=True, text=True, errors="replace", timeout=60)
        log = failure + ("\noriginal applied state restored" if restored.returncode == 0
                         else "\nCRITICAL: could not restore original applied state")
        proposals = selffix._load(store)
        item = proposals[pid]
        item["apply_log"] = log[:4000]
        selffix._history(item, "rollback_failed", "operator", log[:1000])
        selffix._save(store, proposals)
        print(log)
        return 1
    proposals = selffix._load(store)
    item = proposals[pid]
    item["status"] = "rolled_back"
    item["updated_at"] = int(time.time())
    item["apply_log"] = "rollback applied; verification tests passed"
    selffix._history(item, "rolled_back", "operator", "reverse patch and tests succeeded")
    selffix._save(store, proposals)
    print(f"rolled back {pid}; verification tests passed")
    return 0


def _revert(before):
    """Restore the pre-apply tree: checkout tracked mods, delete new files."""
    before_lines = set((before or "").splitlines())
    after = _git_status() or ""
    new_paths, tracked = [], []
    for line in after.splitlines():
        status, _, path = line[:2], line[2:3], line[3:].strip()
        if not path:
            continue
        if status.strip() == "??" and line not in before_lines:
            new_paths.append(path.split(" -> ")[-1])
        else:
            tracked.append(path.split(" -> ")[-1])
    if tracked:
        subprocess.run(["git", "checkout", "--", *tracked],
                       capture_output=True, timeout=60)
    import os
    for path in new_paths:
        try:
            if os.path.isfile(path) and os.path.exists(path):
                os.unlink(path)
        except OSError:
            pass


def _patch_paths(patch):
    return [match.group(2) for match in re.finditer(
        r"^diff --git a/(.+?) b/(.+?)$", patch, flags=re.MULTILINE)]


def _record(store, pid, status, log, base_commit="", touched=()):
    proposals = selffix._load(store)
    entry = proposals.get(pid)
    if entry is None:
        return
    entry["status"] = status
    entry["updated_at"] = int(time.time())
    entry["apply_log"] = log[:4000]
    if base_commit:
        entry["base_commit"] = base_commit
    if touched:
        entry["applied_paths"] = _patch_paths(entry.get("patch_draft", ""))
    entry.setdefault("test_results", []).append({
        "at": int(time.time()), "status": "passed" if status == "applied" else "failed",
        "detail": log[:4000]})
    del entry["test_results"][:-10]
    selffix._history(entry, "patch_applied" if status == "applied" else "apply_failed",
                     "operator", log[:1000])
    selffix._save(store, proposals)


def add_parser(sub):
    p = sub.add_parser("fix", help="self-fix proposals: JARVIS asks, you decide")
    p.add_argument("action", nargs="?", default=None,
                   choices=["list", "show", "propose", "draft", "judge", "approve", "authorize",
                            "reject", "apply", "rollback", "email", "check"],
                   help="what to do (default: list open proposals)")
    p.add_argument("id", nargs="?", help="proposal id (fx-…)")
    p.add_argument("--all", action="store_true", help="with list: include decided")
    p.add_argument("--title", default="", help="with propose: short title")
    p.add_argument("--problem", default="", help="with propose: the problem")
    p.add_argument("--evidence", default="", help="with propose: one evidence line")
    p.add_argument("--suggested", default="", help="with propose: suggested next step")
    p.add_argument("--reason", default="", help="with reject: why not")
    p.add_argument("--with-model", action="store_true",
                   help="deprecated: approved drafting always requires the local model")
    p.add_argument("--test-cmd", default="",
                   help="with apply: override test command (space-separated)")
    p.set_defaults(fn=cmd_fix)
    return p
