"""Friday Defender reviews: a model-driven security review of the codebases on
this machine, run by the owner's own Friday install, with the owner's consent.

The deterministic scanners (appcode: dependency CVEs, code rules, secrets;
pkgverify, webshell, patches) run on their own schedule. This adds what a
reviewer reading the code finds and rules cannot: logic flaws, missing
authorisation, unsafe trust of input. Friday Defender reviews with Archymedes's
signed, reviewed defensive corpus (its "brain"), which Friday itself replicates
and verifies every 6 hours; this collector reports that feed's state.

How it runs: each scheduler pass collects reviews that have finished and starts
at most one new one, as a detached child with its own deadline (the scheduler
never waits on a model). One codebase at a time, round-robin over the appcode
inventory (or the folders the owner named), each at most once a week.

Invariants (tests/test_fridaydefender.py holds each):
    I1  consent: nothing is installed or reviewed until the owner runs
        `jarvis defender enable` in a terminal and says yes; the daemon only
        reads the consent record, and can only withdraw it
    I2  read-only: Friday runs headless in defender mode, where every change
        needs an approval nobody can give; the folder is fingerprinted before
        and after, and any change is critical and withdraws consent
    I3  advisory: model output never authorises anything; its findings are
        capped at medium and carry their source, and nothing acts on them
    I4  privacy: secret values found in model output are masked before
        anything is stored, the raw transcript is deleted after parsing, and
        the provider that sees the code is the one the owner set in Friday
    I5  bounded: one review at a time, a deadline, a budget, a findings cap
        per codebase, a weekly cadence per codebase, a file-count cap on the
        fingerprint
    I6  honest coverage: a missing Friday, a review that did not finish, or
        output with a sequence gap is reported as not observed, never clean
"""

import glob
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

from jarvis.core.finding import finding as _finding

DIR = os.path.expanduser("~/.jarvis/defender")
CONSENT = os.path.join(DIR, "consent.json")
RUNS = os.path.join(DIR, "runs")
LOCK = os.path.join(DIR, "review.lock")
RESULTS_META = "friday_defender_results_v1"   # {root: {"at", "status", "findings": [...], ...}}
CURSOR_META = "friday_defender_cursor_v1"

REVIEW_EVERY_S = 7 * 24 * 3600
DEADLINE_S = 20 * 60
DEFAULT_BUDGET = "0.50"
MAX_FINDINGS = 20
MAX_ROOTS = 200
MAX_FILES = 50000
MAX_TRANSCRIPT = 8 * 1024 * 1024
FEED_STALE_S = 24 * 3600
SEVERITY_CAP = "medium"
ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
INSTALL = ["npm", "install", "-g", "@archymedes/friday"]

# The one request every review makes. Fixed and reviewable (AGENTS.md: question
# text centralised): it asks for a report, never for changes, and for findings
# in a block this module can parse without trusting anything else in the reply.
PROMPT = (
    "Security review only: do not change, create or delete any file and do not run commands that "
    "modify anything. Review this codebase for exploitable vulnerabilities (injection, missing "
    "authorisation, unsafe deserialisation, path traversal, SSRF, weak crypto, secrets handling, "
    "dangerous defaults). Report only issues you can point to in the code. Never include secret "
    "values. End your reply with the findings as a JSON array between the lines <<<FINDINGS and "
    "FINDINGS>>>, each item {\"title\", \"file\", \"line\", \"severity\" (low|medium|high|critical), "
    "\"why\", \"fix\"}; an empty array if you found nothing."
)
FINDINGS_BLOCK = re.compile(r"<<<FINDINGS\s*(\[.*?\])\s*FINDINGS>>>", re.S)


# ── consent ──────────────────────────────────────────────────────────────

def load_consent(path=None):
    """The owner's consent record, or None. A record that is not owner-only,
    not well formed or withdrawn counts as no consent (I1)."""
    path = path or CONSENT
    try:
        st = os.stat(path)
        if st.st_mode & 0o077 or (hasattr(os, "getuid") and st.st_uid != os.getuid()):
            return None
        with open(path, encoding="utf-8", errors="replace") as fh:
            c = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(c, dict) or c.get("v") != 1 or c.get("revoked") or not c.get("granted_at"):
        return None
    roots = c.get("roots")
    if roots is not None and not (isinstance(roots, list) and all(isinstance(r, str) for r in roots)):
        return None
    return c


def write_consent(record, path=None):
    path = path or CONSENT
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=1)
    os.replace(tmp, path)


def revoke(reason, path=None):
    """The daemon may withdraw consent, never grant it."""
    path = path or CONSENT
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            c = json.load(fh)
    except (OSError, ValueError):
        return
    c.update({"revoked": True, "revoked_at": time.time(), "revoked_reason": reason[:300]})
    write_consent(c, path)


# ── Friday and its signed knowledge feed ─────────────────────────────────

def find_friday():
    """Path of the friday command, or None. The daemon's PATH rarely includes
    nvm, so the usual per-user install places are searched too."""
    found = shutil.which("friday")
    if found:
        return found
    home = os.path.expanduser("~")
    cands = sorted(glob.glob(os.path.join(home, ".nvm/versions/node/*/bin/friday")), reverse=True)
    cands += [os.path.join(home, ".local/bin/friday"), "/usr/local/bin/friday", "/usr/bin/friday"]
    appdata = os.environ.get("APPDATA")
    if appdata:
        cands.append(os.path.join(appdata, "npm", "friday.cmd"))
    return next((c for c in cands if os.path.isfile(c) and os.access(c, os.X_OK)), None)


def friday_provider(config_dir=None):
    """(provider, model) Friday is set to use, or (None, None). Only those two
    names are read from its settings: the same file holds API keys, which
    never leave it (I4)."""
    provider = os.environ.get("ARCHYMEDES_PROVIDER")
    model = None
    path = os.path.join(config_dir or os.path.dirname(feed_dir()), "settings.json")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            settings = json.load(fh)
    except (OSError, ValueError):
        settings = {}
    if isinstance(settings, dict):
        provider = provider or settings.get("ARCHYMEDES_PROVIDER")
        if isinstance(provider, str) and provider:
            model = settings.get(f"{provider.upper().replace('-', '_')}_MODEL")
    return (provider if isinstance(provider, str) else None, model if isinstance(model, str) else None)


def feed_dir():
    """Friday's config folder (archymedesConfigDirectory in @archymedes/core)."""
    if os.environ.get("ARCHYMEDES_CONFIG_DIR"):
        return os.path.join(os.environ["ARCHYMEDES_CONFIG_DIR"], "defender-brain")
    if os.name == "nt":
        return os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~/AppData/Roaming"),
                            "Archymedes", "defender-brain")
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "archymedes", "defender-brain")


def feed_findings(now, directory=None):
    path = os.path.join(directory or feed_dir(), "feed-state.json")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            st = json.load(fh)
    except (OSError, ValueError):
        return [_finding("defender", "low", "Friday Defender knowledge feed not checked yet",
                         "Friday has not replicated Archymedes's signed defensive corpus here; its reviews "
                         "use the corpus bundled with the installed version", path)]
    out = []
    checked = (st.get("lastCheckedAt") or 0) / 1000
    if not st.get("activeDigest") or st.get("sequence") is None:
        out.append(_finding("defender", "low", "no signed Defender feed update is active",
                            "the signed corpus has never validated and activated here, so reviews use the "
                            "corpus bundled with Friday (still reviewed, but as old as the install)", path))
    if checked and now - checked > FEED_STALE_S:
        out.append(_finding("defender", "low", "Defender knowledge feed not checked for over a day",
                            f"last check {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(checked))}; Friday "
                            "checks every 6 hours while it runs", path))
    return out


# ── fingerprint, review child, result parsing ────────────────────────────

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "target", "dist", "build", ".next",
             ".archymedes"}


HASH_LIMIT = 1024 * 1024


def fingerprint(root, max_files=MAX_FILES):
    """(digest, files, truncated) over every file under root: content for files
    up to 1 MiB (a write can keep size and mtime; Jev 2026-10-29: 0.80), size and
    mtime above that (I2). Dependency, build and Friday's own folders are left out."""
    h, n, truncated = hashlib.sha256(), 0, False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if n >= max_files:
                truncated = True
                break
            p = os.path.join(dirpath, name)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            h.update(f"{os.path.relpath(p, root)}\0{st.st_size}\0{st.st_mtime_ns}\n".encode("utf-8", "replace"))
            if st.st_size <= HASH_LIMIT and os.path.isfile(p) and not os.path.islink(p):
                try:
                    with open(p, "rb") as fh:
                        h.update(hashlib.sha256(fh.read(HASH_LIMIT + 1)).digest())
                except OSError:
                    h.update(b"unreadable")
            n += 1
        if truncated:
            break
    return h.hexdigest(), n, truncated


def parse_transcript(path, max_bytes=MAX_TRANSCRIPT):
    """(status, summary, problems) from Friday's headless JSONL (protocol v1:
    every line one record, seq strictly increasing from 1)."""
    problems, status, summary, texts, expect = [], "", "", [], 1
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = fh.read(max_bytes + 1)
    except OSError as exc:
        return "", "", [f"transcript unreadable: {exc.strerror or exc}"]
    if len(data) > max_bytes:
        problems.append("transcript larger than the limit; the end was not read")
    for line in data.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            problems.append("a transcript line was not JSON")
            continue
        if rec.get("seq") != expect:
            problems.append(f"transcript sequence gap at {expect} (got {rec.get('seq')}): output was lost")
            expect = (rec.get("seq") or expect) + 1
        else:
            expect += 1
        if rec.get("type") == "text" and isinstance(rec.get("text"), str):
            texts.append(rec["text"])
        elif rec.get("type") == "turn_end":
            status, summary = str(rec.get("status") or ""), str(rec.get("summary") or "")
    if not status:
        problems.append("the review has no end record")
    return status, summary or "".join(texts), problems


def redact(text):
    """Mask anything the secret scanner recognises (I4)."""
    from jarvis.collectors.credentials import PATTERNS
    for _label, rx, _sev in PATTERNS:
        text = rx.sub(lambda m: m.group(0)[:4] + "********", text)
    return text


def parse_findings(summary, root):
    """Validated, capped, redacted findings from the model's block (I3, I4, I5)."""
    m = FINDINGS_BLOCK.search(summary or "")
    if not m:
        return None
    try:
        items = json.loads(m.group(1))
    except ValueError:
        return None
    out = []
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict) or not isinstance(it.get("title"), str):
            continue
        sev = str(it.get("severity", "low")).lower()
        sev = sev if sev in ORDER else "low"
        capped = sev if ORDER[sev] <= ORDER[SEVERITY_CAP] else SEVERITY_CAP
        rel = str(it.get("file") or "")[:300]
        if rel.startswith("/"):
            rel = os.path.relpath(rel, root) if rel.startswith(root) else rel
        line = it.get("line") if isinstance(it.get("line"), int) else None
        out.append({"title": redact(it["title"][:160]), "file": redact(rel), "line": line,
                    "model_severity": sev, "severity": capped,
                    "why": redact(str(it.get("why") or "")[:500]), "fix": redact(str(it.get("fix") or "")[:300])})
        if len(out) >= MAX_FINDINGS:
            break
    return out


def review(root, friday, budget, out_dir=None, deadline=DEADLINE_S):
    """The detached child: run one review, write <id>.result.json atomically,
    delete the raw transcript. Never raises."""
    out_dir = out_dir or RUNS
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    rid = hashlib.sha256(f"{root}{time.time()}".encode()).hexdigest()[:12]
    transcript = os.path.join(out_dir, f"{rid}.jsonl")
    before = fingerprint(root)
    started = time.time()
    exit_code, timed_out = None, False
    try:
        with open(transcript, "wb") as fh:
            p = subprocess.Popen([friday, "--json", "--defender", "--budget", str(budget), "-C", root, PROMPT],
                                 stdout=fh, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, cwd=root,
                                 env={**os.environ, "NO_COLOR": "1"}, start_new_session=True)
            try:
                exit_code = p.wait(timeout=deadline)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except (OSError, AttributeError):
                    p.kill()
                p.wait()
    except OSError as exc:
        _write_result(out_dir, rid, {"root": root, "started": started, "ended": time.time(),
                                     "error": f"friday could not start: {exc.strerror or exc}"})
        return
    after = fingerprint(root)
    status, summary, problems = parse_transcript(transcript)
    findings = parse_findings(summary, root)
    if findings is None and status == "completed":
        problems.append("the review ended without a findings block")
    try:
        os.remove(transcript)                    # I4: the transcript may quote code
    except OSError:
        pass
    _write_result(out_dir, rid, {
        "root": root, "started": started, "ended": time.time(), "exit": exit_code, "timed_out": timed_out,
        "status": status, "changed": before[0] != after[0], "files": after[1],
        "fingerprint_truncated": before[2] or after[2], "problems": problems[:10],
        "findings": findings or []})


def _write_result(out_dir, rid, result):
    tmp = os.path.join(out_dir, f"{rid}.result.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(result, fh)
    os.replace(tmp, os.path.join(out_dir, f"{rid}.result.json"))


# ── the scheduled job ────────────────────────────────────────────────────

def _running(lock=None):
    lock = lock or LOCK
    try:
        with open(lock, encoding="utf-8", errors="replace") as fh:
            pid = int(fh.read().split()[0])
        os.kill(pid, 0) if os.name != "nt" else None
        return True
    except (OSError, ValueError, IndexError):
        return False


def candidate_roots(consent):
    if consent.get("roots"):
        return [r for r in consent["roots"] if os.path.isdir(r)][:MAX_ROOTS]
    from jarvis.core import osvindex
    inv = osvindex.load(osvindex.inventory_path()) or {}
    roots = sorted({p.get("project") for p in inv.get("packages", []) if isinstance(p, dict) and p.get("project")})
    return [r for r in roots if os.path.isdir(r)][:MAX_ROOTS]


def start_review(root, friday, budget, spawn=subprocess.Popen):
    os.makedirs(RUNS, mode=0o700, exist_ok=True)
    from jarvis.core.paths import self_executable
    child = spawn([self_executable(), "-m", "jarvis.collectors.host.fridaydefender", "review", root, friday,
                   str(budget)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL, start_new_session=True)
    with open(LOCK, "w", encoding="utf-8") as fh:
        fh.write(f"{child.pid} {root} {time.time()}\n")
    return child.pid


def collect(store, now, runs=None):
    """Fold finished results into the store; returns findings from changed
    folders (I2) and start errors."""
    runs = runs or RUNS
    try:
        results = json.loads(store.get_meta(RESULTS_META, "") or "{}")
    except (ValueError, TypeError):
        results = {}
    alarms = []
    for path in sorted(glob.glob(os.path.join(runs, "*.result.json"))):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                r = json.load(fh)
        except (OSError, ValueError):
            continue
        root = r.get("root") or "?"
        results[root] = {**r, "at": r.get("ended") or now}
        if r.get("changed"):
            revoke(f"a review changed files under {root}")
            alarms.append(_finding("defender", "critical", f"Friday Defender changed files in {root}",
                                   "a review must leave the folder untouched; files under it changed while it "
                                   "ran. Consent is withdrawn until you check the folder and run "
                                   "`jarvis defender enable` again", root))
        try:
            os.remove(path)
        except OSError:
            pass
    if len(results) > MAX_ROOTS:
        results = dict(sorted(results.items(), key=lambda kv: kv[1].get("at", 0))[-MAX_ROOTS:])
    store.set_meta(RESULTS_META, json.dumps(results))
    return results, alarms


def result_findings(results):
    out = []
    for root, r in sorted(results.items()):
        when = time.strftime("%Y-%m-%d", time.gmtime(r.get("at", 0)))
        if r.get("error") or r.get("timed_out") or r.get("problems") or r.get("status") not in ("completed",):
            why = r.get("error") or ("ran past its deadline" if r.get("timed_out") else
                                     "; ".join(r.get("problems") or []) or f"ended {r.get('status') or 'without status'}")
            out.append(_finding("visibility", "low", f"Friday Defender review of {os.path.basename(root)} incomplete",
                                f"{why} ({when}); what it found before stopping is listed, the rest is unknown",
                                root))
        for f in r.get("findings") or []:
            where = f"{root}/{f['file']}" + (f":{f['line']}" if f.get("line") else "")
            out.append(_finding("defender", f["severity"], f"Defender review: {f['title']}",
                                f"{f['why']} Fix: {f['fix']} (model said {f['model_severity']}; advisory, from "
                                f"Friday Defender on {when})", where))
    return out


def audit(store, hosts=None, now=None, spawn=subprocess.Popen):
    now = time.time() if now is None else now
    out = []
    friday = find_friday()
    consent = load_consent()
    if consent is None:
        how = ("Friday is installed" if friday else "Friday is not installed; enabling offers to install it")
        out.append(_finding("defender", "low", "Friday Defender reviews are off",
                            f"Argus can have Friday Defender review your codebases for vulnerabilities, with "
                            f"your consent. {how}. Run `jarvis defender enable` in a terminal to choose.",
                            "jarvis defender enable"))
        return out + (feed_findings(now) if friday else [])
    if not friday:
        out.append(_finding("visibility", "medium", "Friday Defender consented but Friday is missing",
                            "reviews cannot run; reinstall with `jarvis defender enable`", "friday"))
        return out
    # Consent covers the provider the owner saw when agreeing (Jev 2026-10-29:
    # 0.20 that one yes covers any provider). A change pauses reviews.
    provider, model = friday_provider()
    if (provider, model) != (consent.get("provider"), consent.get("model")):
        out.append(_finding("defender", "medium", "Friday Defender reviews paused: Friday's model changed",
                            f"you agreed to send code to {consent.get('provider')}/{consent.get('model')}; Friday "
                            f"is now set to {provider}/{model}. Run `jarvis defender enable` to confirm the new "
                            "provider", "jarvis defender enable"))
        results, alarms = collect(store, now)
        return out + alarms + result_findings(results)
    results, alarms = collect(store, now)
    out += alarms + result_findings(results) + feed_findings(now)
    if alarms or load_consent() is None or _running():
        return out
    roots = candidate_roots(consent)
    if not roots:
        out.append(_finding("visibility", "low", "no codebases to review",
                            "the appcode inventory is empty and no folders were named", "friday"))
        return out
    try:
        cursor = int(store.get_meta(CURSOR_META, "0") or 0)
    except ValueError:
        cursor = 0
    for i in range(len(roots)):
        root = roots[(cursor + i) % len(roots)]
        if now - (results.get(root) or {}).get("at", 0) >= REVIEW_EVERY_S:
            start_review(root, friday, consent.get("budget") or DEFAULT_BUDGET, spawn)
            store.set_meta(CURSOR_META, str((cursor + i + 1) % len(roots)))
            break
    return out


if __name__ == "__main__" and len(sys.argv) == 5 and sys.argv[1] == "review":
    try:
        review(sys.argv[2], sys.argv[3], sys.argv[4])
    finally:
        try:
            os.remove(LOCK)
        except OSError:
            pass
