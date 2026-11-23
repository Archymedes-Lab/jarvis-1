"""Security Autopilot: investigate findings, group them, recover collectors, ask only when needed.

One persistent state machine (tables `investigations`, `investigation_events`,
`autopilot_decisions`, `recovery` in core/schema.py) over the findings the
scheduler already stores as snapshots. It reads; it never changes the computer.

What runs by itself: read-only evidence collection, correlation, investigation,
re-checks, collector retries, reports, remediation *proposals*.
What never runs by itself: deletion, quarantine, process kill, firewall,
account, credential or registry changes. Those need `authorize()` for the exact
finding, and this module has no code that performs them; ACTION_APPLIED is only
recorded by the existing remediation path through `mark_applied()`.

Invariants:
  * A failed investigation is FAILED, never INVESTIGATED.
  * Grouping never uses the title alone, never drops a member's evidence or
    severity, and a decision covers exactly the findings it listed, at the
    evidence they had then. New or changed evidence re-opens the question.
  * Deterministic analysis is complete without a model; the model only adds an
    optional plain-language note and its absence changes no state.
  * A collector is healthy only when detectorhealth says so (fresh, valid).
"""

import hashlib
import json
import os
import random
import re
import time

from jarvis.response import acknowledge, alert
from jarvis.response.reporting import triage
from jarvis.service import detectorhealth

NEW, QUEUED, INVESTIGATING, INVESTIGATED = "NEW", "QUEUED", "INVESTIGATING", "INVESTIGATED"
NEEDS_USER, PROPOSED, AUTHORIZED = "NEEDS_USER_DECISION", "ACTION_PROPOSED", "ACTION_AUTHORIZED"
APPLIED, VERIFIED, FAILED, INSUFFICIENT = "ACTION_APPLIED", "VERIFIED", "FAILED", "INSUFFICIENT_EVIDENCE"

TRANSITIONS = {
    NEW: {QUEUED},
    QUEUED: {INVESTIGATING},
    INVESTIGATING: {INVESTIGATED, NEEDS_USER, INSUFFICIENT, FAILED, QUEUED},
    INVESTIGATED: {QUEUED, NEEDS_USER},
    NEEDS_USER: {INVESTIGATED, PROPOSED, QUEUED},
    PROPOSED: {AUTHORIZED, INVESTIGATED, QUEUED},
    AUTHORIZED: {APPLIED, PROPOSED},
    APPLIED: {VERIFIED, FAILED},
    VERIFIED: {QUEUED},
    FAILED: {QUEUED},
    INSUFFICIENT: {QUEUED},
}

# Collector-health and upkeep categories: a monitoring problem, not a security finding.
MONITORING_CATEGORIES = frozenset({"visibility", "limits", "intel", "feed", "telemetry",
                                   "auditd", "reporting", "model", "daemon", "collectors"})

REFRESH_S = 24 * 3600            # re-investigate unchanged findings at most daily
STALE_RUN_S = 180                # an INVESTIGATING row older than this was cut off by a restart
BATCH = 40                       # investigations per cycle: bounded work
MAX_ATTEMPTS = 4
RETRY_BASE_S, RETRY_CAP_S = 60, 3600
RECOVERY_MAX_RETRIES, RECOVERY_COOLDOWN_S, RECOVERY_PER_CYCLE = 6, 6 * 3600, 3
KEEP_EVENTS, KEEP_RESOLVED_S = 5000, 30 * 86400
CHOICES = ("recognise", "not_recognise", "investigate_further", "review_individually")
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "ok": 5}

_PATH = re.compile(r"""((?:[A-Za-z]:|%\w+%)[\\/][^\s"'<>|]+|/(?:[\w.\-~ ]+/)+[\w.\-~]+)""")


# --- state machine ---------------------------------------------------------

def _move(store, fid, to, reason, now, **fields):
    row = store.db.execute("SELECT state FROM investigations WHERE fid=?", (fid,)).fetchone()
    old = row["state"] if row else ""
    if row and to != old and to not in TRANSITIONS.get(old, ()):
        raise ValueError(f"illegal transition {old} -> {to} for {fid}")
    sets, args = ["state=?", "updated=?"], [to, now]
    for key, value in fields.items():
        sets.append(f"{key}=?")
        args.append(value)
    store.db.execute(f"UPDATE investigations SET {', '.join(sets)} WHERE fid=?", (*args, fid))
    if to != old:
        store.db.execute("INSERT INTO investigation_events(ts,fid,from_state,to_state,reason)"
                         " VALUES(?,?,?,?,?)", (now, fid, old, to, str(reason)[:300]))
    store.db.commit()


def _row(store, fid):
    r = store.db.execute("SELECT * FROM investigations WHERE fid=?", (fid,)).fetchone()
    return dict(r) if r else None


def _report(row):
    try:
        data = json.loads(row.get("report") or "{}")
    except ValueError:
        data = {}
    return data if isinstance(data, dict) else {}


# --- identity, grouping ----------------------------------------------------

def evidence_hash(f):
    basis = "|".join((str(f.get("severity")), alert.stable_text(f.get("detail")),
                      str(f.get("where") or "")))
    return hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:16]


def first_path(*texts):
    for text in texts:
        m = _PATH.search(str(text or ""))
        if m:
            return m.group(1).rstrip(".,;)")
    return ""


def locus_root(path, category=""):
    """The place a tool or application keeps its files: the unit a person thinks in.

    Many files under one tool's temp, cache, scratch or install folder are one
    story; two different tools never share a root. Evidence stays per file."""
    p = path.replace("\\", "/").lower().rstrip("/")
    if category == "firewall" and p.endswith((".exe", ".dll")):
        return p                                    # rules for one program belong together
    parts = p.split("/")
    for i, seg in enumerate(parts):                  # a tool's folder inside the user temp dir
        if seg == "temp" and "appdata" in parts[:i] and i + 1 < len(parts) - 1:
            return "/".join(parts[:i + 2])
    parts = p.split("/")
    for i, seg in enumerate(parts):                  # a tool's folder inside the user temp dir
        if seg == "temp" and "appdata" in parts[:i] and i + 1 < len(parts) - 1:
            return "/".join(parts[:i + 2])
    for marker in ("/node_modules", "/scratchpad", "/.git/", "/site-packages"):
        if marker in p + "/":
            return p[:(p + "/").index(marker)] + (marker.rstrip("/") if marker == "/scratchpad" else "")
    for i, seg in enumerate(parts):
        if seg == "local" and i > 0 and parts[i - 1] == "appdata" and i + 1 < len(parts) - 1:
            take = 3 if parts[i + 1] == "programs" else 2
            return "/".join(parts[:i + take])        # .../appdata/local/<app>
    if len(parts) > 3 and parts[1] == "users" and parts[3].startswith("."):
        return "/".join(parts[:4])                   # c:/users/<u>/.<tool>
    return os.path.dirname(p)


def group_key(f, job):
    """Same job, same category, same place. Never the title alone.

    A finding with no recognisable place is its own group: nothing is merged on a guess."""
    path = first_path(f.get("where"), f.get("detail"))
    if not path:
        return "solo:" + acknowledge.finding_id(f, job)
    return f"{job}|{f.get('category', '')}|{locus_root(path, f.get('category', ''))}"


def current_findings(store):
    """-> {fid: (finding, job)} for every non-ok finding, from stored snapshots."""
    out = {}
    for job, snap in store.get_snapshots().items():
        for f in snap.get("findings") or []:
            # A coverage gap is about Argus's own detection, not this machine:
            # nothing on the host to investigate (ALERT-QUALITY-2026-11-08).
            if (isinstance(f, dict) and f.get("severity") not in (None, "ok")
                    and not alert.is_coverage_gap(f)):
                out[acknowledge.finding_id(f, job)] = (f, job)
    return out


def kind_of(f):
    return "monitoring" if f.get("category") in MONITORING_CATEGORIES else "security"


# --- sync: new / changed / resolved ---------------------------------------

def sync(store, now=None):
    """Enqueue what is new or changed; mark what has gone. Idempotent."""
    now = int(time.time() if now is None else now)
    found = current_findings(store)
    existing = {r["fid"]: dict(r) for r in store.db.execute("SELECT * FROM investigations")}
    queued = 0
    for fid, (f, job) in found.items():
        ev, gk = evidence_hash(f), group_key(f, job)
        row = existing.get(fid)
        if row is None:
            store.db.execute(
                "INSERT INTO investigations(fid,job,severity,category,title,locus,group_key,state,"
                "evidence,first_seen,last_seen,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (fid, job, f.get("severity", ""), f.get("category", ""), f.get("title", "")[:300],
                 str(f.get("where") or "")[:500], gk, NEW, ev, now, now, now))
            store.db.commit()
            _move(store, fid, QUEUED, "new finding", now)
            queued += 1
            continue
        store.db.execute("UPDATE investigations SET last_seen=?, severity=?, group_key=? WHERE fid=?",
                         (now, f.get("severity", ""), gk, fid))
        reason = None
        if row["resolved_at"]:
            reason = "reappeared after being resolved"
            store.db.execute("UPDATE investigations SET resolved_at=0 WHERE fid=?", (fid,))
        elif row["evidence"] != ev:
            reason = "evidence changed"
        elif row["state"] in (INVESTIGATED, INSUFFICIENT) and now - row["updated"] >= REFRESH_S:
            reason = "scheduled refresh"
        elif row["state"] == FAILED and row["next_run"] <= now and row["attempts"] < MAX_ATTEMPTS:
            reason = "retry after failure"
        if reason and row["state"] not in (QUEUED, INVESTIGATING, AUTHORIZED, APPLIED):
            store.db.execute("UPDATE investigations SET evidence=? WHERE fid=?", (ev, fid))
            _move(store, fid, QUEUED, reason, now)
            queued += 1
        elif row["evidence"] != ev:
            store.db.execute("UPDATE investigations SET evidence=? WHERE fid=?", (ev, fid))
    store.db.commit()
    for fid, row in existing.items():
        if fid in found or row["resolved_at"]:
            continue
        if row["state"] == APPLIED:
            _move(store, fid, VERIFIED, "no longer observed after the approved action", now,
                  resolved_at=now)
        else:
            store.db.execute("UPDATE investigations SET resolved_at=?, updated=? WHERE fid=?",
                             (now, now, fid))
            store.db.execute("INSERT INTO investigation_events(ts,fid,from_state,to_state,reason)"
                             " VALUES(?,?,?,?,?)", (now, fid, row["state"], row["state"],
                                                    "no longer observed"))
            store.db.commit()
    return queued


def recover_interrupted(store, now=None):
    """Rows left INVESTIGATING by a restart go back to the queue."""
    now = int(time.time() if now is None else now)
    n = 0
    for r in store.db.execute("SELECT fid FROM investigations WHERE state=? AND updated<?",
                              (INVESTIGATING, now - STALE_RUN_S)).fetchall():
        _move(store, r["fid"], QUEUED, "interrupted by a restart", now)
        n += 1
    return n


# --- the deterministic investigation --------------------------------------

def _facts_about_path(path, now):
    if not path:
        return [], ["No file or folder location was recorded, so nothing could be inspected."]
    known, unknown = [], []
    try:
        st = os.stat(path)
    except OSError:
        unknown.append(f"{path} could not be inspected from here (missing, or not readable).")
        return known, unknown
    kind = "folder" if os.path.isdir(path) else "file"
    age_d = max(0, int((now - st.st_mtime) // 86400))
    known.append(f"The {kind} exists. Last modified {age_d} day(s) ago"
                 + (f"; {st.st_size} bytes." if kind == "file" else "."))
    unknown.append("File contents were not read.")
    return known, unknown


def investigate(store, f, job, related, now):
    """Read-only deterministic analysis -> report dict. Raises on genuine failure."""
    cls = triage.classify(f, job)
    kind = kind_of(f)
    path = first_path(f.get("where"), f.get("detail"))
    known = [f"{job} reported \"{f.get('title')}\" with severity {f.get('severity')}."]
    suspected, unknown = [], ["Who or what created it, and why."]
    pk, pu = _facts_about_path(path, now)
    known += pk
    unknown += pu
    ledger = store.db.execute("SELECT first_sent,sent_count,reopened FROM alert_ledger WHERE key=?",
                              (alert.finding_key(f),)).fetchone()
    if ledger:
        known.append("First reported " + time.strftime("%Y-%m-%d", time.localtime(ledger["first_sent"]))
                     + f"; reported {ledger['sent_count']} time(s)"
                     + (f"; came back after being cleared {ledger['reopened']} time(s)." if ledger["reopened"] else "."))
    if related:
        known.append(f"{len(related)} other observation(s) share its place and category and are grouped with it.")
    if not (f.get("where") or f.get("detail")):
        return {"assessment": "unknown", "kind": kind, "known": known, "suspected": [],
                "unknown": unknown + ["The detector gave no detail or location."],
                "recommendation": "Re-run the check; ARGUS-INSTINCT has too little to explain this.",
                "insufficient": True}
    if kind == "monitoring":
        assessment = "confirmed"
        known.append("This is about ARGUS-INSTINCT's own visibility, not about an attack.")
        rec = "ARGUS-INSTINCT handles this itself where it can; see Monitoring."
    elif cls["owner"] == triage.JARVIS:
        assessment, rec = "strongly_supported", "ARGUS-INSTINCT is handling this. No action needed unless it keeps coming back."
        known.append("The finding is of a kind ARGUS-INSTINCT repairs or retries on its own.")
    elif f.get("severity") in ("critical", "high"):
        assessment = "suspicious"
        suspected.append(f"Its detector rated it {f.get('severity')}. That is a signal worth a look, not proof of a break-in.")
        rec = cls.get("action") or "Check whether you recognise it."
    else:
        assessment, rec = "unknown", cls.get("action") or "Nothing is needed now; ARGUS-INSTINCT will keep watching."
    unknown.append("Whether you caused it. Only you can say.")
    return {"assessment": assessment, "kind": kind, "known": known, "suspected": suspected,
            "unknown": unknown, "recommendation": rec, "command": cls.get("command") or "",
            "owner": cls["owner"], "needs_owner": cls["owner"] in (triage.YOU_DO, triage.YOU_CONFIRM)
            and f.get("severity") in ("critical", "high") and kind == "security"}


def _ai_note(report, f, conf):
    """Optional plain-language note from the local model. Never changes state; None when unavailable."""
    try:
        from jarvis.response import llm
        if llm.cooling_down() or llm.ping(conf)[0] not in ("model_loaded", "model_ready"):
            return None
        user = json.dumps({"title": f.get("title"), "severity": f.get("severity"),
                           "category": f.get("category"), "known": report["known"][:4],
                           "unknown": report["unknown"][:3]})
        text, err = llm.chat(conf, "In two plain sentences for a non-technical person, say what this "
                                   "security observation may mean and what is unknown. Do not claim "
                                   "compromise or safety. Use only the JSON.", user, num_predict=90)
        return None if err else text[:400]
    except Exception:
        return None


def _recognised(store, fid, evidence):
    for r in store.db.execute("SELECT scope FROM autopilot_decisions WHERE choice='recognise'"
                              " ORDER BY id DESC LIMIT 200"):
        try:
            if json.loads(r["scope"]).get(fid) == evidence:
                return True
        except ValueError:
            continue
    return False


def run_queue(store, now=None, pressured=False, limit=BATCH, conf=None, use_ai=True):
    """Investigate up to `limit` queued findings. Deferred entirely under host pressure."""
    now = int(time.time() if now is None else now)
    if pressured:
        return {"investigated": 0, "deferred": True}
    found, done, ai_used = current_findings(store), 0, False
    rows = store.db.execute("SELECT * FROM investigations WHERE state=? AND next_run<=?",
                            (QUEUED, now)).fetchall()
    rows = sorted(rows, key=lambda r: (SEV_RANK.get(r["severity"], 9), r["first_seen"]))[:limit]
    for row in rows:
        fid = row["fid"]
        if fid not in found:
            continue
        f, job = found[fid]
        _move(store, fid, INVESTIGATING, "started", now, attempts=row["attempts"] + 1)
        try:
            related = [x for x, (g, j) in found.items()
                       if x != fid and group_key(g, j) == row["group_key"]]
            rep = investigate(store, f, job, related, now)
            state = INSUFFICIENT if rep.get("insufficient") else INVESTIGATED
            if rep.get("needs_owner") and not _recognised(store, fid, evidence_hash(f)):
                state = NEEDS_USER
            if state == NEEDS_USER and use_ai and not ai_used and conf is not None:
                note = _ai_note(rep, f, conf)
                rep["ai"] = "used" if note else "unavailable"
                if note:
                    rep["ai_note"] = note
                ai_used = True
            _move(store, fid, state, "investigation complete", now,
                  report=json.dumps(rep), error="", evidence=evidence_hash(f), next_run=0)
            done += 1
        except Exception as exc:    # a failed investigation stays visibly failed
            delay = min(RETRY_CAP_S, RETRY_BASE_S * 2 ** row["attempts"])
            _move(store, fid, FAILED, f"investigation failed: {type(exc).__name__}", now,
                  error=str(exc)[:300], next_run=now + int(delay * (0.75 + 0.5 * random.random())))
    return {"investigated": done, "deferred": False}


# --- decisions -------------------------------------------------------------

def _members(store, key, state=None):
    sql, args = "SELECT * FROM investigations WHERE group_key=? AND resolved_at=0", [key]
    if state:
        sql += " AND state=?"
        args.append(state)
    return [dict(r) for r in store.db.execute(sql + " ORDER BY severity, first_seen", args)]


_CONSEQUENCE = {
    "recognise": "Records that you know about these exact observations. They stop asking for a decision "
                 "unless something about them changes. Nothing is whitelisted and similar future items are still checked.",
    "not_recognise": "ARGUS-INSTINCT prepares a suggested response. Nothing is changed until you separately authorise it.",
    "investigate_further": "ARGUS-INSTINCT re-checks and gathers fresh read-only evidence. Nothing is changed.",
    "review_individually": "Opens each observation on its own so you can judge them one at a time.",
}


def decision_queue(store):
    """One case per group that still needs the owner."""
    cases, seen = [], set()
    for r in store.db.execute("SELECT group_key FROM investigations WHERE state=? AND resolved_at=0",
                              (NEEDS_USER,)):
        key = r["group_key"]
        if key in seen:
            continue
        seen.add(key)
        members = _members(store, key)
        waiting = [m for m in members if m["state"] == NEEDS_USER]
        reps = [_report(m) for m in waiting]
        worst = min(waiting, key=lambda m: SEV_RANK.get(m["severity"], 9))
        folder = key.split("|", 2)[2] if key.count("|") >= 2 else ""
        count = len(members)
        title = (waiting[0]["title"] if count == 1
                 else f"{count} related observations" + (f" in {folder}" if folder else ""))
        est = list(dict.fromkeys(k for rep in reps for k in rep.get("known", [])))[:6]
        unc = list(dict.fromkeys(k for rep in reps for k in rep.get("unknown", [])))[:5]
        cases.append({
            "key": key, "title": title, "severity": worst["severity"], "count": count,
            "what_happened": f"ARGUS-INSTINCT observed {count} thing(s) that look related. Its checks rated the worst one {worst['severity']}.",
            "why_it_matters": "Only you can tell whether you or a program you use created these. "
                              "Unexplained items of this kind are worth a quick look; they are not proof of a break-in.",
            "established": est, "uncertain": unc,
            "recommended": reps[0].get("recommendation", ""),
            "ai_note": next((r.get("ai_note") for r in reps if r.get("ai_note")), ""),
            "observations": [{"id": m["fid"], "title": m["title"], "severity": m["severity"], "job": m["job"],
                              "where": m["locus"], "state": m["state"],
                              "assessment": _report(m).get("assessment", "")} for m in members],
            "options": [{"choice": c, "consequence": _CONSEQUENCE[c]} for c in CHOICES],
        })
    cases.sort(key=lambda c: SEV_RANK.get(c["severity"], 9))
    return cases


def decide(store, key, choice, fids=None, note="", now=None):
    """Record the owner's decision for the listed findings of one group. -> result dict."""
    now = int(time.time() if now is None else now)
    if choice not in CHOICES:
        raise ValueError("unknown choice")
    waiting = {m["fid"]: m for m in _members(store, key, NEEDS_USER)}
    chosen = [x for x in (fids or list(waiting)) if x in waiting]
    if not chosen:
        raise ValueError("nothing in that group is waiting for a decision")
    scope = {fid: waiting[fid]["evidence"] for fid in chosen}
    store.db.execute("INSERT INTO autopilot_decisions(ts,group_key,choice,scope,note) VALUES(?,?,?,?,?)",
                     (now, key, choice, json.dumps(scope), str(note)[:300]))
    store.db.commit()
    for fid in chosen:
        rep = _report(waiting[fid])
        stamp = {"choice": choice, "ts": now, "scope": "this observation only"}
        if choice == "recognise":
            rep["decision"] = stamp
            _move(store, fid, INVESTIGATED, "owner recognised this observation", now,
                  report=json.dumps(rep))
        elif choice == "not_recognise":
            rep["decision"] = stamp
            rep["proposal"] = {"step": rep.get("command") or rep.get("recommendation", ""),
                               "requires_authorization": True}
            _move(store, fid, PROPOSED, "owner does not recognise this; response proposed", now,
                  report=json.dumps(rep))
        elif choice == "investigate_further":
            _move(store, fid, QUEUED, "owner asked for more investigation", now, next_run=0)
    return {"ok": True, "choice": choice, "scope": list(scope), "applies_to_future": False}


AUTO_META = "autopilot.auto_handle"
AUTO_SEVERITIES = frozenset({"high"})     # only "high" and "critical" ever reach the owner; critical never auto-handled
AUTO_MIN_AGE_S = 3 * 86400                # unchanged and standing for three days
AUTO_PER_CYCLE = 25                       # bounded: a burst of new items is cleared over several cycles


def auto_handle_enabled(store):
    return (store.get_meta(AUTO_META, "") or "") == "1"


def set_auto_handle(store, on):
    store.set_meta(AUTO_META, "1" if on else "0")
    return bool(on)


def auto_handle(store, now=None, limit=AUTO_PER_CYCLE):
    """Opt-in: record "recognise" for waiting groups that are low-stakes to dismiss.

    A group qualifies only when every waiting member is rated high (never
    critical), is of the "you confirm" kind (the owner's own tools and
    accounts, not "only you can fix this"), and has been unchanged for
    AUTO_MIN_AGE_S. The record is the owner's own "recognise": this
    observation at this evidence, so changed evidence re-opens it. It never
    rejects, proposes or authorises anything, and each entry in
    autopilot_decisions carries the "auto-handled" note. -> count handled.
    """
    if not auto_handle_enabled(store):
        return 0
    now = int(time.time() if now is None else now)
    done = 0
    for case in decision_queue(store):
        if done >= limit:
            break
        if case["severity"] not in AUTO_SEVERITIES:
            continue
        waiting = [m for m in _members(store, case["key"], NEEDS_USER)]
        if not waiting or len(waiting) > limit - done:
            continue
        if not all(_report(m).get("owner") == triage.YOU_CONFIRM
                   and now - int(m["first_seen"]) >= AUTO_MIN_AGE_S for m in waiting):
            continue
        decide(store, case["key"], "recognise", [m["fid"] for m in waiting],
               note="auto-handled: standing, owner-confirm, not critical", now=now)
        done += len(waiting)
    return done


def authorize(store, fid, now=None):
    """The only door to ACTION_AUTHORIZED: one finding, one step. Does not perform it."""
    now = int(time.time() if now is None else now)
    row = _row(store, fid)
    if not row or row["state"] != PROPOSED:
        raise ValueError("no proposed action for that finding")
    store.db.execute("INSERT INTO autopilot_decisions(ts,group_key,choice,scope,note) VALUES(?,?,?,?,?)",
                     (now, row["group_key"], "authorize_action", json.dumps({fid: row["evidence"]}), ""))
    _move(store, fid, AUTHORIZED, "owner authorised the proposed step for this finding", now)
    return {"ok": True, "fid": fid, "performed": False}


def mark_applied(store, fid, ok, detail="", now=None):
    """Called by the existing remediation path after it acted on an authorised finding."""
    now = int(time.time() if now is None else now)
    row = _row(store, fid)
    if not row or row["state"] != AUTHORIZED:
        raise ValueError("that finding has no authorised action")
    _move(store, fid, APPLIED if ok else PROPOSED, detail or ("applied" if ok else "action failed"), now)


# --- collector recovery ----------------------------------------------------

def backoff(retries, rng=random.random):
    return int(min(RETRY_CAP_S, RETRY_BASE_S * 2 ** retries) * (0.75 + 0.5 * rng()))


def _klass(det):
    err = (det.get("error") or "").lower()
    if det["state"] == detectorhealth.MISSING_DEP:
        return "missing_dependency"
    if det["state"] == detectorhealth.RESTRICTED:
        return "permission"
    if det["state"] in (detectorhealth.UNSUPPORTED, detectorhealth.NOT_APPLICABLE):
        return "unsupported"
    if re.search(r"\b(404|410)\b|\bgone\b|expired|no longer (available|provided|exists)|discontinued", err):
        return "source_unavailable"
    return "transient"


_KLASS_TEXT = {
    "missing_dependency": "A program this check needs is not installed. ARGUS-INSTINCT will not install it for you; "
                          "install it or accept the gap.",
    "permission": "This check is not allowed to read something it needs. Grant that access, or accept the gap.",
    "unsupported": "This check does not work on this computer. Nothing to fix.",
    "source_unavailable": "The outside data source this check uses is gone or expired. ARGUS-INSTINCT has stopped retrying it.",
    "transient": "The check failed or went quiet. ARGUS-INSTINCT is retrying with increasing delays.",
}


def plan_recovery(store, report, now=None, rng=random.random):
    """Update recovery rows from a detectorhealth report -> list of {job, action, klass}.

    action is "retry" (due now), "wait", or "none" (retrying cannot help)."""
    now = int(time.time() if now is None else now)
    plan = []
    rows = {r["job"]: dict(r) for r in store.db.execute("SELECT * FROM recovery")}
    for det in report.get("detectors", []):
        job = det["id"]
        row = rows.get(job)
        if det["state"] == detectorhealth.HEALTHY:
            if row and det.get("recovery_confirmed"):
                store.db.execute("DELETE FROM recovery WHERE job=?", (job,))
            continue
        if det["state"] == detectorhealth.NOT_APPLICABLE:
            continue
        klass = _klass(det)
        if klass != "transient":
            status = "unavailable" if klass in ("source_unavailable", "unsupported") else "needs_owner"
            store.db.execute("INSERT INTO recovery(job,klass,retries,next_try,last_try,status,note,updated)"
                             " VALUES(?,?,0,0,0,?,?,?) ON CONFLICT(job) DO UPDATE SET klass=excluded.klass,"
                             "status=excluded.status,note=excluded.note,updated=excluded.updated",
                             (job, klass, status, _KLASS_TEXT[klass], now))
            plan.append({"job": job, "action": "none", "klass": klass})
            continue
        if row is None:
            store.db.execute("INSERT INTO recovery(job,klass,retries,next_try,last_try,status,note,updated)"
                             " VALUES(?,?,0,?,0,'retrying',?,?)",
                             (job, klass, now + backoff(0, rng), _KLASS_TEXT[klass], now))
            plan.append({"job": job, "action": "wait", "klass": klass})
            continue
        if row["status"] == "exhausted" and now >= row["next_try"]:
            row.update(retries=0, status="retrying")        # cooldown over: a fresh budget
        if row["retries"] >= RECOVERY_MAX_RETRIES:
            store.db.execute("UPDATE recovery SET status='exhausted', retries=?, next_try=CASE WHEN status<>'exhausted'"
                             " THEN ? ELSE next_try END, note=?, updated=? WHERE job=?",
                             (row["retries"], now + RECOVERY_COOLDOWN_S,
                              "Retries are used up; ARGUS-INSTINCT will try again after a long pause.", now, job))
            plan.append({"job": job, "action": "none", "klass": klass})
        elif now >= row["next_try"]:
            plan.append({"job": job, "action": "retry", "klass": klass})
        else:
            plan.append({"job": job, "action": "wait", "klass": klass})
    store.db.commit()
    return plan


def run_recovery(store, plan, runner, now=None, pressured=False, rng=random.random):
    """Queue due retries through the scheduler's own `force`, at most a few per cycle."""
    now = int(time.time() if now is None else now)
    sent = 0
    for item in plan:
        if item["action"] != "retry":
            continue
        row = store.db.execute("SELECT retries FROM recovery WHERE job=?", (item["job"],)).fetchone()
        if pressured or sent >= RECOVERY_PER_CYCLE or runner is None:
            store.db.execute("UPDATE recovery SET next_try=? WHERE job=?", (now + RETRY_BASE_S, item["job"]))
            continue
        retries = (row["retries"] if row else 0) + 1
        queued = bool(runner(item["job"]))
        store.db.execute("UPDATE recovery SET retries=?, last_try=?, next_try=?, status='retrying', updated=?"
                         " WHERE job=?", (retries, now, now + backoff(retries, rng), now, item["job"]))
        sent += queued
    store.db.commit()
    return sent


# --- health numbers (one definition) --------------------------------------

def health_numbers(report):
    """The only place the monitoring figures are defined.

    total = detectors that apply to this computer (not-applicable ones are excluded);
    reporting = those with fresh, valid results; partial = reporting late or with limited access;
    not_reporting = the rest. Every screen must show these same numbers."""
    c = report.get("counts") or {}
    total = int(report.get("total") or 0)
    return {"total": total, "reporting": int(c.get("verified", 0)), "partial": int(c.get("partial", 0)),
            "not_reporting": int(c.get("blind", 0)),
            "definition": "Checks that apply to this computer. 'Reporting' means a fresh, valid result."}


# --- notifications ---------------------------------------------------------

NOTICE_KEY, PREFS_KEY = "autopilot.notified", "autopilot.prefs"


def _json_meta(store, key, default):
    try:
        v = json.loads(store.get_meta(key, "") or "")
        return v if isinstance(v, type(default)) else default
    except ValueError:
        return default


def take_notices(store, now=None):
    """-> consolidated notices not yet delivered; marks them delivered. Quiet hours hold non-critical ones."""
    now = int(time.time() if now is None else now)
    sent = _json_meta(store, NOTICE_KEY, {})
    prefs = _json_meta(store, PREFS_KEY, {})
    hour = time.localtime(now).tm_hour
    qs, qe = prefs.get("quiet_start"), prefs.get("quiet_end")
    quiet = (qs is not None and qe is not None and
             ((qs <= hour < qe) if qs <= qe else (hour >= qs or hour < qe)))
    fresh = []
    for case in decision_queue(store):
        ids = sorted(o["id"] for o in case["observations"] if o["state"] == NEEDS_USER)
        evid = hashlib.sha1("|".join(f"{i}{_row(store, i)['evidence']}" for i in ids).encode()).hexdigest()[:12]
        key = f"decision:{case['key']}:{evid}"
        if key not in sent and not (quiet and case["severity"] != "critical"):
            fresh.append((key, {"kind": "decision", "severity": case["severity"],
                                "text": f"A decision is needed: {case['title']}."}))
    for r in store.db.execute("SELECT job,klass FROM recovery WHERE status IN ('exhausted','needs_owner')"):
        key = f"monitor:{r['job']}:{r['klass']}"
        if key not in sent and not quiet:
            fresh.append((key, {"kind": "monitoring", "severity": "medium",
                                "text": f"A check ({r['job']}) is unavailable and needs your attention."}))
    for r in store.db.execute("SELECT fid,title,resolved_at FROM investigations WHERE resolved_at>?",
                              (now - 86400,)):
        key = f"resolved:{r['fid']}:{r['resolved_at']}"
        asked = store.db.execute("SELECT 1 FROM investigation_events WHERE fid=? AND to_state=? LIMIT 1",
                                 (r["fid"], NEEDS_USER)).fetchone()
        if key not in sent and not quiet and asked:
            fresh.append((key, {"kind": "resolved", "severity": "info", "text": f"Resolved: {r['title']}."}))
    for key, _n in fresh:
        sent[key] = now
    if len(sent) > 500:
        sent = dict(sorted(sent.items(), key=lambda kv: kv[1])[-300:])
    if fresh:
        store.set_meta(NOTICE_KEY, json.dumps(sent))
    if not fresh:
        return []
    if len(fresh) == 1:
        return [fresh[0][1]]
    worst = min((n["severity"] for _k, n in fresh), key=lambda s: SEV_RANK.get(s, 9))
    decisions = sum(1 for _k, n in fresh if n["kind"] == "decision")
    parts = ([f"{decisions} decisions are waiting for you"] if decisions else []) + \
            ([f"{len(fresh) - decisions} other update(s)"] if len(fresh) > decisions else [])
    return [{"kind": "digest", "severity": worst, "text": "; ".join(parts) + ". Open ARGUS-INSTINCT to review."}]


# --- the overview ----------------------------------------------------------

def daily_summary(store, report, now=None, window=86400):
    now = int(time.time() if now is None else now)
    since = now - window

    def count(sql, *a):
        return store.db.execute(sql, a).fetchone()[0]

    nums = health_numbers(report)
    limits = []
    if nums["not_reporting"]:
        limits.append(f"{nums['not_reporting']} of {nums['total']} checks are not reporting, so those areas are unobserved.")
    failed = count("SELECT COUNT(*) FROM investigations WHERE state=? AND resolved_at=0", FAILED)
    insuff = count("SELECT COUNT(*) FROM investigations WHERE state=? AND resolved_at=0", INSUFFICIENT)
    if failed:
        limits.append(f"{failed} investigation(s) failed and will be retried.")
    if insuff:
        limits.append(f"{insuff} observation(s) had too little evidence to explain.")
    return {
        "window_hours": window // 3600,
        "new_findings": count("SELECT COUNT(*) FROM investigations WHERE first_seen>=?", since),
        "investigations_completed": count(
            "SELECT COUNT(*) FROM investigation_events WHERE ts>=? AND from_state=? AND to_state IN (?,?,?)",
            since, INVESTIGATING, INVESTIGATED, NEEDS_USER, INSUFFICIENT),
        "needs_attention": count("SELECT COUNT(DISTINCT group_key) FROM investigations WHERE state=? AND resolved_at=0",
                                 NEEDS_USER),
        "monitoring": nums,
        "actions_authorized": count("SELECT COUNT(*) FROM investigation_events WHERE ts>=? AND to_state=?", since, AUTHORIZED),
        "actions_performed": count("SELECT COUNT(*) FROM investigation_events WHERE ts>=? AND to_state=?", since, APPLIED),
        "limitations": limits or ["None beyond what ARGUS-INSTINCT can see on this computer."],
    }


def status(store, report, now=None):
    """Everything the simple dashboard shows, in one read-only call."""
    now = int(time.time() if now is None else now)
    nums = health_numbers(report)
    states = {r["state"]: r["n"] for r in store.db.execute(
        "SELECT state, COUNT(*) n FROM investigations WHERE resolved_at=0 GROUP BY state")}
    queue = decision_queue(store)
    handled = [dict(r) for r in store.db.execute(
        "SELECT title,severity,state,updated,group_key FROM investigations WHERE resolved_at=0 AND state IN (?,?) "
        "ORDER BY updated DESC LIMIT 40", (INVESTIGATED, VERIFIED))]
    groups = {}
    for h in handled:
        g = groups.setdefault(h["group_key"], {"title": h["title"], "count": 0, "severity": h["severity"],
                                               "updated": h["updated"]})
        g["count"] += 1
    handled_groups = [{**g, "title": g["title"] if g["count"] == 1 else f"{g['title']} and {g['count'] - 1} related"}
                      for g in groups.values()][:10]
    recoveries = [{"job": r["job"], "klass": r["klass"], "status": r["status"], "retries": r["retries"],
                   "next_try": r["next_try"], "note": r["note"]} for r in store.db.execute("SELECT * FROM recovery")]
    if queue:
        level, headline = "attention", "A decision is waiting for you"
    elif nums["total"] and nums["not_reporting"] > nums["total"] // 2:
        level, headline = "incomplete", "ARGUS-INSTINCT cannot see much right now"
    elif nums["not_reporting"]:
        level, headline = "partial", "Nothing needs you, but some checks are not reporting"
    else:
        level, headline = "ok", "Nothing needs you right now"
    return {
        "health": {"level": level, "headline": headline,
                   "okay": "Nothing needs a decision from you." if not queue else
                           f"{len(queue)} case(s) need a decision from you.",
                   "monitoring": nums,
                   "monitoring_line": f"{nums['reporting']} of {nums['total']} checks are reporting."
                                      if nums["total"] else "No checks are scheduled yet."},
        "queue": {"investigating": states.get(INVESTIGATING, 0), "queued": states.get(QUEUED, 0),
                  "failed": states.get(FAILED, 0), "insufficient": states.get(INSUFFICIENT, 0),
                  "states": states},
        "handled": {"groups": handled_groups, "investigated": states.get(INVESTIGATED, 0)},
        "needs_me": queue, "recovery": recoveries,
        "policy": {"auto_handle": auto_handle_enabled(store), "min_age_days": AUTO_MIN_AGE_S // 86400},
        "summary": daily_summary(store, report, now),
    }


# --- the cycle and its thread ---------------------------------------------

def prune(store, now=None):
    now = int(time.time() if now is None else now)
    store.db.execute("DELETE FROM investigations WHERE resolved_at>0 AND resolved_at<? AND state NOT IN (?,?,?)",
                     (now - KEEP_RESOLVED_S, AUTHORIZED, APPLIED, PROPOSED))
    store.db.execute("DELETE FROM investigation_events WHERE id <= (SELECT COALESCE(MAX(id),0) FROM"
                     " investigation_events) - ?", (KEEP_EVENTS,))
    store.db.execute("DELETE FROM autopilot_decisions WHERE id <= (SELECT COALESCE(MAX(id),0) FROM"
                     " autopilot_decisions) - 2000")
    store.db.commit()


def cycle(store, report, runner=None, now=None, pressured=False, conf=None):
    now = int(time.time() if now is None else now)
    out = {"interrupted": recover_interrupted(store, now), "queued": sync(store, now)}
    out.update(run_queue(store, now, pressured=pressured, conf=conf))
    out["auto_handled"] = auto_handle(store, now)
    plan = plan_recovery(store, report, now)
    out["retries"] = run_recovery(store, plan, runner, now, pressured=pressured)
    prune(store, now)
    return out


def loop(db_path, scheduler, report_fn, interval=30.0, stop=None):
    """Background thread body. `report_fn(store)` -> detectorhealth report. Never raises."""
    from jarvis.core import governor
    from jarvis.core.store import Store
    from jarvis.response import alert as alert_mod
    time.sleep(10)
    while not (stop and stop.is_set()):
        store = None
        try:
            store = Store(db_path)
            pressured, _why = governor.live_pressure()
            cycle(store, report_fn(store), getattr(scheduler, "force", None), pressured=pressured,
                  conf=alert_mod.load_conf())
        except Exception:
            pass
        finally:
            if store is not None:
                store.close()
        time.sleep(interval)
