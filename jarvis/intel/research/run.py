"""Refreshing the corpus one topic at a time, re-vetting stored indicators, and
summarising the knowledge base."""

import json

from jarvis.core import vet
from jarvis.core.util import now
from jarvis.intel.corpus import CORPUS

from .client import (
    CONFIG_PATH,
    BudgetExceeded,
    IntelError,
    _charge,
    daily_budget,
    load_key,
    search,
    spent_today,
)
from .extraction import ingest_result


def refresh(store, topics=None, per_query=6, days=365, key=None, on_progress=None):
    """Run part of the corpus and ingest what comes back.

    Defaults to a single topic per call so the daemon spreads cost over time
    rather than spending the whole corpus in one burst.
    """
    key = key or load_key()
    if not key:
        raise IntelError(
            "no Exa API key configured — run: jarvis intel --set-key <key>")

    budget = daily_budget()
    already = spent_today(store)
    if already >= budget:
        raise BudgetExceeded(
            f"daily API budget reached (${already:.3f} of ${budget:.2f}) — "
            f"raise `daily_budget` in {CONFIG_PATH} or wait for tomorrow")

    names = list(topics) if topics else [_next_topic(store)]
    stats = {"seen": 0, "kept": 0, "rejected": 0, "docs": 0, "unparsed": 0,
             "not_research": 0, "queries": 0, "errors": [], "cost": 0.0,
             "reasons": {}, "topics": names}

    for topic in names:
        for query in CORPUS.get(topic, []):
            if on_progress:
                on_progress(topic, query)
            if spent_today(store) >= budget:
                stats["errors"].append(
                    f"stopped early: daily budget ${budget:.2f} reached")
                break
            try:
                res = search(query, key, num_results=per_query, days=days)
            except IntelError as exc:
                stats["errors"].append(f"{topic}: {exc}")
                continue
            stats["queries"] += 1
            cost = float((res.get("costDollars") or {}).get("total") or 0.0)
            stats["cost"] += cost
            _charge(store, cost)
            for result in res.get("results", []):
                ingest_result(store, result, topic, query, stats)
            store.commit()
        store.set_meta(f"intel_topic_{topic}", now())

    store.set_meta("intel_last_refresh", now())
    store.set_meta("intel_spend_total",
                   round(float(store.get_meta("intel_spend_total", 0) or 0)
                         + stats["cost"], 4))
    store.commit()
    return stats


def daemon_options(store):
    """Bounded Exa breadth for unattended refreshes.

    The daily dollar brake remains authoritative. These knobs let a user buy
    broader/fresher intelligence without changing code or allowing an
    unbounded scheduled search.
    """
    try:
        with open(CONFIG_PATH, errors="replace") as fh:
            conf = json.load(fh) or {}
    except (OSError, ValueError):
        conf = {}
    try:
        topic_count = max(1, min(int(conf.get("intel_topics_per_run", 2)), 6))
    except (TypeError, ValueError):
        topic_count = 2
    try:
        results = max(1, min(int(conf.get("intel_results_per_query", 6)), 25))
    except (TypeError, ValueError):
        results = 6
    try:
        days = max(7, min(int(conf.get("intel_lookback_days", 365)), 1825))
    except (TypeError, ValueError):
        days = 365
    ages = []
    for topic in CORPUS:
        last = int(store.get_meta(f"intel_topic_{topic}", 0) or 0)
        ages.append((last, topic))
    ages.sort()
    return {
        "topics": [topic for _last, topic in ages[:topic_count]],
        "per_query": results,
        "days": days,
    }


def _next_topic(store):
    """Least recently refreshed topic, so the corpus rotates on its own."""
    ages = []
    for topic in CORPUS:
        last = int(store.get_meta(f"intel_topic_{topic}", 0) or 0)
        ages.append((last, topic))
    ages.sort()
    return ages[0][1]


def revet(store):
    """Re-judge every stored indicator against the current rules.

    The gate gets tighter as bad extractions are found. Without this, the first
    poisoned batch stays live forever and the knowledge base is only ever as
    good as the rules on the day it was fetched.
    """
    stats = {"checked": 0, "dropped": 0, "moved": 0, "reasons": {}}
    rows = store.db.execute(
        "SELECT id, kind, value, norm, status FROM indicators").fetchall()
    for r in rows:
        stats["checked"] += 1
        kind = r["kind"]
        raw = r["value"]
        if kind == "process" and raw.strip().lower().endswith(
                (".so", ".ko", ".dll", ".dylib")):
            kind = "filename"
        norm, why = vet.vet(kind, raw)
        if not norm:
            if r["status"] != "rejected":
                store.db.execute(
                    "UPDATE indicators SET status='rejected' WHERE id=?", (r["id"],))
                stats["dropped"] += 1
                stats["reasons"][why] = stats["reasons"].get(why, 0) + 1
            continue
        if kind != r["kind"] or norm != r["norm"]:
            # Moving a row can collide with an existing one; drop it if so.
            try:
                store.db.execute(
                    "UPDATE indicators SET kind=?, norm=?, status='active' WHERE id=?",
                    (kind, norm, r["id"]))
                stats["moved"] += 1
            except Exception:
                store.db.execute("DELETE FROM indicators WHERE id=?", (r["id"],))
        elif r["status"] == "rejected":
            store.db.execute(
                "UPDATE indicators SET status='active' WHERE id=?", (r["id"],))
    store.commit()
    return stats


def summary(store):
    """What the knowledge base currently holds."""
    rows = store.db.execute(
        "SELECT kind, COUNT(*) n FROM indicators WHERE status='active' "
        "GROUP BY kind ORDER BY n DESC").fetchall()
    docs = store.db.execute("SELECT COUNT(*) n FROM intel_docs").fetchone()["n"]
    return {
        "docs": docs,
        "by_kind": {r["kind"]: r["n"] for r in rows},
        "total": sum(r["n"] for r in rows),
        "last_refresh": int(store.get_meta("intel_last_refresh", 0) or 0),
        "spend": float(store.get_meta("intel_spend_total", 0) or 0),
        "spend_today": spent_today(store),
        "budget": daily_budget(),
    }
