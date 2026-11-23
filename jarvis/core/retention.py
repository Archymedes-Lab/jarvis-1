"""Bounded growth for the state database.

The store accumulates about 12 MB a day, most of it low-severity process
events and threat-feed indicators. Left alone it reaches multiple gigabytes
within a year, and every collector that queries it slows down together.

Retention is expressed as a table of policies rather than as DELETE
statements scattered through the collectors, so what is kept — and why — can
be read in one place and reported before anything is removed. Nothing here
deletes a finding an operator has not seen: severity tiers keep serious
events far longer than routine ones, and critical events are never aged out.
"""

from .util import now

DAY = 86400


class Policy:
    """One retention rule: what it removes, and the reasoning for the age."""

    def __init__(self, name, table, days, where, why, params=()):
        self.name = name
        self.table = table
        self.days = days
        self.where = where
        self.why = why
        self.params = params

    def _args(self, days=None):
        cutoff = now() - (days if days is not None else self.days) * DAY
        return (cutoff,) + tuple(self.params)

    def count(self, store, days=None):
        sql = "SELECT COUNT(*) FROM %s WHERE %s" % (self.table, self.where)
        return store.db.execute(sql, self._args(days)).fetchone()[0]

    def apply(self, store, days=None):
        sql = "DELETE FROM %s WHERE %s" % (self.table, self.where)
        return store.db.execute(sql, self._args(days)).rowcount


# Ordered roughly by how much space each reclaims. The severity tiers on
# `events` are the substance of the policy: a routine low-severity process
# sighting is worth a fortnight, a high-severity one worth half a year, and a
# critical one is never removed on age alone.
POLICIES = [
    Policy("incident-coverage-flaps", "defender_transitions", 0,
           "observed_at < ? AND previous_state IN ('not_observed','unobserved') "
           "AND state IN ('not_observed','unobserved') AND run_id IN "
           "(SELECT run_id FROM defender_runs)",
           "derived dormant-incident coverage flips; the durable run receipt "
           "retains the same coverage/error evidence, while active, first-seen, "
           "recurrence and severity transitions are never matched"),
    Policy("defender-runs", "defender_runs", 30,
           "observed_at < ? AND sequence NOT IN "
           "(SELECT MAX(sequence) FROM defender_runs GROUP BY job) "
           "AND run_id NOT IN (SELECT last_run_id FROM defender_incidents) "
           "AND NOT EXISTS (SELECT 1 FROM defender_transitions "
           "WHERE defender_transitions.run_id=defender_runs.run_id)",
           "routine collector receipts; preserve latest coverage and every "
           "receipt referenced by incident history"),
    Policy("events-low", "events", 14,
           "ts < ? AND severity = 'low'",
           "routine sightings; the process baseline already records what ran"),
    Policy("events-medium", "events", 60,
           "ts < ? AND severity = 'medium'",
           "long enough to cover a monthly review cycle"),
    Policy("events-high", "events", 180,
           "ts < ? AND severity = 'high'",
           "kept across a half-year so slow-burn activity stays comparable"),
    Policy("indicators-retired", "indicators", 30,
           "last_seen < ? AND status = 'retired' AND source != 'exa'",
           "feed entries already retired by prune(); writeup-derived "
           "indicators are never removed"),
    Policy("indicators-rejected", "indicators", 7,
           "last_seen < ? AND status = 'rejected'",
           "explicitly rejected during triage"),
    Policy("procs-stale", "procs", 120,
           "last_seen < ? AND approved = 0",
           "a program not seen in four months is no longer part of the "
           "baseline; approved entries are kept"),
    Policy("peers-stale", "peers", 90,
           "last_seen < ? AND approved = 0",
           "network peers churn; approved entries are kept"),
    Policy("hunt-hits", "hunt_hits", 90,
           "ts < ?",
           "threat-intel matches are re-derived on every hunt"),
    Policy("net-events", "net_events", 60,
           "ts < ?",
           "interface state changes"),
]

# `events.severity` is indexed only by time, so the tiered deletes above scan
# by ts and filter. This composite index makes both the count and the delete
# an index range rather than a table scan.
INDEXES = [
    ("idx_events_sev_ts", "events", "severity, ts"),
    ("idx_ind_status_seen", "indicators", "status, last_seen"),
    ("idx_procs_last_seen", "procs", "last_seen"),
    ("idx_peers_last_seen", "peers", "last_seen"),
]


def ensure_indexes(store):
    """Create the indexes the policies rely on. Safe to call repeatedly."""
    made = []
    for name, table, cols in INDEXES:
        try:
            store.db.execute("CREATE INDEX IF NOT EXISTS %s ON %s(%s)"
                             % (name, table, cols))
            made.append(name)
        except Exception:
            # A table this build does not have is not an error; the policy
            # that uses it will report zero rows.
            continue
    store.commit()
    return made


def plan(store, overrides=None):
    """What each policy would remove, without removing it."""
    overrides = overrides or {}
    out = []
    for p in POLICIES:
        days = overrides.get(p.name, p.days)
        try:
            n = p.count(store, days)
        except Exception as exc:
            out.append({"name": p.name, "table": p.table, "days": days,
                        "rows": 0, "why": p.why, "error": str(exc)})
            continue
        out.append({"name": p.name, "table": p.table, "days": days,
                    "rows": n, "why": p.why, "error": ""})
    return out


def apply(store, overrides=None, indexes=True):
    """Run every policy. Returns the same shape as plan(), with rows removed."""
    if indexes:
        ensure_indexes(store)
    overrides = overrides or {}
    out = []
    for p in POLICIES:
        days = overrides.get(p.name, p.days)
        try:
            n = p.apply(store, days)
            err = ""
        except Exception as exc:
            n, err = 0, str(exc)
        out.append({"name": p.name, "table": p.table, "days": days,
                    "rows": n, "why": p.why, "error": err})
    store.commit()
    return out


def db_size(store):
    """Bytes in use and bytes reclaimable without a full VACUUM."""
    page = store.db.execute("PRAGMA page_size").fetchone()[0]
    count = store.db.execute("PRAGMA page_count").fetchone()[0]
    free = store.db.execute("PRAGMA freelist_count").fetchone()[0]
    return {"bytes": page * count, "free_bytes": page * free,
            "pages": count, "free_pages": free}


def vacuum(store):
    """Return freed pages to the filesystem.

    VACUUM rewrites the whole database and needs room for a second copy, so
    it is a deliberate command rather than part of the scheduled sweep.
    """
    before = db_size(store)
    store.commit()
    store.db.execute("VACUUM")
    after = db_size(store)
    return {"before": before, "after": after,
            "reclaimed": before["bytes"] - after["bytes"]}


# -- command line -----------------------------------------------------------
