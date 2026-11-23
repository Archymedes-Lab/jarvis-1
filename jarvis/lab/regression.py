"""Every scenario the Arena has run, and every result, kept forever.

The point of the Arena is that a defence, once earned, is hard to lose. So a
scenario that has ever run becomes permanent, and each run is recorded. A build
whose score on a scenario drops below its best is a regression, surfaced by
name — that is the monotonic ratchet the design is after.
"""

import json
import os
import sqlite3
import time
from pathlib import Path

DEFAULT_DB = Path(os.path.expanduser("~/.jarvis/arena.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS scenarios (
  id TEXT PRIMARY KEY, title TEXT, platform TEXT, safety TEXT, source TEXT,
  origin TEXT, techniques TEXT, spec TEXT, added_at REAL);
CREATE TABLE IF NOT EXISTS runs (
  run_id INTEGER PRIMARY KEY AUTOINCREMENT, scenario_id TEXT NOT NULL,
  at REAL NOT NULL, score INTEGER NOT NULL, ok INTEGER NOT NULL,
  exercised TEXT, passed TEXT, earliest_seq INTEGER, earliest_time TEXT,
  card TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS runs_scenario ON runs(scenario_id, at);
"""


class Regression:
    def __init__(self, path=DEFAULT_DB):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    def remember(self, scenario):
        with self.db:
            self.db.execute(
                "INSERT INTO scenarios VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "title=excluded.title, platform=excluded.platform, safety=excluded.safety, "
                "source=excluded.source, origin=excluded.origin, techniques=excluded.techniques, "
                "spec=excluded.spec",
                (scenario.id, scenario.title, scenario.platform, scenario.safety, scenario.source,
                 scenario.origin, json.dumps(scenario.techniques), json.dumps(scenario.to_dict()),
                 time.time()))

    def record(self, card):
        ed = card.get("earliest_decision") or {}
        with self.db:
            self.db.execute(
                "INSERT INTO runs(scenario_id,at,score,ok,exercised,passed,earliest_seq,"
                "earliest_time,card) VALUES(?,?,?,?,?,?,?,?,?)",
                (card["scenario"], time.time(), card["score"], int(card["ok"]),
                 json.dumps(card["exercised"]), json.dumps(card["passed"]),
                 ed.get("seq"), ed.get("time"), json.dumps(card)))

    def best(self, scenario_id):
        row = self.db.execute("SELECT MAX(score) FROM runs WHERE scenario_id=?",
                              (scenario_id,)).fetchone()
        return row[0]

    def latest(self, scenario_id):
        return self.db.execute(
            "SELECT * FROM runs WHERE scenario_id=? ORDER BY at DESC LIMIT 1",
            (scenario_id,)).fetchone()

    def history(self, scenario_id, limit=50):
        return self.db.execute(
            "SELECT * FROM runs WHERE scenario_id=? ORDER BY at DESC LIMIT ?",
            (scenario_id, limit)).fetchall()

    def scenarios(self, source=None):
        q = "SELECT * FROM scenarios"
        args = ()
        if source:
            q += " WHERE source=?"
            args = (source,)
        return self.db.execute(q + " ORDER BY id", args).fetchall()

    def regressions(self):
        """Scenarios whose most recent run scored below their historical best."""
        out = []
        for row in self.scenarios():
            best = self.best(row["id"])
            latest = self.latest(row["id"])
            if latest is not None and best is not None and latest["score"] < best:
                out.append({"id": row["id"], "title": row["title"],
                            "best": best, "now": latest["score"]})
        return out

    def summary(self):
        rows = self.scenarios()
        latest = {r["id"]: self.latest(r["id"]) for r in rows}
        scored = [latest[r["id"]] for r in rows if latest[r["id"]] is not None]
        passing = sum(1 for r in scored if r["ok"])
        return {"scenarios": len(rows), "run": len(scored), "passing": passing,
                "regressions": self.regressions()}
