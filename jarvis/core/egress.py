"""Approve-once egress baseline: which programs are expected to reach the internet.

A learned baseline that trusts whatever it sees first would trust the implant
too. So nothing is learned silently: the first time a program not on the
built-in list talks to a public address, JARVIS asks once. "Yes" makes that
program quiet; "no" makes every later connection from it a high finding.
"""

import time

EXPECTED, UNEXPECTED = "expected", "unexpected"
TITLE = "outbound connections from"


def program_of(title):
    """The program name from an egress finding title, or ""."""
    title = title or ""
    return title[len(TITLE):].strip() if title.startswith(TITLE + " ") else ""


def decision(store, host, program):
    try:
        row = store.db.execute(
            "SELECT decision FROM egress_baseline WHERE host=? AND program=?",
            (host, program)).fetchone()
    except Exception:
        return ""
    return row[0] if row else ""


def decide(store, host, program, choice, now=None):
    if choice not in (EXPECTED, UNEXPECTED):
        raise ValueError("decision must be expected or unexpected")
    store.db.execute(
        """INSERT INTO egress_baseline(host, program, decision, at) VALUES(?,?,?,?)
           ON CONFLICT(host, program) DO UPDATE SET decision=excluded.decision, at=excluded.at""",
        (host, program, choice, int(time.time() if now is None else now)))
    store.commit()


def decisions(store):
    try:
        return [dict(r) for r in store.db.execute(
            "SELECT host, program, decision, at FROM egress_baseline ORDER BY program")]
    except Exception:
        return []
