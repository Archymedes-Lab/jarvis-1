"""Which programs have started on the WSL guest before: the start history.

The scan collector looks at the process table once a minute, so it never
records a program that lives for a fraction of a second, and most container
health checks, build steps and shell utilities do. Sysmon for Linux sees every
start. This keeps one row per distinct (image path, SHA-256) that has started,
with its first and last sighting and a count, written by the incremental
sysmon_linux pass from the events it already parses. The /procs identity check
(web/procidentity.py) asks it "has this exact program run here before?".

Windows needs no table of its own: the event log index already records the
first sighting of every started image and hash (core/eventlog.py, sightings).

Invariants:

  * Metadata only: image path, hash, base name and times. Never a command line,
    user, working directory or parent.
  * Bounded: at most MAX_ROWS rows; the least recently seen are dropped first.
    Measured 2026-10-24: ~4,800 starts an hour, ~115 distinct images.
  * Honest about its age: `since()` is when recording began. Until it is
    RECENT_S old, "not in the history" means "not known", not "never ran".
  * Written only by the scheduled incremental pass, so a manual 24-hour audit
    never counts the same starts twice.
"""

import os

from jarvis.core.util import now

HOST = "wsl"
MAX_ROWS = 50_000
SINCE_KEY = "start_history_since"

DDL = """
CREATE TABLE IF NOT EXISTS start_images (
    host        TEXT NOT NULL,
    image       TEXT NOT NULL,
    sha256      TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL DEFAULT '',
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (host, image, sha256)
);
CREATE INDEX IF NOT EXISTS start_images_sha ON start_images(sha256);
CREATE INDEX IF NOT EXISTS start_images_seen ON start_images(last_seen);
"""


def ensure(db):
    db.executescript(DDL)


def starts(events, at_of):
    """(image, sha256, name, unix time) for each process start in parsed events."""
    out = []
    for e in events:
        if e.get("id") != 1:
            continue
        image = (e.get("Image") or "").strip()
        if not image or image == "-":
            continue
        sha = ""
        for part in (e.get("Hashes") or "").split(","):
            key, _, value = part.partition("=")
            if key.strip().upper() == "SHA256" and len(value.strip()) == 64:
                sha = value.strip().lower()
        out.append((image, sha, os.path.basename(image), int(at_of(e) or now())))
    return out


def record(store, events, at_of):
    """Fold one pass's starts into the history; returns how many were recorded."""
    rows = starts(events, at_of)
    db = store.db
    ensure(db)
    if store.get_meta(SINCE_KEY) is None:
        store.set_meta(SINCE_KEY, now())
    db.executemany(
        "INSERT INTO start_images(host, image, sha256, name, first_seen, last_seen, count) "
        "VALUES(?,?,?,?,?,?,1) ON CONFLICT(host, image, sha256) DO UPDATE SET "
        "first_seen=min(first_seen, excluded.first_seen), last_seen=max(last_seen, excluded.last_seen), "
        "count=count+1",
        [(HOST, image, sha, name, at, at) for image, sha, name, at in rows])
    extra = db.execute("SELECT count(*) FROM start_images").fetchone()[0] - MAX_ROWS
    if extra > 0:
        db.execute("DELETE FROM start_images WHERE rowid IN "
                   "(SELECT rowid FROM start_images ORDER BY last_seen LIMIT ?)", (extra,))
    store.commit()
    return len(rows)
