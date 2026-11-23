"""Bulk indicator feeds: volume that search cannot buy.

intel.py reads security writeups, which is the only way to learn *tradecraft* —
the path a rootkit drops, the unit file it installs, the technique it uses.
What writeups cannot give is coverage: a single article names a handful of
hashes, and paying a search API per document to accumulate tens of thousands of
them costs real money for data that is published free.

So the two halves are split by what each is actually good at:

    intel.py   narrative  ->  paths, filenames, techniques, persistence
    feeds.py   bulk       ->  hashes, domains, addresses, ranges, CVEs

Every feed here is public, unauthenticated, and refreshed by its publisher on
its own schedule — ThreatFox and URLhaus update continuously, CISA KEV when a
vulnerability starts being exploited, MITRE ATT&CK on release. Together they
put the knowledge base well past fifty thousand live records at no cost.

Feed data is more trustworthy than an extraction from prose: these are curated,
attributed, and confirmed-malicious. It is still not trusted. Everything goes
through the same vet.py gate, because a feed can carry a defanged placeholder
or a private address just as easily, and because the invariant that intel may
only ever ADD suspicion has to hold for every source without exception.
"""

import csv
import io
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from jarvis.core import inflate, paths, vet
from jarvis.core.util import now

UA = "jarvis-feeds/1.0 (+local host monitoring)"

# name -> (url, parser, interval_seconds, description)
FEEDS = {}


def feed(name, url, interval, desc, max_bytes=64 * 1024 * 1024):
    def wrap(fn):
        FEEDS[name] = {"url": url, "parse": fn, "interval": interval,
                       "desc": desc, "max_bytes": max_bytes}
        return fn
    return wrap


# Largest feed measured inflated: 76 MB (bazaar-full, 2026-10). Twice that, and
# small enough for the server edition's 768 MB MemoryHigh to survive parsing.
MAX_INFLATED = 160 * 1024 * 1024


# abuse.ch has required a free account Auth-Key on its exports since
# 2025-06-30; without one URLhaus, ThreatFox and MalwareBazaar answered
# "410 Gone" here from 2026-10-21 while the job still read complete.
ABUSECH_KEY_ENV = "ABUSECH_AUTH_KEY"
ABUSECH_KEY_CONF = "abuse_ch_auth_key"


def abusech_key():
    """The owner's abuse.ch Auth-Key, or "". Never logged or echoed."""
    key = os.environ.get(ABUSECH_KEY_ENV, "").strip()
    if key:
        return key
    try:
        with open(paths.CONFIG_PATH, encoding="utf-8", errors="replace") as fh:
            conf = json.load(fh) or {}
        return str(conf.get(ABUSECH_KEY_CONF) or "").strip() if isinstance(conf, dict) else ""
    except (OSError, ValueError):
        return ""


def _is_abusech_url(url):
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    return host == "abuse.ch" or host.endswith(".abuse.ch")


def is_abusech(name):
    """Whether a scheduled feed is served by abuse.ch (needs the Auth-Key)."""
    return _is_abusech_url((FEEDS.get(name) or {}).get("url", ""))


# Since 2026-10-21 abuse.ch serves exports only from {platform}-api.abuse.ch with the
# Auth-Key in the path (the old export URLs answer 410 Gone with no forwarding
# address; verified with a real key on 2026-11-04). The feed table keeps the
# placeholder: the key is filled in for the request only, so it never reaches the
# feed registry, the indicators' source_url, feed_runs errors or the dashboard.
KEY_SLOT = "{auth_key}"
WRITE_CHUNK = 2000          # indicators per commit (see ingest)
WRITE_PAUSE_S = 0.05        # between commits, so other writers get the lock


def abusech_export(platform, filename):
    return f"https://{platform}-api.abuse.ch/v2/files/exports/{KEY_SLOT}/{filename}"


def _resolve(url):
    """(url to request, key to scrub from errors). ValueError when a keyed URL has no key."""
    if KEY_SLOT not in url:
        return url, ""
    key = abusech_key()
    if not key:
        raise ValueError("abuse.ch Auth-Key not set: add abuse_ch_auth_key to the config "
                         f"(or {ABUSECH_KEY_ENV}); free at https://auth.abuse.ch/")
    return url.replace(KEY_SLOT, urllib.parse.quote(key, safe="")), key


def _auth_headers(url):
    if _is_abusech_url(url):
        key = abusech_key()
        return {"Auth-Key": key} if key else {}
    return {}


def fetch(url, max_bytes, timeout=180, max_inflated=MAX_INFLATED):
    """Download and transparently decompress. The full abuse.ch dumps ship as
    zip archives that expand roughly sevenfold, so the inflated size is capped
    separately from the download — otherwise a feed changing shape upstream
    could exhaust memory on a machine this is supposed to be protecting.
    Both layers count the bytes they produce (core/inflate.py): neither a gzip
    bomb nor a zip header that understates its size gets past the cap."""
    real, key = _resolve(url)
    headers = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "gzip"}
    if not key:
        headers.update(_auth_headers(url))
    req = urllib.request.Request(real, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise ValueError(f"feed exceeds {max_bytes} bytes")
            if resp.headers.get("Content-Encoding") == "gzip" or raw[:2] == b"\x1f\x8b":
                raw = inflate.gunzip(raw, max_inflated)
    except Exception as exc:
        # The key is in the request path: no error text may carry it onward.
        if key and key in str(exc):
            raise ValueError(str(exc).replace(key, "<abuse.ch key>")) from None
        raise
    if raw[:2] == b"PK":
        raw = inflate.zip_first_member(raw, max_inflated)
    return raw


def _host(value):
    """Hostname out of a URL or host:port, or "" if there isn't one."""
    v = (value or "").strip().strip('"')
    v = re.sub(r"^[a-z0-9+.-]+://", "", v, flags=re.I)
    v = v.split("/")[0].split("?")[0]
    if v.count(":") == 1:
        v = v.split(":")[0]
    return v.strip("[]").lower()


def _rows(raw):
    """Iterate a commented CSV the way abuse.ch publishes them."""
    text = raw.decode("utf-8", "replace")
    body = "\n".join(l for l in text.splitlines()
                     if l.strip() and not l.lstrip().startswith("#"))
    return csv.reader(io.StringIO(body), skipinitialspace=True)


# ── the feeds ─────────────────────────────────────────────────────────────

@feed("threatfox", abusech_export("threatfox", "recent.csv"), 3600,
      "abuse.ch ThreatFox — current C2 infrastructure, updated continuously")
def _threatfox(raw):
    out = []
    for row in _rows(raw):
        if len(row) < 9:
            continue
        value, ioc_type, family = row[2], row[3], (row[7] or "").strip()
        try:
            conf = int(row[9]) if len(row) > 9 and row[9].strip().isdigit() else 50
        except (ValueError, IndexError):
            conf = 50
        if conf < 50:
            continue                    # low-confidence entries are not worth the noise
        if ioc_type in ("url", "domain"):
            out.append(("domain", _host(value), family))
        elif ioc_type in ("ip:port", "ip"):
            out.append(("ipv4", _host(value), family))
        elif ioc_type == "sha256_hash":
            out.append(("sha256", value.strip(), family))
    return out


@feed("malwarebazaar", abusech_export("mb", "sha256_recent.txt"), 3600,
      "abuse.ch MalwareBazaar — SHA-256 of recently submitted samples")
def _bazaar(raw):
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip().strip('"')
        if line and not line.startswith("#"):
            out.append(("sha256", line, ""))
    return out


@feed("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.json", 3600,
      "abuse.ch Feodo Tracker — botnet C2 servers")
def _feodo(raw):
    out = []
    for item in json.loads(raw.decode("utf-8", "replace")):
        if isinstance(item, dict) and item.get("ip_address"):
            out.append(("ipv4", item["ip_address"], item.get("malware") or ""))
    return out


@feed("urlhaus", abusech_export("urlhaus", "recent.csv"), 3600,
      "abuse.ch URLhaus — hosts serving malware payloads")
def _urlhaus(raw):
    out = []
    for row in _rows(raw):
        if len(row) < 3:
            continue
        host = _host(row[2])
        if not host:
            continue
        tag = row[5] if len(row) > 5 else ""
        kind = "ipv4" if re.match(r"^\d+\.\d+\.\d+\.\d+$", host) else "domain"
        out.append((kind, host, tag))
    return out


@feed("openphish", "https://openphish.com/feed.txt", 10800,
      "OpenPhish — live phishing hosts")
def _openphish(raw):
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        host = _host(line)
        if host and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            out.append(("domain", host, "phishing"))
    return out


@feed("et-compromised",
      "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", 10800,
      "Emerging Threats — currently compromised hosts")
def _et(raw):
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(("ipv4", line, "compromised host"))
    return out


@feed("spamhaus-drop", "https://www.spamhaus.org/drop/drop.txt", 86400,
      "Spamhaus DROP — networks under criminal control")
def _drop(raw):
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith((";", "#")):
            continue
        out.append(("cidr", line.split(";")[0].strip(), "hijacked network"))
    return out


@feed("cisa-kev",
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      86400, "CISA KEV — vulnerabilities known to be exploited in the wild")
def _kev(raw):
    data = json.loads(raw.decode("utf-8", "replace"))
    out = []
    for v in data.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").strip()
        if cve:
            label = f"{v.get('vendorProject','')} {v.get('product','')}".strip()
            out.append(("cve", cve, label[:120]))
    return out




# ── full historical dumps ─────────────────────────────────────────────────
# The "recent" endpoints above keep the picture current; these carry the depth.
# They are large, so they refresh daily rather than hourly.

@feed("bazaar-full", abusech_export("mb", "sha256_full.txt.zip"), 86400,
      "abuse.ch MalwareBazaar — full sample corpus",
      max_bytes=48 * 1024 * 1024)
def _bazaar_full(raw):
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip().strip('"')
        if line and not line.startswith("#"):
            out.append(("sha256", line, ""))
    return out


@feed("threatfox-full", abusech_export("threatfox", "full.csv.zip"), 86400,
      "abuse.ch ThreatFox — full C2 corpus", max_bytes=32 * 1024 * 1024)
def _threatfox_full(raw):
    return _threatfox(raw)


@feed("urlhaus-full", abusech_export("urlhaus", "full.csv.zip"), 86400,
      "abuse.ch URLhaus — full payload-host corpus",
      max_bytes=32 * 1024 * 1024)
def _urlhaus_full(raw):
    return _urlhaus(raw)


@feed("ipsum", "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
      86400, "IPsum — addresses appearing on multiple public blocklists")
def _ipsum(raw):
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2 or not parts[1].isdigit():
            continue
        # The second column is how many independent blocklists carry it. One
        # list alone is too often a scanner or a stale entry; two is a claim
        # with corroboration.
        if int(parts[1]) < 2:
            continue
        out.append(("ipv4", parts[0], f"on {parts[1]} blocklists"))
    return out


@feed("blocklist-de", "https://lists.blocklist.de/lists/all.txt", 10800,
      "blocklist.de — hosts observed attacking public services")
def _blocklist_de(raw):
    return [("ipv4", l.strip(), "attacking host")
            for l in raw.decode("utf-8", "replace").splitlines()
            if l.strip() and not l.startswith("#")]


@feed("cins", "https://cinsscore.com/list/ci-badguys.txt", 10800,
      "CINS Army — poor-reputation addresses")
def _cins(raw):
    return [("ipv4", l.strip(), "poor reputation")
            for l in raw.decode("utf-8", "replace").splitlines()
            if l.strip() and not l.startswith("#")]


@feed("binarydefense", "https://www.binarydefense.com/banlist.txt", 10800,
      "Binary Defense — artillery threat intelligence banlist")
def _bindef(raw):
    return [("ipv4", l.strip(), "banlist")
            for l in raw.decode("utf-8", "replace").splitlines()
            if l.strip() and not l.startswith("#")]


def _attack(raw, store):
    """MITRE ATT&CK is a catalogue, not a list of indicators — it gets a table."""
    data = json.loads(raw.decode("utf-8", "replace"))
    rows, ts = [], now()
    for obj in data.get("objects", []):
        # Revoked and deprecated entries are techniques MITRE has retired or
        # folded into others; nothing can cover them and they are not counted.
        if (obj.get("type") != "attack-pattern" or obj.get("revoked")
                or obj.get("x_mitre_deprecated")):
            continue
        tid = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id", "")
                break
        if not tid:
            continue
        tactics = ",".join(p.get("phase_name", "")
                           for p in obj.get("kill_chain_phases", []))
        rows.append((tid, obj.get("name", "")[:200], tactics,
                     ",".join(obj.get("x_mitre_platforms", []) or [])[:200], ts))
    store.db.executemany(
        """INSERT INTO attack_techniques(tid,name,tactics,platforms,updated)
           VALUES(?,?,?,?,?)
           ON CONFLICT(tid) DO UPDATE SET name=excluded.name,
               tactics=excluded.tactics, platforms=excluded.platforms,
               updated=excluded.updated""", rows)
    if len(rows) >= ATTACK_MIN_ROWS:
        # Rows this load did not refresh were retired upstream. Only a load
        # large enough to be the whole catalogue may remove anything: a
        # truncated download must not empty the table.
        store.db.execute("DELETE FROM attack_techniques WHERE updated < ?", (ts,))
    store.commit()
    return len(rows)


# The enterprise catalogue has about 700 live techniques and sub-techniques.
ATTACK_MIN_ROWS = 400


ATTACK_URL = ("https://raw.githubusercontent.com/mitre/cti/master/"
              "enterprise-attack/enterprise-attack.json")


# ── ingestion ─────────────────────────────────────────────────────────────

def ingest(store, name, spec, max_rows=250000):
    """Fetch one feed, vet every row, and upsert the survivors in one batch."""
    started = time.time()
    try:
        raw = fetch(spec["url"], spec["max_bytes"])
    except (urllib.error.URLError, urllib.error.HTTPError, OSError,
            ValueError, TimeoutError) as exc:
        store.db.execute(
            """INSERT INTO feed_runs(name,last_run,rows,kept,bytes,error)
               VALUES(?,?,0,0,0,?)
               ON CONFLICT(name) DO UPDATE SET last_run=excluded.last_run,
                   error=excluded.error""", (name, now(), str(exc)[:200]))
        store.commit()
        return {"name": name, "error": str(exc)[:200], "rows": 0, "kept": 0}

    try:
        parsed = spec["parse"](raw)
    except Exception as exc:
        error = f"parse failed: {exc}"[:200]
        store.db.execute(
            """INSERT INTO feed_runs(name,last_run,rows,kept,bytes,error)
               VALUES(?,?,0,0,0,?)
               ON CONFLICT(name) DO UPDATE SET last_run=excluded.last_run,
                   error=excluded.error""", (name, now(), error))
        store.commit()
        return {"name": name, "error": error, "rows": 0, "kept": 0}

    ts = now()
    batch, seen, rejected = [], set(), 0
    for kind, value, family in parsed[:max_rows]:
        norm, _why = vet.vet(kind, value)
        if not norm:
            rejected += 1
            continue
        key = (kind, norm)
        if key in seen:
            continue
        seen.add(key)
        batch.append((kind, str(value)[:512], norm, "high", name,
                      (family or "")[:120], (family or "")[:200],
                      spec["url"], ts, ts, name))

    sql = """INSERT INTO indicators(kind,value,norm,confidence,topic,context,
                                    malware,source_url,first_seen,last_seen,source)
             VALUES(?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(kind,norm) DO UPDATE SET
                 last_seen=excluded.last_seen,
                 status='active',
                 doc_count=indicators.doc_count+1"""
    # Small commits with a breath between them: each one holds SQLite's single
    # write lock, and on 2026-11-05 20 000-row commits into the 900 MB store held
    # it past the 10 s busy timeout, so other writers failed ("database is
    # locked") and three scheduler lanes died. Readers are never blocked (WAL).
    for i in range(0, len(batch), WRITE_CHUNK):
        store.db.executemany(sql, batch[i:i + WRITE_CHUNK])
        store.commit()
        time.sleep(WRITE_PAUSE_S)
    store.db.execute(
        """INSERT INTO feed_runs(name,last_run,rows,kept,bytes,error)
           VALUES(?,?,?,?,?,'')
           ON CONFLICT(name) DO UPDATE SET last_run=excluded.last_run,
               rows=excluded.rows, kept=excluded.kept, bytes=excluded.bytes,
               error=''""",
        (name, ts, len(parsed), len(batch), len(raw)))
    store.commit()
    return {"name": name, "rows": len(parsed), "kept": len(batch),
            "rejected": rejected, "bytes": len(raw),
            "secs": round(time.time() - started, 1)}


def refresh(store, names=None, force=False, on_progress=None):
    """Run every feed that is due (or all of them, with force)."""
    results = []
    targets = names or list(FEEDS)
    for name in targets:
        spec = FEEDS.get(name)
        if not spec:
            continue
        if not force:
            row = store.db.execute(
                "SELECT last_run FROM feed_runs WHERE name=?", (name,)).fetchone()
            if row and now() - row["last_run"] < spec["interval"]:
                continue
        if on_progress:
            on_progress(name, spec["desc"])
        results.append(ingest(store, name, spec))
    return results


def refresh_attack(store, force=False):
    """Refresh the ATT&CK catalogue. Large and slow-moving, so monthly."""
    row = store.db.execute(
        "SELECT last_run FROM feed_runs WHERE name='attack'").fetchone()
    if row and not force and now() - row["last_run"] < 30 * 86400:
        return {"name": "attack", "skipped": True}
    try:
        raw = fetch(ATTACK_URL, 96 * 1024 * 1024, timeout=240)
        n = _attack(raw, store)
    except Exception as exc:
        return {"name": "attack", "error": str(exc)[:200]}
    store.db.execute(
        """INSERT INTO feed_runs(name,last_run,rows,kept,bytes,error)
           VALUES('attack',?,?,?,?,'')
           ON CONFLICT(name) DO UPDATE SET last_run=excluded.last_run,
               rows=excluded.rows, kept=excluded.kept, bytes=excluded.bytes,
               error=''""", (now(), n, n, len(raw)))
    store.commit()
    return {"name": "attack", "kept": n, "bytes": len(raw)}


def failing(store):
    """{feed: error} for every scheduled feed whose last attempt failed.

    A feed is retried once per interval, so the run that saw the failure is
    the only one that would mention it; this reads the persisted state so
    every run reports it until a fetch succeeds."""
    names = set(FEEDS) | {"attack", "tranco"}
    return {r["name"]: r["error"] for r in store.db.execute(
        "SELECT name, error FROM feed_runs WHERE error != ''")
        if r["name"] in names}


def prune(store, days=90):
    """Retire feed indicators the publisher has stopped listing.

    C2 infrastructure is rented and recycled; an address that dropped off every
    feed three months ago is far more likely to be someone else's server now
    than to still be a threat. Writeup-derived indicators are never pruned —
    a malware sample's hash is true forever.
    """
    cutoff = now() - days * 86400
    cur = store.db.execute(
        "UPDATE indicators SET status='retired' "
        "WHERE source!='exa' AND status='active' AND last_seen < ?", (cutoff,))
    store.commit()
    return cur.rowcount


def status(store):
    rows = store.db.execute(
        "SELECT * FROM feed_runs ORDER BY name").fetchall()
    return [dict(r) for r in rows]


TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


def refresh_tranco(store, force=False):
    """Weekly Tranco ranking for core.warninglist, the popular-domain filter."""
    from jarvis.core import warninglist
    row = store.db.execute(
        "SELECT last_run FROM feed_runs WHERE name='tranco'").fetchone()
    if row and not force and now() - row["last_run"] < 7 * 86400:
        return {"name": "tranco", "skipped": True}
    try:
        raw = fetch(TRANCO_URL, 32 * 1024 * 1024, timeout=240)
        rows = []
        for line in raw.decode("utf-8", "replace").splitlines()[:warninglist.KEEP]:
            rank, _, domain = line.partition(",")
            if rank.isdigit() and domain:
                rows.append((domain.strip().lower(), int(rank)))
        if len(rows) < warninglist.KEEP // 2:
            raise ValueError(f"only {len(rows)} ranked domains")
    except Exception as exc:
        return {"name": "tranco", "error": str(exc)[:200]}
    warninglist.store_ranking(store, rows)
    store.db.execute(
        """INSERT INTO feed_runs(name,last_run,rows,kept,bytes,error)
           VALUES('tranco',?,?,?,?,'')
           ON CONFLICT(name) DO UPDATE SET last_run=excluded.last_run,
               rows=excluded.rows, kept=excluded.kept, bytes=excluded.bytes, error=''""",
        (now(), len(rows), len(rows), len(raw)))
    store.commit()
    return {"name": "tranco", "kept": len(rows), "bytes": len(raw)}
