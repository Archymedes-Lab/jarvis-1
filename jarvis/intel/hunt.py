"""Evaluate stored indicators against what is actually on this machine.

research.py answers "what is being used against machines like this one?".
This module answers the only question that matters: "is any of it here?"

Every check is a comparison against state jarvis already collects — the process
baseline, the peer table, the filesystem — so a hunt costs almost nothing and
can run often. Indicators are compared as opaque data: never executed, never
interpolated into a shell, never used to build a command.

False positives are the failure mode that kills a tool like this, so matching
is exact and a second local check runs before anything is reported:

  * a path that exists is only reported if the package manager does not own it
  * a process name must match exactly, not as a substring
  * a hash match is reported at critical because a 256-bit collision is not a
    false positive

The ATT&CK side is different in kind and lives in gaps.py.
"""

import ipaddress
import json
import os
import time

from jarvis.collectors.process.detect import TRUSTED_PATHS
from jarvis.core import vet, warninglist
from jarvis.core.finding import finding as _finding
from jarvis.core.util import dpkg_owns, now
from jarvis.platform import host as machine
from jarvis.platform.windows import ps_json, stdin_text


def _win_to_wsl(path):
    """C:\\Users\\x as this process names it, so Windows paths are checkable from here."""
    p = path.replace("\\", "/")
    if len(p) > 2 and p[1] == ":" and p[2] == "/":
        return machine.local_path(path) or None
    return None


_dpkg_owns = dpkg_owns


def _sha256(path, cap=256 * 1024 * 1024):
    import hashlib
    try:
        if os.path.getsize(path) > cap:
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, ValueError):
        return ""


def _hash_cached(store, path):
    """Hash a file, reusing the stored digest while size and mtime are unchanged."""
    try:
        st = os.stat(path)
    except OSError:
        return ""
    row = store.db.execute(
        "SELECT sha256,size,mtime FROM file_hashes WHERE path=?", (path,)
    ).fetchone()
    if row and row["size"] == st.st_size and row["mtime"] == int(st.st_mtime):
        return row["sha256"]
    digest = _sha256(path)
    if digest:
        store.db.execute(
            """INSERT INTO file_hashes(path,sha256,size,mtime,hashed_at)
               VALUES(?,?,?,?,?)
               ON CONFLICT(path) DO UPDATE SET
                   sha256=excluded.sha256, size=excluded.size,
                   mtime=excluded.mtime, hashed_at=excluded.hashed_at""",
            (path, digest, st.st_size, int(st.st_mtime), now()))
    return digest


def _active(store, kind):
    return store.db.execute(
        "SELECT norm, value, source_url, context, doc_count, confidence, source FROM indicators "
        "WHERE kind=? AND status='active'", (kind,)).fetchall()


# ── the checks ────────────────────────────────────────────────────────────

# One finding per (process, host) for listed peers, not one per peer. A
# peer-to-peer client talks to hundreds of listed residential addresses a
# day; on 2026-10-21 that was 232 of 251 criticals and 232 block proposals,
# which buried every other critical (PROTECTION-REVIEW F4). The worst
# severity and feed still decide the finding; the count and a sample of
# addresses stay in the detail; a process with one listed peer reads as before.
# Flagged-network (Spamhaus DROP) hits fold into the same per-process finding.
PEER_SAMPLE = 5
# A process with a handful of listed peers keeps one finding per peer: a
# genuine command-and-control contact is usually one or two addresses, and
# must not be folded into a count. Only a peer-to-peer volume collapses.
PEER_SINGLE_THRESHOLD = 5


# Feeds that list addresses seen attacking or scanning others (reputation),
# as opposed to malware command-and-control and payload infrastructure
# (ThreatFox, Feodo, URLhaus).
ATTACK_SOURCE_FEEDS = frozenset({"blocklist-de", "cins", "binarydefense", "ipsum"})

# Shared, reassigned infrastructure of the largest providers: one address
# serves many tenants and changes hands, so a blocklist entry for it may be
# about someone else entirely. Measured: firefox to 142.251.38.238 (Google,
# 1e100.net) and 35.190.43.134 (Google Cloud) listed as attack sources
# (QC-ARGUS-1-2026-10-27). A hit here stays listed, at medium, and says why.
# Only ranges the provider itself publishes as Google / Google Cloud
# (goog.json, cloud.json); add a provider only from its own published list.
SHARED_PROVIDER_IPV4 = tuple(ipaddress.ip_network(v) for v in (
    "8.8.4.0/24", "8.8.8.0/24", "34.64.0.0/10", "35.184.0.0/13", "35.192.0.0/12",
    "35.208.0.0/12", "35.224.0.0/12", "35.240.0.0/13", "64.233.160.0/19",
    "66.102.0.0/20", "66.249.64.0/19", "72.14.192.0/18", "74.125.0.0/16",
    "108.177.0.0/17", "142.250.0.0/15", "172.217.0.0/16", "172.253.0.0/16",
    "173.194.0.0/16", "209.85.128.0/17", "216.58.192.0/19", "216.239.32.0/19",
))
SHARED_PROVIDER = "Google / Google Cloud"

# A blocklist entry is one source's claim about an address. It is critical
# only with a second, independent signal (ALERT-QUALITY-2026-11-08); alone,
# a command-and-control listing is high (still listed, still a threat-area
# page), a reputation listing medium.
LONE_C2_SEVERITY = "high"
DROP_FOLDERS = ("/temp/", "/tmp/", "/downloads/")
# Beacon-shaped contact: the same process reached the same listed address
# and port in at least this many samples spread over at least this long. Not
# counted for a process with peer-to-peer volume (more than
# PEER_SINGLE_THRESHOLD listed peers), whose swarm members recur by design.
REPEAT_MIN_SAMPLES = 3
REPEAT_MIN_SPAN_S = 3600


def shared_provider(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and any(addr in n for n in SHARED_PROVIDER_IPV4)


def _process_signals(store, exe, cache):
    """Signals about the process itself, independent of any address list:
    its image sits in a temp or download folder, or its cached digest matches
    a known malware sample. Read from what jarvis already holds; nothing is
    hashed here."""
    exe = exe or ""
    if exe in cache:
        return cache[exe]
    out = []
    norm = exe.lower().replace("\\", "/")
    if norm and any(d in norm for d in DROP_FOLDERS):
        out.append("its image runs from a temp or download folder")
    if norm:
        try:
            row = store.db.execute(
                "SELECT i.malware m FROM file_hashes h JOIN indicators i "
                "ON i.kind='sha256' AND i.norm=h.sha256 AND i.status='active' "
                "WHERE h.path=? LIMIT 1", (exe,)).fetchone()
        except Exception:
            row = None
        if row is not None:
            out.append("its image matches a known malware sample")
    cache[exe] = out
    return out


def grade_ip_hit(feed, confidence, ip, process_signals=(), in_flagged_network=False):
    """(severity, qualifier, reasons) for one address-list hit.

    Pure, so the policy is testable and replayable. Severity never rises on
    one list alone: a lone command-and-control listing is high; critical needs
    an independent signal (about the process, its beacon-shaped repeated
    contact, or a second provider's listing of the address); shared provider infrastructure and reputation lists are
    medium. `reasons` names whatever corroborated or capped it."""
    corroboration = list(process_signals)
    if in_flagged_network:
        corroboration.append("the address is also inside a Spamhaus DROP network")
    shared = ([f"shared {SHARED_PROVIDER} address; the listing may concern another tenant"]
              if shared_provider(ip) else [])
    if feed in ATTACK_SOURCE_FEEDS:
        # Reputation lists record hosts seen attacking or scanning others;
        # shared and reassigned cloud addresses land there (Google and
        # Microsoft addresses did, 2026-10-30). Reaching one is worth
        # knowing, not proof of an attacker.
        return "medium", "reported attack source", shared + corroboration
    if shared:
        return "medium", "threat-intelligence", shared + corroboration
    if confidence != "high":
        return "medium", "threat-intelligence", corroboration
    if corroboration:
        return "critical", "known attacker", corroboration
    return LONE_C2_SEVERITY, "listed command-and-control", [
        "one list only, no second signal"]


_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def collapse_peer_hits(hits):
    groups = {}
    for h in hits:
        groups.setdefault((h["pname"], h["host"]), []).append(h)
    out = []
    for (pname, host), rows in sorted(groups.items()):
        rows = sorted(rows, key=lambda h: (_RANK.get(h["severity"], 9), h["ip"]))
        worst = rows[0]
        if len(rows) <= PEER_SINGLE_THRESHOLD:
            for h in rows:                      # one finding per listed peer, as before
                why = "; ".join(h.get("reasons") or ())
                if h.get("network"):
                    title = f"contacted a host in a flagged network: {h['network']}"
                    detail = f"{pname} \u2192 {h['ip']}:{h['port']} \u2014 {h['label']}"
                else:
                    title = f"contacted a {h['qualifier']} IP: {h['ip']}"
                    detail = (f"{pname} \u2192 {h['ip']}:{h['port']} \u2014 {h['label']} "
                              f"(via {h['feed']})")
                out.append(_finding("c2 match", h["severity"], title,
                                    detail + (f" \u2014 {why}" if why else ""),
                                    h["src"], host))
            continue
        # Count addresses, not rows: one address reached on several ports or
        # by several instances is one listed peer, graded by its worst hit.
        per_ip = {}
        for h in rows:                          # rows are worst-first
            per_ip.setdefault(h["ip"], h)
        ips = list(per_ip.values())
        crit = sum(1 for h in ips if h["severity"] == "critical")
        feeds = sorted({h["feed"] for h in rows})
        sample = ", ".join(f"{h['ip']}:{h['port']}" for h in ips[:PEER_SAMPLE])
        by_sev = ", ".join(f"{n} {s}" for s, n in (
            (s, sum(1 for h in ips if h["severity"] == s)) for s in _RANK) if n)
        why = "; ".join(worst.get("reasons") or ())
        out.append(_finding(
            "c2 match", worst["severity"],
            f"{pname} contacted {len(ips)} listed IPs ({crit} corroborated)",
            f"{pname} on {host} reached {len(ips)} addresses on threat lists "
            f"(via {', '.join(feeds)}; {by_sev}); e.g. {sample}"
            + (" \u2026" if len(ips) > PEER_SAMPLE else "")
            + (f". Worst: {worst['ip']} \u2014 {why}" if why else "")
            + ". A peer-to-peer client does this by design; anything else should not. "
              "Each address can still be blocked individually with jarvis defend.",
            worst["src"], host))
    return out


def check_peers(store):
    """Do any recorded network peers match attacker infrastructure?

    Written as indexed joins rather than by loading indicators into Python.
    At a few thousand records the difference is invisible; at half a million it
    is the difference between a hunt that runs every half hour and one that
    reads a hundred megabytes into memory to answer a question SQLite can
    answer from an index.
    """
    out = []
    peer_hits = []
    signals_cache = {}

    # Ranges cannot be indexed by value, so they are bucketed by first octet.
    # A peer then only has to be tested against the handful of networks that
    # could possibly contain it instead of all of them.
    buckets = {}
    for r in _active(store, "cidr"):
        try:
            net = ipaddress.ip_network(r["norm"])
        except ValueError:
            continue
        if net.version != 4:
            continue
        first = int(str(net.network_address).split(".")[0])
        buckets.setdefault(first, []).append((net, r))

    def flagged_network(ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.version != 4:
            return None
        for net, hit in buckets.get(int(str(addr).split(".")[0]), ()):
            if addr in net:
                return net, hit
        return None

    # Addresses: one join, served entirely from the (kind, norm) unique index.
    raw = []
    for r in store.db.execute(
            """SELECT p.remote_ip ip, p.remote_port port, p.host host,
                      p.seen_count seen, p.first_seen first, p.last_seen last,
                      pr.name pname, pr.exe exe, i.context ctx, i.source_url src,
                      i.malware fam, i.source feed, i.confidence confidence
                 FROM peers p
                 JOIN indicators i
                   ON i.kind='ipv4' AND i.norm = p.remote_ip
                      AND i.status='active'
                LEFT JOIN procs pr ON pr.fp = p.fp
                WHERE p.scope='public'"""):
        # Re-vet at match time as well as ingestion time. The corpus is
        # persistent, so a newly learned shared-infrastructure exclusion must
        # take effect immediately rather than waiting for a manual re-vet.
        if not vet.vet_ipv4(r["ip"])[0]:
            continue
        raw.append(dict(r))
    listed = {}
    for r in raw:
        listed.setdefault((r["pname"], r["host"]), set()).add(r["ip"])
    for r in raw:
        signals = list(_process_signals(store, r["exe"], signals_cache))
        seen, span = int(r["seen"] or 0), int(r["last"] or 0) - int(r["first"] or 0)
        if (seen >= REPEAT_MIN_SAMPLES and span >= REPEAT_MIN_SPAN_S
                and len(listed[(r["pname"], r["host"])]) <= PEER_SINGLE_THRESHOLD):
            signals.append(f"the same process reached it repeatedly ({seen} samples "
                           f"over {span // 3600} h), not as one of a peer-to-peer swarm")
        label = r["fam"] or r["ctx"] or "listed in threat intelligence"
        severity, qualifier, reasons = grade_ip_hit(
            r["feed"], r["confidence"], r["ip"], signals,
            in_flagged_network=flagged_network(r["ip"]) is not None)
        peer_hits.append({"ip": r["ip"], "port": r["port"], "pname": r["pname"] or "unknown process",
                          "label": label, "feed": r["feed"], "src": r["src"], "host": r["host"],
                          "severity": severity, "qualifier": qualifier, "reasons": reasons})

    # Flagged networks (Spamhaus DROP): one list's claim about a whole range,
    # so high at most; collapsed per process with the address hits above.
    if buckets:
        for p in store.db.execute(
                """SELECT p.remote_ip ip, p.remote_port port, p.host host,
                          pr.name pname FROM peers p
                     LEFT JOIN procs pr ON pr.fp = p.fp
                    WHERE p.scope='public'"""):
            m = flagged_network(p["ip"])
            if not m:
                continue
            net, hit = m
            shared = shared_provider(p["ip"])
            peer_hits.append({
                "ip": p["ip"], "port": p["port"], "pname": p["pname"] or "unknown process",
                "label": hit["context"] or "listed range", "feed": hit["source"] or "range",
                "src": hit["source_url"], "host": p["host"],
                "severity": "medium" if shared else "high", "qualifier": "flagged network",
                "network": str(net),
                "reasons": ([f"shared {SHARED_PROVIDER} address"] if shared else [])})
    out.extend(collapse_peer_hits(peer_hits))

    # Domains: exact reverse-DNS match, then parent domains. Only the distinct
    # rdns values are walked, and each parent is a single index probe, so this
    # stays a few thousand lookups no matter how large the indicator set is.
    rdns_rows = store.db.execute(
        "SELECT DISTINCT rdns FROM peers WHERE scope='public' AND rdns != ''"
    ).fetchall()
    matched = {}
    for row in rdns_rows:
        host = (row["rdns"] or "").lower().rstrip(".")
        m = warninglist.match_domain(store, host)
        if m:
            matched[host] = m
    for host, m in matched.items():
        parent, hit, severity, qualifier = m["indicator"], m["hit"], m["severity"], m["qualifier"]
        if severity == "critical":
            # A peer's reverse-DNS name on one domain list is the same single
            # claim as an address listing: high without a second signal.
            severity, qualifier = LONE_C2_SEVERITY, "listed command-and-control"
        for p in store.db.execute(
                """SELECT p.remote_ip ip, p.remote_port port, p.host host,
                          pr.name pname FROM peers p
                     LEFT JOIN procs pr ON pr.fp = p.fp
                    WHERE p.scope='public' AND lower(p.rdns) LIKE ?""",
                (host + "%",)):
            label = hit["malware"] or hit["context"] or "listed in threat intelligence"
            out.append(_finding(
                "c2 match", severity,
                f"contacted a {qualifier} domain: {parent}",
                f"{p['pname'] or 'unknown process'} → {host} "
                f"({p['ip']}:{p['port']}) — {label} (via {hit['source']})",
                hit["source_url"], p["host"]))
    return out


# Directories under C:\Windows that any user or service can write to. A
# Microsoft-signed binary sitting in one of these is still a drop — attackers
# bring signed hosts along to sideload from — so a signature does not clear it.
_WIN_WRITABLE = ("c:/windows/temp/", "c:/windows/tasks/", "c:/windows/tracing/",
                 "c:/windows/debug/", "c:/windows/registration/crmlog/",
                 "c:/windows/system32/spool/", "c:/windows/system32/tasks/")


# Files every Debian/Ubuntu system has but dpkg does not register (created by
# maintainer scripts or the installer). Detection writeups name them as the
# thing an attacker modifies, which says nothing about whether they exist.
_STOCK_UNREGISTERED = frozenset((
    "/etc/profile", "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/etc/fstab",
    "/etc/sudoers", "/etc/crontab", "/etc/environment", "/etc/ld.so.cache",
    "/etc/machine-id", "/etc/shells", "/etc/os-release",
    # Copied from /etc/skel on every install; backdoor.check_persistence
    # reads every home's shell profiles, root's included, for payloads.
    "/root/.bashrc", "/root/.profile"))


# How long a process-name match counts as current activity.
NAMED_PROCESS_WINDOW_S = 72 * 3600


def _win_norm(path):
    p = path.replace("\\", "/")
    while "//" in p:
        p = p.replace("//", "/")
    return p.lower()


def _microsoft_signed(paths):
    """Subset of Windows paths carrying a valid Microsoft Authenticode signature.

    Writeups name stock binaries (rundll32, dllhost, explorer) that malware
    abuses, and the feed records them as attacker paths. The file existing is
    then meaningless. Paths come from feeds, so they travel as JSON on stdin and
    are never interpolated into the script.
    """
    if not paths:
        return set()
    payload = json.dumps(sorted(paths))
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        + stdin_text("p") +
        "$p=$p|ConvertFrom-Json;"
        "$ok=@(foreach($x in $p){$s=Get-AuthenticodeSignature -LiteralPath $x;"
        "if($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match "
        "'O=Microsoft Corporation'){$x}});"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json -InputObject $ok -Compress)))")
    result = ps_json(script, timeout=60, payload=payload)
    if isinstance(result, str):
        result = [result]
    return set(result) if isinstance(result, list) else set()


def check_paths(store):
    """Does any attacker-dropped path actually exist here?"""
    out = []
    stock = {}      # windows path -> finding args, pending a signature check
    for r in _active(store, "path"):
        raw = r["norm"]
        candidates = []
        if raw.startswith("/"):
            candidates.append(("wsl", raw))
        win = _win_to_wsl(raw)
        if win:
            candidates.append(("win", win))
        for host, path in candidates:
            try:
                if not os.path.lexists(path):
                    continue
                if os.path.isdir(path) or not (
                        os.path.isfile(path) or os.path.islink(path)):
                    continue        # sockets, fifos and devices are not payloads
            except (OSError, ValueError):
                continue
            if host == "wsl" and path in _STOCK_UNREGISTERED:
                continue        # exists on every system; tampering is audited elsewhere
            if host == "wsl" and _dpkg_owns(path):
                continue        # a package owns it: present by design
            finding = _finding(
                "dropped file", "high",
                f"a file named in threat intelligence exists here: {raw}",
                (r["context"] or "listed as an attacker-created path")
                + " — verify before deleting; the name may simply collide",
                r["source_url"], host)
            norm = _win_norm(raw)
            if (host == "win" and norm.startswith("c:/windows/")
                    and not norm.startswith(_WIN_WRITABLE)):
                stock.setdefault(raw.replace("\\\\", "\\"), []).append(finding)
            else:
                out.append(finding)
    signed = _microsoft_signed(set(stock))
    for path, findings in stock.items():
        if path not in signed:
            out.extend(findings)    # unsigned or unverifiable: still report
    return out


def check_processes(store):
    """Has anything with an attacker-associated name ever run here?

    This is the weakest indicator class by a wide margin. A writeup naming a
    binary the attacker abused puts that name in the feed, and if the name
    belongs to real software the match is meaningless. The first live run
    produced 1500 findings for `wslhost.exe` on exactly this mistake.

    So a name match alone is not evidence. It is only reported when the binary
    is somewhere a legitimate copy would not be — the same reasoning the path
    check applies with dpkg, and the reason severity here is capped below the
    hash and infrastructure checks.
    """
    out = []
    names = {r["norm"]: r for r in _active(store, "process")}
    if not names:
        return out
    pending = []
    for row in store.db.execute(
            "SELECT name, exe, host, cmdline, last_seen FROM procs"):
        name = (row["name"] or "").lower()
        stem = name.rsplit(".", 1)[0] if "." in name else name
        hit = names.get(name) or names.get(stem)
        if not hit:
            continue
        exe = (row["exe"] or "").lower().replace("\\", "/")
        if exe.startswith(TRUSTED_PATHS):
            continue        # the real binary, in the place it belongs
        pending.append((row, hit, exe))
    # Microsoft's own updaters live in per-user AppData (OneDriveSetup.exe,
    # Teams, Edge's installer), outside TRUSTED_PATHS. A valid Microsoft
    # signature on the exact file that ran settles those; anything unsigned
    # or signed by anyone else is still reported.
    signed = _microsoft_signed({row["exe"] for row, _hit, exe in pending
                                if row["host"] == "win" and row["exe"]})
    for row, hit, exe in pending:
        if row["host"] == "win" and row["exe"] in signed:
            continue
        # With no executable path there is nothing to compare against where a
        # legitimate copy lives (another user's process, or a Windows pseudo-
        # process such as Registry), so the name match is all there is — the
        # evidence this docstring says is not enough on its own. It stays
        # listed, at low.
        # The indicator's own confidence caps it, as for domains: a name the
        # writeup reader pulled from prose is medium evidence at most.
        # Measured: OneDriveSetup.exe, Microsoft's self-deleting updater, from
        # a Splunk detection-rule page — gone before its signature could be read.
        # A copy in a temp or download folder is suspicious whatever the source.
        dropped = any(d in exe for d in ("/temp/", "/tmp/", "/downloads/"))
        sev = ("high" if dict(hit).get("confidence") == "high" or dropped else "medium") if exe else "low"
        # The procs table is a history. A match last seen days ago stays
        # listed, but as a record of what ran, not as current activity.
        stale = time.time() - float(row["last_seen"] or 0) > NAMED_PROCESS_WINDOW_S
        if stale and not dropped:
            sev = "low"
        out.append(_finding(
            "named process", sev,
            f"a process matching a known malware name ran: {row['name']}",
            (hit["context"] or "name listed in threat intelligence")
            + f" — {(row['cmdline'] or '')[:110]}"
            + ("" if exe else " — executable path unknown, so a legitimate copy cannot be "
                              "told from a masquerade"),
            hit["source_url"] or (row["exe"] or ""), row["host"]))
    return out


def check_hashes(store, limit=1500):
    """Hash the executables jarvis has seen and compare against sample digests."""
    out = []
    have = store.db.execute(
        "SELECT 1 FROM indicators WHERE kind='sha256' AND status='active' "
        "LIMIT 1").fetchone()
    if not have:
        return out
    seen = set()
    rows = store.db.execute(
        "SELECT DISTINCT exe, host FROM procs WHERE exe LIKE '/%' "
        "ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
    for row in rows:
        path = row["exe"]
        if not path or path in seen:
            continue
        seen.add(path)
        digest = _hash_cached(store, path)
        if not digest:
            continue
        hit = store.db.execute(
            "SELECT context, source_url, malware, source FROM indicators "
            "WHERE kind='sha256' AND norm=? AND status='active'",
            (digest,)).fetchone()
        if hit:
            label = hit["malware"] or hit["context"] or "listed in threat intelligence"
            out.append(_finding(
                "sample match", "critical",
                f"a file here matches a known malware sample: {os.path.basename(path)}",
                f"SHA-256 {digest} — {label} (via {hit['source']})",
                path, row["host"]))
    store.commit()
    return out


# Where a payload named only by filename has to live in order to work. A PAM
# backdoor must be on the PAM module path; a preloaded object must be findable
# by the loader; a rootkit module must be under the module tree. Hunting only
# these keeps the check bounded and cheap — a whole-filesystem sweep for
# attacker filenames would be both slow and a false-positive machine.
FILENAME_DIRS = (
    "/lib/security", "/usr/lib/security", "/lib/x86_64-linux-gnu/security",
    "/usr/lib/x86_64-linux-gnu/security", "/usr/local/lib", "/usr/local/bin",
    "/etc", "/etc/systemd/system", "/lib/systemd/system", "/etc/cron.d",
    "/tmp", "/var/tmp", "/dev/shm", "/run", "/opt", "/usr/lib/modules",
)


def check_filenames(store, max_entries=40000):
    """Look for attacker-named files in the places such payloads must live."""
    out = []
    names = {r["norm"]: r for r in _active(store, "filename")}
    if not names:
        return out

    scanned = 0
    for root in FILENAME_DIRS:
        if not os.path.isdir(root):
            continue
        # /lib/modules is deep and huge; everything else is one level.
        depth_cap = 3 if "modules" in root else 1
        base_depth = root.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if dirpath.rstrip("/").count("/") - base_depth >= depth_cap:
                dirnames[:] = []
            for fn in filenames:
                scanned += 1
                if scanned > max_entries:
                    return out
                hit = names.get(fn.lower())
                if not hit:
                    continue
                full = os.path.join(dirpath, fn)
                if _dpkg_owns(full):
                    continue
                out.append(_finding(
                    "dropped file", "high",
                    f"a file named in threat intelligence is present: {fn}",
                    (hit["context"] or "filename listed in threat intelligence")
                    + " — no package owns this file",
                    full, "wsl"))
    return out


def _aggregate(findings):
    """Collapse repeats of one indicator into a single counted finding.

    The same C2 address seen by nineteen browser tabs is one fact, not
    nineteen. Reporting it nineteen times buries whatever else the hunt found.
    """
    groups = {}
    for f in findings:
        key = (f["category"], f["title"], f["host"])
        if key in groups:
            groups[key]["_n"] += 1
        else:
            groups[key] = {**f, "_n": 1}
    out = []
    for g in groups.values():
        n = g.pop("_n")
        if n > 1:
            g["detail"] = f"{g['detail']}  [seen {n}×]"
        out.append(g)
    return out


def hunt(store, hosts=("wsl", "win")):
    """Run every indicator check and record the hits."""
    findings = []
    for fn in (check_peers, check_paths, check_filenames, check_processes,
               check_hashes):
        try:
            findings += fn(store)
        except Exception as exc:      # one broken check must not hide the rest
            findings.append(_finding(
                "hunt", "medium", f"{fn.__name__} failed", str(exc)))
    findings = [f for f in findings if f["host"] in hosts or f["host"] == "wsl"]
    findings = _aggregate(findings)

    ts = now()
    for f in findings:
        if f["category"] == "hunt":
            continue
        store.db.execute(
            """INSERT INTO hunt_hits(ts,kind,value,host,severity,evidence,source_url)
               VALUES(?,?,?,?,?,?,?)""",
            (ts, f["category"], f["title"][:300], f["host"], f["severity"],
             f["detail"][:600], f["where"][:400]))
    store.set_meta("hunt_last_run", ts)
    store.commit()
    return findings


def sort_findings(findings):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    cat = {"c2 match": 0, "sample match": 1, "dropped file": 2,
           "named process": 3, "coverage gap": 4, "hunt": 5}
    return sorted(findings, key=lambda f: (order.get(f["severity"], 9),
                                           cat.get(f["category"], 9), f["title"]))
