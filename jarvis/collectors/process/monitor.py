"""Scan orchestration: collect -> assess -> record -> report."""

import json

from jarvis.core import state as state_mod
from jarvis.core.util import classify_ip, iso, now, reverse_dns
from jarvis.platform import linux as collect_linux
from jarvis.platform import topology
from jarvis.platform import windows as collect_windows

from . import detect

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def collect_all(hosts=("wsl", "win"), with_sockets=True):
    def _read():
        procs = []
        if "wsl" in hosts:
            procs += collect_linux.collect(with_sockets=with_sockets)
        if "win" in hosts:
            procs += collect_windows.collect()
        return procs

    # One authoritative process snapshot per interval, shared by the scan
    # and the resource profiler (Phase 3: one expensive read, many cheap
    # consumers). A socket-less consumer reuses the socket-full snapshot by
    # stripping connections rather than triggering a second /proc + WMI walk.
    if not with_sockets:
        try:
            full = state_mod.get_processes(
                hosts, lambda: _read_full(hosts), with_sockets=True)
        except Exception:
            full = None
        if full is not None:
            return [{**p, "conns": []} for p in full]
    return state_mod.get_processes(hosts, _read, with_sockets=with_sockets)


def _read_full(hosts):
    procs = []
    if "wsl" in hosts:
        procs += collect_linux.collect(with_sockets=True)
    if "win" in hosts:
        procs += collect_windows.collect()
    return procs


def _remote_summary(p, enrich):
    """Distinct external peers this process is talking to, most notable first."""
    seen, out = set(), []
    for c in p.get("conns", []):
        ip = c.get("remote_ip") or ""
        scope = classify_ip(ip)
        if scope in ("unspecified", "invalid") or c.get("state") == "LISTEN":
            continue
        key = (ip, c.get("remote_port"))
        if key in seen:
            continue
        seen.add(key)
        item = {
            "ip": ip,
            "port": c.get("remote_port"),
            "proto": c.get("proto"),
            "state": c.get("state"),
            "scope": scope,
        }
        if enrich and scope == "public":
            item["rdns"] = reverse_dns(ip)
        out.append(item)
    out.sort(key=lambda i: (i["scope"] != "public", i["ip"]))
    return out


def scan(store, hosts=("wsl", "win"), enrich=False, learn=False, record=True):
    """One full pass. `learn` folds everything seen into the approved baseline."""
    procs = collect_all(hosts)
    # Only the fingerprints running now are looked up (detect.assess tests
    # membership of each process's own fp); the full tables are never loaded.
    known, approved = store.fp_status(p["fp"] for p in procs)

    findings, new_peers = [], []
    ts = now()
    # Read once per scan; an unreadable fact leaves every mismatch standing.
    try:
        topo = topology.snapshot() if "wsl" in hosts else None
    except Exception:
        topo = None

    for p in procs:
        verdict = detect.assess(p, known, approved, topo)
        remotes = _remote_summary(p, enrich)

        store.upsert_proc(p, approved=1 if learn else 0)

        for r in remotes:
            first = store.upsert_peer(
                p["host"], p["fp"], r["ip"], r["port"], r["scope"], r.get("rdns", "")
            )
            if first and r["scope"] == "public" and not learn:
                new_peers.append({**r, "proc": p, "fp": p["fp"]})

        interesting = verdict["unknown"] or verdict["reasons"]
        if interesting and not learn:
            rec = {**p, **verdict, "remotes": remotes, "ts": ts}
            findings.append(rec)
            if record:
                store.add_event({
                    "ts": ts,
                    "host": p["host"],
                    "severity": verdict["severity"],
                    "kind": "new-process" if verdict["unknown"] else "trait",
                    "fp": p["fp"],
                    "pid": p["pid"],
                    "name": p["name"],
                    "exe": p["exe"] or p.get("script", ""),
                    "cmdline": p["cmdline"][:2000],
                    "user": p["user"],
                    "reasons": ",".join(verdict["reasons"]),
                    "remotes": json.dumps(remotes)[:4000],
                })

    store.commit()
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], -f["score"]))
    return {
        "ts": ts,
        "scanned": len(procs),
        # The daemon uses the same point-in-time observations to reconcile the
        # temporal state projection. They are not written to the presentation
        # snapshot; _scan converts only discrepancies into findings.
        "processes": procs,
        "findings": findings,
        "new_public_peers": new_peers,
        "hosts": list(hosts),
    }


def summarize(result, top=None):
    """Human-readable scan summary."""
    lines = []
    counts = {}
    for f in result["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    tally = " ".join(f"{k}={counts[k]}" for k in ("critical", "high", "medium", "low")
                     if k in counts) or "clean"
    lines.append(f"[{iso(result['ts'])}] scanned {result['scanned']} processes "
                 f"across {'+'.join(result['hosts'])} — {tally}")
    return "\n".join(lines)
