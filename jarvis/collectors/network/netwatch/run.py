"""The netwatch audit: what the recorded transitions mean."""

import json

from jarvis.core.finding import win_finding as _finding
from jarvis.core.util import iso, now

from . import confirmed, posture
from .record import coherent_unverified_roam, confirmed_network_switch
from .sample import _rank

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


# Connectivity drops are ordinary on their own (roaming, a guest network,
# sleep). What makes them worth attention is a burst, the shape of a
# deauthentication flood, or a drop that coincides with the network itself
# changing underneath.
DROP_KINDS = ("wlan-disconnected", "net-profile-disconnected", "link-lost",
              "wlan-connect-failed", "wlan-assoc-failed")
BURST_KINDS = ("wlan-disconnected", "net-profile-disconnected", "link-lost")
CHANGE_KINDS = ("adapter-disabled", "ap-unknown", "ap-repeat-unverified", "crypto-downgrade",
                "dns-changed", "gateway-changed")
PAIRED_CHANGE_KINDS = ("ap-unknown", "ap-repeat-unverified", "crypto-downgrade", "dns-changed",
                       "gateway-changed")
AP_KINDS = ("ap-unknown", "ap-repeat-unverified")
BURST_COUNT, BURST_WINDOW_S, CHANGE_WINDOW_S = 3, 600, 300
MAC_CONFIRM_WINDOW_S = 600
MAC_CONFIRM_LIMIT = 12


def _drop_pattern(store, since, pins=None):
    """Why this day's drops deserve attention, or "" when they do not.

    A burst always counts. A single drop beside a network change counts
    unless the change is already explained: leaving one identified network
    for another involves a disconnect by definition, and a roam between
    owner-confirmed access points is the owner's own network."""
    marks = ",".join("?" * len(BURST_KINDS))
    drops = [r[0] for r in store.db.execute(
        f"SELECT ts FROM net_events WHERE ts>=? AND kind IN ({marks}) ORDER BY ts",
        (since, *BURST_KINDS))]
    for i, t in enumerate(drops):
        n = sum(1 for u in drops[i:] if u - t <= BURST_WINDOW_S)
        if n >= BURST_COUNT:
            return f"{n} drops within {BURST_WINDOW_S // 60} minutes, the shape of a deauthentication flood"
    pins = confirmed.load(store) if pins is None else pins
    marks = ",".join("?" * len(CHANGE_KINDS))
    for event in store.db.execute(
            f"SELECT kind, ts, iface FROM net_events WHERE ts>=? AND kind IN ({marks})",
            (since - CHANGE_WINDOW_S, *CHANGE_KINDS)):
        if not any(abs(event["ts"] - t) <= CHANGE_WINDOW_S for t in drops):
            continue
        if event["kind"] in PAIRED_CHANGE_KINDS:
            switched, coherent, owned = _paired_network_context(store, event, pins)
            if switched or (owned and event["kind"] in AP_KINDS):
                continue
        return f"a drop coincided with {event['kind'].replace('-', ' ')}"
    return ""


def _corroborated_roam(store, previous, current):
    """Fill one missing ARP reading only from bounded, consistent same-AP samples."""
    if coherent_unverified_roam(previous, current):
        return True
    missing, other = ((previous, current) if not previous["gw_mac"] else
                      (current, previous))
    if missing["gw_mac"] or not other["gw_mac"]:
        return False
    rows = store.db.execute(
        "SELECT gw_mac FROM net_samples WHERE iface=? AND ssid=? AND bssid=? "
        "AND state='connected' AND auth=? AND cipher=? AND gateway=? AND dns=? "
        "AND ts BETWEEN ? AND ? AND gw_mac!='' ORDER BY ts LIMIT ?",
        (missing["iface"], missing["ssid"], missing["bssid"],
         missing["auth"], missing["cipher"], missing["gateway"], missing["dns"],
         missing["ts"] - MAC_CONFIRM_WINDOW_S,
         missing["ts"] + MAC_CONFIRM_WINDOW_S, MAC_CONFIRM_LIMIT + 1)).fetchall()
    if not rows or len(rows) > MAC_CONFIRM_LIMIT or any(
            row["gw_mac"] != other["gw_mac"] for row in rows):
        return False
    patched = dict(missing)
    patched["gw_mac"] = other["gw_mac"]
    if missing is previous:
        previous = patched
    else:
        current = patched
    return coherent_unverified_roam(previous, current)


def _paired_network_context(store, event, pins=None):
    """Re-interpret an event only with its exact sample and prior sample.
    -> (identified switch, coherent roam, coherent roam between pinned APs)."""
    current = store.db.execute(
        "SELECT * FROM net_samples WHERE iface=? AND ts=?",
        (event["iface"], event["ts"])).fetchone()
    previous = store.db.execute(
        "SELECT * FROM net_samples WHERE iface=? AND ts<? "
        "ORDER BY ts DESC LIMIT 1", (event["iface"], event["ts"])).fetchone()
    if not current or not previous:
        return False, False, False
    switched = bool(current["state"] == previous["state"] == "connected"
                    and confirmed_network_switch(previous, current))
    coherent = _corroborated_roam(store, previous, current)
    owned = bool(coherent and pins and confirmed.covers(pins, previous, current))
    return switched, coherent, owned


def _paired_change_findings(store, since):
    marks = ",".join("?" * len(PAIRED_CHANGE_KINDS))
    rows = store.db.execute(
        f"SELECT ts,iface,kind,severity,detail,prev,curr FROM net_events "
        f"WHERE ts>=? AND kind IN ({marks}) ORDER BY ts",
        (since, *PAIRED_CHANGE_KINDS))
    pins = confirmed.load(store)
    groups = {}
    paired = {}
    for event in rows:
        sample_key = (event["iface"], event["ts"])
        if sample_key not in paired:
            paired[sample_key] = _paired_network_context(store, event, pins)
        switched, coherent, owned = paired[sample_key]
        is_ap = event["kind"] in AP_KINDS
        owned = owned and is_ap
        severity = ("low" if switched or owned else
                    "medium" if is_ap and coherent else
                    "high" if is_ap else event["severity"])
        key = (event["kind"], severity, switched, is_ap and coherent, owned)
        count = groups.get(key, (0, None))[0] + 1
        groups[key] = (count, event)
    out = []
    for (kind, severity, switched, coherent, owned), (count, event) in groups.items():
        title = kind.replace("-", " ")
        if switched:
            title += " during identified network switch"
            detail = ("the adjacent samples have different known SSIDs and BSSIDs; "
                      "this change belongs to a different network baseline. "
                      "The original event remains in the timeline")
        elif owned:
            title += " between owner-confirmed access points"
            detail = ("both access points and the gateway hardware are pinned to a "
                      "network the owner confirmed; authentication, cipher, gateway "
                      "and DNS held. The original event remains in the timeline")
        elif coherent:
            title += " during coherent unverified roam"
            detail = ("recent adjacent samples retain strong Wi-Fi authentication, "
                      "cipher, gateway address and MAC, and DNS; AP ownership is "
                      "unverified. The original event remains in the timeline")
        else:
            detail = event["detail"] or ""
        if event["prev"] or event["curr"]:
            detail += f"  ({event['prev']} → {event['curr']})"
        out.append(_finding(
            "network", severity, f"{title} ×{count}" if count > 1 else title,
            f"{detail} — last at {iso(event['ts'])}", "net_events"))
    return out


def audit(store, hours=24):
    """Report what the recorded history says about the last day."""
    since = now() - hours * 3600
    out = []
    pins = confirmed.load(store)

    marks = ",".join("?" * len(PAIRED_CHANGE_KINDS))
    rows = store.db.execute(
        "SELECT kind, severity, COUNT(*) n, MAX(ts) last, "
        "       MAX(detail) detail, MAX(prev) prev, MAX(curr) curr "
        f"FROM net_events WHERE ts>=? AND kind NOT IN ({marks}) "
        "GROUP BY kind, severity ORDER BY COUNT(*) DESC",
        (since, *PAIRED_CHANGE_KINDS)).fetchall()
    for r in rows:
        if r["kind"] in ("link-up", "wlan-connected", "wlan-auth",
                         "wlan-assoc", "wlan-auth-done", "wlan-auth-started",
                         "wlan-assoc-started", "ap-roam"):
            continue
        detail = r["detail"] or ""
        if r["prev"] or r["curr"]:
            detail += f"  ({r['prev']} → {r['curr']})"
        severity = r["severity"]
        if r["kind"] in DROP_KINDS and severity == "medium":
            why = _drop_pattern(store, since, pins)
            if not why:
                severity = "low"
                detail += (" — isolated: no burst of drops and no network "
                           "change around them")
            else:
                detail += f" — {why}"
        out.append(_finding(
            "network", severity,
            f"{r['kind'].replace('-', ' ')} ×{r['n']}"
            if r["n"] > 1 else r["kind"].replace("-", " "),
            f"{detail} — last at {iso(r['last'])}", "net_events"))
    out.extend(_paired_change_findings(store, since))

    blocked = store.get_meta("netwatch_wlan_blocked", "") == "1"
    if blocked:
        out.append(_finding(
            "network", "medium",
            "SSID and access point are invisible to this audit",
            "Windows denied this collector's access to SSID, BSSID, "
            "authentication and cipher. Without them, evil-twin and encryption-"
            "downgrade detection cannot run — adapter state, gateway MAC, DNS "
            "and the connect/disconnect log still work. Check Location under "
            "Settings > Privacy & security > Location. Background services can "
            "remain denied after interactive access is allowed; this audit "
            "needs a consented user-session sampling path.",
            "netsh wlan"))

    latest = store.db.execute(
        "SELECT * FROM net_samples ORDER BY ts DESC LIMIT 1").fetchone()
    if latest:
        if latest["state"] == "disabled":
            out.append(_finding(
                "network", "critical", "the wireless adapter is disabled now",
                f"last seen in this state at {iso(latest['ts'])}", latest["iface"]))
        elif latest["state"] == "connected-opaque":
            out.append(_finding(
                "network", "ok", f"link is up on {latest['iface']}",
                f"gateway {latest['gateway'] or '?'} "
                f"({latest['gw_mac'] or 'no arp entry'}) · "
                f"dns {latest['dns'] or '?'} — SSID hidden by permissions",
                latest["iface"]))
        elif latest["state"] == "connected":
            open_net = _rank(latest["auth"]) <= 1
            out.append(_finding(
                "network", "high" if open_net else "ok",
                f"connected to {latest['ssid']}"
                + (" over an unencrypted network" if open_net else ""),
                f"{latest['auth'] or 'unknown auth'} / "
                f"{latest['cipher'] or 'unknown cipher'} · "
                f"AP {latest['bssid'] or '?'} · gateway {latest['gateway'] or '?'}"
                f" ({latest['gw_mac'] or 'no arp entry'})",
                latest["iface"]))
        gap = now() - latest["ts"]
        if gap > 3600:
            out.append(_finding(
                "network", "medium", "network state has not been sampled recently",
                f"last sample {iso(latest['ts'])} — coverage of the timeline has "
                f"a {gap // 60} minute hole", "netwatch"))
    else:
        out.append(_finding(
            "network", "medium", "no network history recorded yet",
            "run `jarvis netwatch` or start the daemon to begin the timeline",
            "netwatch"))
    try:
        stored = json.loads(store.get_meta("netwatch_posture", "") or "null")
    except (TypeError, ValueError):
        stored = None
    out.extend(posture.findings(stored))
    return sort_findings(out)


def timeline(store, hours=24, limit=200):
    return [dict(r) for r in store.db.execute(
        "SELECT * FROM net_events WHERE ts>=? ORDER BY ts DESC LIMIT ?",
        (now() - hours * 3600, limit))]


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))
