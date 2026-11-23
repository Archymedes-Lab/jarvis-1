"""Storing every sample and raising timeline events for what changed, including
entries folded in from the Windows WLAN logs."""

import json

from jarvis.core.util import now

from .sample import _rank, sample

POSTURE_META = "netwatch_posture"
POSTURE_EVERY_S = 1800
ROAM_PAIR_MAX_AGE_S = 900


def confirmed_network_switch(prev, current):
    """Both identified Wi-Fi networks differ; never infer this from missing IDs."""
    return bool(prev["ssid"] and current["ssid"] and prev["bssid"]
                and current["bssid"] and prev["ssid"] != current["ssid"]
                and prev["bssid"] != current["bssid"])


def coherent_unverified_roam(prev, current):
    """Strong adjacent context supports roaming, never AP ownership."""
    try:
        age = int(current["ts"]) - int(prev["ts"])
        auth = str(current["auth"] or "").strip().lower()
        cipher = str(current["cipher"] or "").strip().lower()
        return bool(
            0 < age <= ROAM_PAIR_MAX_AGE_S
            and prev["state"] == current["state"] == "connected"
            and prev["iface"] == current["iface"]
            and prev["ssid"] and prev["ssid"] == current["ssid"]
            and prev["bssid"] and current["bssid"]
            and prev["bssid"] != current["bssid"]
            and auth == str(prev["auth"] or "").strip().lower()
            and any(mode in auth for mode in ("wpa2-personal", "wpa2-enterprise",
                                                   "wpa3-personal", "wpa3-enterprise", "wpa3-sae"))
            and cipher == str(prev["cipher"] or "").strip().lower()
            and any(mode in cipher for mode in ("ccmp", "gcmp", "aes"))
            and all(prev[field] and prev[field] == current[field]
                    for field in ("gateway", "gw_mac", "dns"))
        )
    except (KeyError, IndexError, TypeError, ValueError):
        return False


def _last_sample(store, iface):
    return store.db.execute(
        "SELECT * FROM net_samples WHERE iface=? ORDER BY ts DESC LIMIT 1",
        (iface,)).fetchone()


def _event(store, ts, iface, kind, severity, detail, prev="", curr=""):
    store.db.execute(
        """INSERT INTO net_events(ts,iface,kind,severity,detail,prev,curr)
           VALUES(?,?,?,?,?,?,?)""",
        (ts, iface, kind, severity, detail[:500], str(prev)[:200], str(curr)[:200]))


def record(store, s=None):
    """Store one sample and raise events for anything that changed."""
    if s is None:
        # The WLAN history is re-read every half hour, not every sample: it
        # covers a week and cannot change meaningfully in five minutes, and
        # fetching it was most of this collector's cost.
        # Every sample now carries the log delta, so the timeline has no
        # holes between passes.
        try:
            last = int(float(store.get_meta("netwatch_log_at", 0) or 0))
        except (TypeError, ValueError):
            last = 0
        try:
            posture_at = float(json.loads(store.get_meta(POSTURE_META, "") or "{}").get("at") or 0)
        except (TypeError, ValueError, AttributeError):
            posture_at = 0.0
        s = sample(since_ts=last or None, posture=now() - posture_at >= POSTURE_EVERY_S)
        if s:
            store.set_meta("netwatch_log_at", now())
    if not s:
        return []
    iface = s["iface"]
    prev = _last_sample(store, iface)
    events = []

    def fire(kind, sev, detail, p="", c=""):
        _event(store, s["ts"], iface, kind, sev, detail, p, c)
        events.append({"kind": kind, "severity": sev, "detail": detail})

    if prev:
        # -- adapter turned off ---------------------------------------------
        if s["state"] == "disabled" and prev["state"] != "disabled":
            fire("adapter-disabled", "critical",
                 "the wireless adapter was disabled — nothing disables a "
                 "working adapter by accident",
                 prev["state"], s["state"])
        elif prev["state"] == "disabled" and s["state"] != "disabled":
            fire("adapter-enabled", "medium",
                 "the wireless adapter was re-enabled",
                 prev["state"], s["state"])

        # -- link lost -------------------------------------------------------
        if (prev["state"] in ("connected", "connected-opaque")
                and s["state"] not in ("connected", "connected-opaque", "disabled")):
            fire("link-lost", "medium",
                 f"connection to {prev['ssid'] or 'the network'} was lost",
                 prev["state"], s["state"])
        elif (prev["state"] not in ("connected", "connected-opaque")
              and s["state"] in ("connected", "connected-opaque")):
            fire("link-up", "low", f"connected to {s['ssid']}",
                 prev["state"], s["state"])

        if s["state"] == "connected" and prev["state"] == "connected":
            switched = confirmed_network_switch(prev, s)
            if switched:
                fire("network-switched", "low",
                     "moved between two identified Wi-Fi networks; their DNS, "
                     "gateway and encryption settings are separate baselines",
                     prev["ssid"], s["ssid"])
            # -- access point swap -------------------------------------------
            if not switched and prev["bssid"] and s["bssid"] and prev["bssid"] != s["bssid"]:
                seen_before = store.db.execute(
                    "SELECT seen_count FROM known_aps WHERE ssid=? AND bssid=?",
                    (s["ssid"], s["bssid"])).fetchone()
                # known_aps is populated by every sample. A prior sighting is
                # useful forensic context, but it cannot authenticate an AP.
                # A replayed SSID/BSSID would pass an automatic known-AP test.
                coherent = coherent_unverified_roam(prev, s)
                fire("ap-repeat-unverified" if seen_before else "ap-unknown",
                     "medium" if coherent else "high",
                     (f"{s['ssid']} moved to an access point seen before" if seen_before
                      else f"{s['ssid']} moved to a newly seen access point")
                     + ("; recent strong Wi-Fi security and gateway/DNS context "
                        "are unchanged, but AP ownership is unverified" if coherent else
                        "; AP ownership or coherent network context is unverified"),
                     prev["bssid"], s["bssid"])

            # -- encryption weakened -----------------------------------------
            if not switched and _rank(s["auth"]) < _rank(prev["auth"]):
                fire("crypto-downgrade", "critical",
                     f"encryption on {s['ssid']} weakened from "
                     f"{prev['auth']} to {s['auth']}",
                     prev["auth"], s["auth"])

            # -- gateway hardware changed -------------------------------------
            if (not switched and prev["gw_mac"] and s["gw_mac"]
                    and prev["gw_mac"] != s["gw_mac"]):
                fire("gateway-changed", "high",
                     f"the default gateway {s['gateway']} is answering from a "
                     f"different MAC address — this is what ARP spoofing looks "
                     f"like", prev["gw_mac"], s["gw_mac"])

            # -- resolver changed ---------------------------------------------
            if not switched and prev["dns"] and s["dns"] and prev["dns"] != s["dns"]:
                fire("dns-changed", "high",
                     f"DNS servers for {iface} changed",
                     prev["dns"], s["dns"])

    if s["state"] == "connected" and s["ssid"] and s["bssid"]:
        store.db.execute(
            """INSERT INTO known_aps(ssid,bssid,auth,first_seen,last_seen)
               VALUES(?,?,?,?,?)
               ON CONFLICT(ssid,bssid) DO UPDATE SET
                   last_seen=excluded.last_seen,
                   seen_count=known_aps.seen_count+1""",
            (s["ssid"], s["bssid"], s["auth"], s["ts"], s["ts"]))

    store.db.execute(
        """INSERT OR REPLACE INTO net_samples
           (ts,iface,state,ssid,bssid,channel,band,auth,cipher,signal,
            ipv4,gateway,gw_mac,dns)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (s["ts"], iface, s["state"], s["ssid"], s["bssid"], s["channel"],
         s["band"], s["auth"], s["cipher"], s["signal"], s["ipv4"],
         s["gateway"], s["gw_mac"], s["dns"]))

    store.set_meta("netwatch_wlan_blocked", "1" if s.get("wlan_blocked") else "0")
    if s.get("_posture"):
        store.set_meta(POSTURE_META, json.dumps(s["_posture"]))
    _ingest_wlanlog(store, s.get("_wlanlog") or [], _WLAN_KIND)
    _ingest_wlanlog(store, s.get("_netprofile") or [], _PROFILE_KIND)
    store.commit()
    return events


# The real WLAN-AutoConfig identifiers. The previous map had 11004 and 11010
# the wrong way round, so "security stopped" was reported as an authentication
# *start* — which reads as the opposite of what happened.
_WLAN_KIND = {
    8000:  ("wlan-connect-start", "low"),
    8001:  ("wlan-connected", "low"),
    8002:  ("wlan-connect-failed", "medium"),
    8003:  ("wlan-disconnected", "medium"),
    8011:  ("wlan-roaming", "low"),
    11000: ("wlan-assoc-start", "low"),
    11001: ("wlan-assoc-ok", "low"),
    11002: ("wlan-assoc-failed", "medium"),
    11004: ("wlan-security-stopped", "low"),
    11005: ("wlan-security-ok", "low"),
    11006: ("wlan-security-failed", "high"),
    11010: ("wlan-security-start", "low"),
    11013: ("wlan-security-restart", "low"),
    12011: ("wlan-msm-assoc", "low"),
    12012: ("wlan-msm-auth", "low"),
    12013: ("wlan-msm-done", "low"),
}


# NetworkProfile: 10000 connected, 10001 disconnected — any adapter.
_PROFILE_KIND = {
    10000: ("net-profile-connected", "low"),
    10001: ("net-profile-disconnected", "medium"),
}


def _ingest_wlanlog(store, rows, kindmap):
    """Fold a Windows log into the timeline, de-duplicating by event time."""
    seen = {r["curr"] for r in store.db.execute(
        "SELECT curr FROM net_events WHERE curr != '' "
        "ORDER BY ts DESC LIMIT 3000")}
    for r in rows:
        raw = (r.get("time") or "")
        stamp = raw[:19]
        if not stamp or stamp in seen:
            continue
        kind, sev = kindmap.get(int(r.get("id") or 0), ("wlan-event", "low"))
        # PowerShell emits ISO-8601 *with* an offset. Slicing to 19 characters
        # throws that away, and treating the remainder as UTC skewed every
        # Windows-side event by the offset — three hours here, because Windows
        # runs +02:00 while this WSL install runs +03:00. A forensic timeline
        # that is silently three hours wrong correlates the wrong events, which
        # is worse than having no timeline.
        try:
            from datetime import datetime
            ts = int(datetime.fromisoformat(raw).timestamp())
        except (ValueError, TypeError):
            try:
                import calendar
                import time as _t
                ts = int(calendar.timegm(_t.strptime(stamp, "%Y-%m-%dT%H:%M:%S")))
            except Exception:
                continue
        store.db.execute(
            """INSERT INTO net_events(ts,iface,kind,severity,detail,prev,curr)
               VALUES(?,?,?,?,?,?,?)""",
            (ts, "", kind, sev, (r.get("msg") or "")[:400], "", stamp))
        seen.add(stamp)
