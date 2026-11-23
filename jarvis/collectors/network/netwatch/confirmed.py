"""Access points the owner has confirmed as a network they use.

A coherent roam proves recent strong context, never who runs the access point;
only the person on site can say "this is the coworking space's Wi-Fi". This
records that decision, pinned to the BSSIDs recorded for the SSID at the time
and to the single gateway hardware address seen behind it. An access point
added later, or a different gateway, keeps its original severity until the
owner confirms again. Only access-point changes are ever lowered: DNS,
gateway and encryption changes on a confirmed network keep their severity.

Residual risk, accepted by the owner: BSSIDs and ARP answers can be cloned,
so an evil twin that copies a pinned BSSID and relays the real gateway is not
told apart by this pin.
"""

import json
import time

META = "netwatch_confirmed_aps_v1"


class ConfirmError(ValueError):
    pass


def load(store):
    try:
        value = json.loads(store.get_meta(META, "{}") or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def _save(store, data):
    store.set_meta(META, json.dumps(data, sort_keys=True))
    store.commit()


def confirm(store, ssid, reason, now=None):
    """Pin every recorded access point of `ssid` and its one gateway."""
    reason = (reason or "").strip()
    if not reason:
        raise ConfirmError("a reason is required")
    bssids = sorted({str(r[0]).lower() for r in store.db.execute(
        "SELECT bssid FROM known_aps WHERE ssid=? AND bssid!=''", (ssid,))})
    if not bssids:
        raise ConfirmError(f"no access point has been recorded for {ssid!r}")
    macs = sorted({str(r[0]).lower() for r in store.db.execute(
        "SELECT DISTINCT gw_mac FROM net_samples "
        "WHERE ssid=? AND state='connected' AND gw_mac!=''", (ssid,))})
    if len(macs) != 1:
        raise ConfirmError(
            f"{ssid!r} has been seen behind {len(macs)} gateway hardware addresses "
            f"({', '.join(macs) or 'none'}); an ambiguous network cannot be confirmed")
    entry = {"bssids": bssids, "gw_mac": macs[0], "reason": reason[:300],
             "at": int(time.time() if now is None else now)}
    data = load(store)
    data[ssid] = entry
    _save(store, data)
    return entry


def revoke(store, ssid):
    data = load(store)
    entry = data.pop(ssid, None)
    _save(store, data)
    return entry


def covers(confirmed, previous, current):
    """Both ends of a same-SSID move are pinned access points behind the
    pinned gateway. A missing gateway reading on one side is allowed only
    when the other side carries the pinned one."""
    if previous["ssid"] != current["ssid"]:
        return False
    entry = confirmed.get(previous["ssid"])
    if not isinstance(entry, dict) or not entry.get("gw_mac"):
        return False
    pinned = set(entry.get("bssids") or ())
    macs = [str(s["gw_mac"] or "").lower() for s in (previous, current)]
    return (str(previous["bssid"] or "").lower() in pinned
            and str(current["bssid"] or "").lower() in pinned
            and any(macs)
            and all(m == entry["gw_mac"] for m in macs if m))
