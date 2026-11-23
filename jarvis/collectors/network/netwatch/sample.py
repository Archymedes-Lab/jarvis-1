"""One reading of network state from Windows, plus every log entry since the last
reading, parsed into a sample dict."""

import time

from jarvis.core.paths import load_win_script
from jarvis.core.util import now
from jarvis.platform.windows import aslist, ps_json

PS_NET = load_win_script("netwatch.ps1")


# Ordered weakest to strongest, so a downgrade is a decrease.
AUTH_RANK = {
    "open": 0, "none": 0, "wep": 1, "shared": 1,
    "wpa-personal": 2, "wpa2-personal": 3, "wpa2-enterprise": 3,
    "wpa3-personal": 4, "wpa3-enterprise": 4, "wpa3-sae": 4,
}


def _rank(auth):
    a = (auth or "").strip().lower()
    for key, val in AUTH_RANK.items():
        if key in a:
            return val
    return 3 if a else -1


def _parse_wlan(text):
    """Pull the fields netsh prints for the connected interface."""
    out = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip().lower()
        v = v.strip()
        if not v:
            continue
        if k == "name":
            out["iface"] = v
        elif k == "state":
            out["state"] = v.lower()
        elif k == "ssid" and "bssid" not in k:
            out["ssid"] = v
        elif k in ("bssid", "ap bssid"):
            out["bssid"] = v.lower()
        elif k == "channel":
            out["channel"] = int(v) if v.isdigit() else 0
        elif k in ("authentication",):
            out["auth"] = v
        elif k in ("cipher",):
            out["cipher"] = v
        elif k in ("signal",):
            out["signal"] = int(v.rstrip("%")) if v.rstrip("%").isdigit() else 0
        elif k in ("radio type", "band"):
            out.setdefault("band", v)
    return out


def sample(since_ts=None, posture=False):
    """One reading of current network state plus every log entry since `since_ts`.

    Reading the Windows logs incrementally is what makes complete coverage
    affordable: a full week costs seconds, five minutes of new entries costs
    almost nothing, and nothing is skipped either way. `posture` adds the
    half-hourly wireless posture block (see posture.py).
    """
    if since_ts:
        # A minute of overlap so an entry written between the query and the
        # bookmark is seen twice rather than lost.
        secs = max(120, int(time.time() - since_ts) + 60)
        since = f"(Get-Date).AddSeconds(-{secs})"
    else:
        since = "(Get-Date).AddDays(-7)"
    script = (PS_NET.replace("__SINCE__", since)
                    .replace("__POSTURE__", "$true" if posture else "$false"))
    data = ps_json(script, timeout=180)
    if not data:
        return None
    wlan = _parse_wlan(data.get("wlan"))
    iface = wlan.get("iface") or ""

    adapters = aslist(data.get("adapters"))
    wifi_ad = None
    for a in adapters:
        if iface and a.get("name") == iface:
            wifi_ad = a
            break
    if wifi_ad is None:
        for a in adapters:
            if "802.11" in (a.get("type") or "") or "Wi-Fi" in (a.get("name") or ""):
                wifi_ad = a
                iface = iface or a.get("name") or "Wi-Fi"
                break

    ipcfg = {}
    for c in aslist(data.get("ipcfg")):
        if c.get("iface") == iface:
            ipcfg = c
            break

    gw = (ipcfg.get("gw") or "").split(",")[0].strip()
    gw_mac = ""
    if gw:
        for n in aslist(data.get("neighbors")):
            if n.get("ip") == gw:
                gw_mac = (n.get("mac") or "").lower()
                break

    status = (wifi_ad or {}).get("status") or ""
    if status.lower() in ("disabled", "not present"):
        state = "disabled"
    elif wlan.get("state") == "connected":
        state = "connected"
    elif status.lower() == "up":
        state = "up"
    else:
        state = wlan.get("state") or status.lower() or "unknown"

    # netsh needs Location consent in this execution context to reveal
    # SSID/BSSID; a background service can remain denied after the user
    # enables Location for interactive apps.
    # Without it the field is simply absent, which would look exactly like a
    # disconnected adapter — so the blocker is recorded explicitly instead.
    raw = data.get("wlan") or ""
    blocked = ("location permission" in raw.lower()
               or "requires elevation" in raw.lower()
               or "error 5" in raw.lower())
    if blocked and state == "up":
        state = "connected-opaque"

    return {
        "ts": now(), "iface": iface or "Wi-Fi", "state": state,
        "wlan_blocked": blocked,
        "ssid": wlan.get("ssid", ""), "bssid": wlan.get("bssid", ""),
        "channel": wlan.get("channel", 0), "band": wlan.get("band", ""),
        "auth": wlan.get("auth", ""), "cipher": wlan.get("cipher", ""),
        "signal": wlan.get("signal", 0),
        "ipv4": ipcfg.get("ipv4", ""), "gateway": gw, "gw_mac": gw_mac,
        "dns": ipcfg.get("dns", ""),
        "_wlanlog": aslist(data.get("wlanlog")),
        "_netprofile": aslist(data.get("netprofile")),
        "_adapters": adapters,
        "_posture": _posture(data.get("posture")),
    }


def _posture(raw):
    """Normalise the posture block's PowerShell shapes (single items arrive
    unwrapped). None when this sample did not include it."""
    if not isinstance(raw, dict):
        return None
    p = dict(raw)
    for key in ("direct", "vpn", "routes", "open_auto"):
        p[key] = aslist(p.get(key))
    p["at"] = now()
    return p
