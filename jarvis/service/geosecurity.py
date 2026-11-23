"""GeoSecurity state: fuse location signals, hold trusted zones, feed the globe.

The browser view (`/geo`) is the face of this, but the security value is the
fusion: a position is trusted only as far as the independent signals agree, so
spoofing one source does not convince JARVIS. Confidence is built only from
signals JARVIS actually has — a native fix and its accuracy, whether it lands
in a user-declared zone, and how fresh it is. There is no paired-phone or
BLE-proximity input yet, so that part of the design contributes nothing rather
than a fabricated 0.98.

Anomalies follow the same honesty: device-separation needs a second trusted
device JARVIS does not have, so it is not raised. What can be raised truthfully
is raised — being geo-blind, or sitting outside every trusted zone while
high-severity security findings are active.

Imagery is environmental context, labelled for what it is (NASA GIBS daily
true-color), never called "live". No position marker is shown unless there is a
real fix or a user-asserted home zone to center on.
"""

import json
from datetime import datetime, timedelta, timezone

from jarvis.collectors.host import geo
from jarvis.core.util import now

# NASA GIBS: public, no token, global. Daily true-color; honest about cadence.
# VIIRS (wide swath, overlapping orbits) is the primary layer: the narrower
# MODIS swath leaves hard black no-data wedges over this region (verified
# 2026-09-20: same z5 Kigali tile 31% pure-black on MODIS, 0% on VIIRS).
# Capped at z7: sharper static mosaics own the closer bands below.
IMAGERY = {
    "provider": "NASA GIBS",
    "layer": "VIIRS_NOAA20_CorrectedReflectance_TrueColor",
    "tile_matrix_set": "GoogleMapsCompatible_Level9",
    "format": "image/jpeg",
    "max_level": 7,
    "endpoint": "https://gibs.earthdata.nasa.gov/wmts/epsg3857/best/wmts.cgi",
    "attribution": "Imagery courtesy NASA EOSDIS GIBS",
    "cadence": "daily true-color, not live",
}


def get_zones(store):
    return geo.get_zones(store)


def set_zones(store, zones):
    store.set_meta("geo_zones", json.dumps(zones))
    store.commit()


def add_zone(store, name, lat, lon, radius_m=200, address="", kind=""):
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise ValueError("latitude/longitude out of range")
    zones = [z for z in get_zones(store) if z["name"] != name]
    zones.append({"name": name, "lat": float(lat), "lon": float(lon),
                  "radius_m": max(20, int(radius_m)),
                  "address": str(address or "")[:200],
                  "kind": str(kind or "")[:20]})
    set_zones(store, zones)
    return zones


def update_zone(store, name, radius_m=None, address=None, kind=None):
    """Edit a zone in place (radius/address/kind). Raises ValueError if missing."""
    zones = get_zones(store)
    for z in zones:
        if z["name"] == name:
            if radius_m is not None:
                z["radius_m"] = max(20, min(50000, int(radius_m)))
            if address is not None:
                z["address"] = str(address)[:200]
            if kind is not None:
                z["kind"] = str(kind)[:20]
            set_zones(store, zones)
            return zones
    raise ValueError(f"no trusted zone '{name}'")


def remove_zone(store, name):
    set_zones(store, [z for z in get_zones(store) if z["name"] != name])


def fusion(store, geo_current):
    """Position confidence from the signals actually available. -> {score, signals}.

    A user-declared location is trusted for what it is — where the user says they
    are — but not treated as an independently verified fix, so it never reaches
    the certainty a tight GNSS reading would.
    """
    signals = []
    status = (geo_current or {}).get("status")
    if status == "ok" and (geo_current or {}).get("source") == "user-set":
        signals.append(("location you set manually", 0.7))
        if geo_current.get("zone") and geo_current["zone"] != "outside":
            signals.append(("inside a user-declared trusted zone", 0.6))
    elif status == "ok":
        acc = geo_current.get("accuracy_m") or 9999
        # A tight native fix is strong evidence; a loose one much less.
        w = 0.9 if acc <= 50 else 0.75 if acc <= 500 else 0.5 if acc <= 5000 else 0.3
        signals.append(("native GNSS/Wi-Fi fix", round(w, 2)))
        if geo_current.get("zone") and geo_current["zone"] != "outside":
            signals.append(("inside a user-declared trusted zone", 0.85))
        age = now() - (geo_current.get("ts") or 0)
        if age > 3600:
            signals.append(("fix is stale", 0.3))
    elif status == "denied":
        signals.append(("location permission off — no position", 0.0))
    else:
        signals.append(("no position available", 0.0))
    # Combine as noisy-OR over independent signals (weak signals still can't
    # manufacture certainty; one strong signal dominates honestly).
    product = 1.0
    for _, w in signals:
        product *= (1 - max(0.0, min(1.0, w)))
    score = round(1 - product, 2) if signals else 0.0
    return {"score": score, "signals": [{"name": n, "weight": w} for n, w in signals]}


def _devices(store, geo_current, health_state):
    """Only devices JARVIS actually knows. This machine; no fabricated phone/watch."""
    trusted = bool((health_state or {}).get("healthy"))
    this = {"name": "this device", "kind": "workstation",
            "trust": "trusted" if trusted else "degraded",
            "located": (geo_current or {}).get("status") == "ok",
            "zone": (geo_current or {}).get("zone")}
    return [this]


def anomalies(store, geo_current, recent_findings):
    """Truthfully raisable geo anomalies only."""
    out = []
    status = (geo_current or {}).get("status")
    zones = get_zones(store)
    if status == "denied":
        out.append({"kind": "geo_blind", "severity": "low",
                    "detail": "Location is off; JARVIS cannot detect device movement or theft."})
    hot = [f for f in (recent_findings or []) if f.get("severity") in ("critical", "high")]
    if status == "ok" and zones and geo_current.get("zone") == "outside" and hot:
        # Name the nearest zone with measured distance so the panel states
        # a checkable fact, and frame location as context — being outside a
        # zone does not prove the findings are a physical compromise.
        nearest, best = None, None
        for z in zones:
            d = geo.haversine_m(geo_current["lat"], geo_current["lon"],
                                z["lat"], z["lon"])
            if best is None or d < best:
                nearest, best = z, d
        where = (f"~{int(round(best))} m from {nearest['name']} "
                 f"(trusted radius {nearest.get('radius_m', 200)} m)") \
            if nearest else "outside every trusted zone"
        out.append({"kind": "outside_zone_with_activity", "severity": "high",
                    "detail": f"This device is {where} while "
                              f"{len(hot)} high-severity finding(s) are active — "
                              f"treat location as context, not proof of compromise."})
    return out


def observation_date():
    """The imagery date the globe requests: UTC yesterday, matching the
    TIME= parameter geo.html appends to daily GIBS requests."""
    return (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()

# Static seamless Earth beneath the daily layer: no TIME dimension, so it
# also covers daily-tile errors and poles. (GIBS true-color layers are
# JPEG-only — no alpha — so this is a fallback, not gap transparency.)
IMAGERY_BASE = {
    "provider": "NASA GIBS",
    "layer": "BlueMarble_NextGeneration",
    "tile_matrix_set": "GoogleMapsCompatible_Level8",
    "format": "image/jpeg",
    "max_level": 8,
    "endpoint": "https://gibs.earthdata.nasa.gov/wmts/epsg3857/best/wmts.cgi",
    "attribution": "NASA Blue Marble Next Generation",
    "cadence": "static seamless basemap (fallback)",
}

# Street-level detail for high zoom: GIBS daily layers stop at z9, so zooming
# further only magnifies blur. Esri World Imagery (XYZ to z19, verified over
# Kigali 2026-09-20) renders only at z14+, leaving sharper static mosaics
# below it. Free use with attribution; single allowlisted tile origin.
IMAGERY_DETAIL = {
    "provider": "Esri",
    "layer": "World_Imagery",
    "url_template": "https://server.arcgisonline.com/ArcGIS/rest/services/"
                    "World_Imagery/MapServer/tile/{z}/{y}/{x}",
    "min_level": 14,
    "max_level": 19,
    "attribution": "Imagery © Esri, Maxar, Earthstar Geographics",
    "cadence": "sub-metre basemap for close zoom",
}

# Mid bands: 10 m Sentinel-2 cloudless mosaic (EOX, free, no key, verified
# z11/z14/z16 over Kigali 2026-09-20). Static 2020 data — sharpness, not
# freshness; the daily VIIRS layer above z0–7 remains the current picture.
IMAGERY_MID = {
    "provider": "EOX",
    "layer": "s2cloudless-2020",
    "url_template": "https://tiles.maps.eox.at/wmts/1.0.0/"
                    "s2cloudless-2020_3857/default/g/{z}/{y}/{x}.jpg",
    "min_level": 8,
    "max_level": 13,
    "attribution": "Sentinel-2 cloudless by EOX IT Services GmbH "
                   "(contains modified Copernicus Sentinel data 2020)",
    "cadence": "10 m mosaic, 2020 (static)",
}


def imagery(loc):
    """Imagery config for the globe, and where to center it (honestly)."""
    center = None
    if (loc or {}).get("status") == "ok":
        center = {"lat": loc["lat"], "lon": loc["lon"],
                  "source": "user-set" if loc.get("source") == "user-set" else "device fix"}
    return {**IMAGERY, "date": observation_date(), "base": IMAGERY_BASE,
            "mid": IMAGERY_MID, "detail": IMAGERY_DETAIL, "center": center}


def view(loc):
    """Accuracy-aware default view: street, city, or globe. Pure.

    A tight fix opens at street scale; a loose one at city scale; no
    position (or a user-set point with no accuracy) opens the global
    context with no marker. `tile_center` is rounded to ~1 km so tile
    requests never encode the exact position — the precise marker
    overlay stays local (Phase 11); tiles only need the neighbourhood.
    """
    if (loc or {}).get("status") == "ok" and "lat" in (loc or {}):
        acc = loc.get("accuracy_m")
        if isinstance(acc, (int, float)) and acc <= 100:
            mode, zoom = "street", 16
            reason = f"±{int(acc)} m fix: street scale is useful"
        elif isinstance(acc, (int, float)) and acc <= 5000:
            mode, zoom = "city", 11
            reason = f"±{int(acc)} m fix: city scale matches the uncertainty"
        else:
            mode, zoom = "city", 11
            reason = ("user-declared point without a measured accuracy: "
                      "city scale, zone context")
        return {"mode": mode, "zoom": zoom, "reason": reason,
                "tile_center": {"lat": round(float(loc["lat"]), 2),
                                "lon": round(float(loc["lon"]), 2)}}
    return {"mode": "globe", "zoom": 2,
            "reason": "no position: global context only, no marker",
            "tile_center": None}


def set_here(store, lat, lon, label=None):
    """Record a user-declared current location (labelled, never a GNSS fix)."""
    return geo.set_manual(store, lat, lon, label)


def clear_here(store):
    geo.clear_manual(store)


def state(store, health_state=None, recent_findings=None):
    """The full payload the /geo view renders."""
    loc = geo.effective(store, geo.current(store))
    zones = get_zones(store)
    # If there is no location at all but a home zone exists, center there —
    # user-asserted, not a guessed position, and marked as such.
    img = imagery(loc)
    if img["center"] is None and zones:
        home = next((z for z in zones if z["name"].upper() == "HOME"), zones[0])
        img["center"] = {"lat": home["lat"], "lon": home["lon"], "source": "home zone"}
    return {
        "location": loc or {"status": "unknown"},
        "confidence": fusion(store, loc),
        "view": view(loc),
        "zones": zones,
        "devices": _devices(store, loc, health_state),
        "anomalies": anomalies(store, loc, recent_findings),
        "imagery": img,
        "generated_at": now(),
    }
