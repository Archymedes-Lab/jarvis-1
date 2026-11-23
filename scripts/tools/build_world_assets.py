"""Build the two data files the world view needs, from pinned Natural Earth.

    python3 scripts/tools/build_world_assets.py SOURCE_DIR

SOURCE_DIR holds the three GeoJSON files named in SOURCES, taken from
https://github.com/nvkelso/natural-earth-vector at tag v5.1.2 (public domain).
Each is checked against its SHA-256 before use, so the outputs are reproducible
and a changed upstream file is refused rather than silently built in.

Outputs, both committed:

    jarvis/intel/data/gazetteer.json           names -> coordinates, for placing
                                               a headline on the map
    jarvis/web/static/vendor/world-50m.json    country outlines and a land mask,
                                               for drawing the globe

Every coordinate in both files comes from Natural Earth. The tables below only
add spellings (the names newsrooms use) and say which Natural Earth regions a
well-known region name stands for; they never supply a position.
"""
import base64
import hashlib
import json
import os
import sys
import unicodedata

TAG = "v5.1.2"
SOURCES = {
    "ne_50m_admin_0_countries.geojson":
        "3e458fc036ad0a66411f2c1e6cac49c5d7bfb81cb1123bc513b22511a2b7fdeb",
    "ne_10m_populated_places_simple.geojson":
        "fd3fa867a320cbd5c5b6bb5bc550afeec2939fb2cef688e508007282a55ac42f",
    "ne_10m_admin_1_states_provinces.geojson":
        "22d0e3ad85eb3e27f17cabf8ba2d50e554fbc27a87796ff891d958185da62fb5",
}
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GAZETTEER = os.path.join(ROOT, "jarvis", "intel", "data", "gazetteer.json")
WORLD = os.path.join(ROOT, "jarvis", "web", "static", "vendor", "world-50m.json")

MIN_PLACE_POP = 15000
MASK_W, MASK_H = 480, 240          # 0.75 degree cells

# Spellings newsrooms use for a country, by Natural Earth ADM0_A3.
COUNTRY_ALIASES = {
    "COD": ["DR Congo", "DRC", "Democratic Republic of Congo", "Congo-Kinshasa"],
    "COG": ["Republic of Congo", "Congo-Brazzaville"],
    "GBR": ["Britain", "UK"],
    "USA": ["United States"],
    "ARE": ["UAE"],
    "KOR": ["South Korea"],
    "PRK": ["North Korea"],
    "CIV": ["Ivory Coast"],
    "MMR": ["Burma"],
    "TUR": ["Türkiye", "Turkiye"],
    "CZE": ["Czech Republic"],
    "PSX": ["Palestinian territories", "Palestinian territory"],
    "CAF": ["CAR"],
    "BIH": ["Bosnia", "Bosnia-Herzegovina"],
    "SSD": ["South Sudan"],
    "RUS": ["Russia"],
    "SYR": ["Syria"],
    "IRN": ["Iran"],
    "LAO": ["Laos"],
    "MKD": ["North Macedonia"],
    "SWZ": ["Eswatini", "Swaziland"],
    "TLS": ["East Timor"],
}
# Country names that are also common given names or US states: placed only when
# a city or region of that country is named in the same text.
WEAK_COUNTRIES = {"GEO", "JOR", "TCD"}

# Spellings newsrooms use for a city: alias -> (ADM0_A3, Natural Earth name).
PLACE_ALIASES = {
    "Kiev": ("UKR", "Kyiv"),
    "Odesa": ("UKR", "Odessa"),
    "Zaporizhzhia": ("UKR", "Zaporizhzhya"),
    "Mykolaiv": ("UKR", "Mykolayiv"),
    "Lviv": ("UKR", "Lviv"),
    "Taiz": ("YEM", "Taizz"),
    "Hodeidah": ("YEM", "Al Hudaydah"),
    "Hudaydah": ("YEM", "Al Hudaydah"),
    "Mekelle": ("ETH", "Mekele"),
    "Hebron": ("PSX", "Al Khalil"),
    "Al-Fashir": ("SDN", "El Fasher"),
    "El-Fasher": ("SDN", "El Fasher"),
    "al-Fashir": ("SDN", "El Fasher"),
}

# Region names used on their own in headlines: name -> (ADM0_A3 the region is
# shown under, [Natural Earth admin-1 names whose label points are averaged]).
KNOWN_REGIONS = {
    "Gaza": ("PSX", ["Gaza Strip"]),
    "Gaza Strip": ("PSX", ["Gaza Strip"]),
    "West Bank": ("PSX", ["West Bank"]),
    "Darfur": ("SDN", ["North Darfur", "Western Darfur", "Southern Darfur",
                       "Central Darfur", "Eastern Darfur"]),
    "North Darfur": ("SDN", ["North Darfur"]),
    "Kordofan": ("SDN", ["North Kordufan", "South Kordufan"]),
    "Donbas": ("UKR", ["Donets'k", "Luhans'k"]),
    "Donetsk region": ("UKR", ["Donets'k"]),
    "Luhansk": ("UKR", ["Luhans'k"]),
    "Crimea": ("UKR", ["Crimea"]),
    "Tigray": ("ETH", ["Tigray"]),
    "Amhara": ("ETH", ["Amhara"]),
    "Kashmir": ("IND", ["Jammu and Kashmir"]),
    "North Kivu": ("COD", ["Nord-Kivu"]),
    "South Kivu": ("COD", ["Sud-Kivu"]),
    "Kivu": ("COD", ["Nord-Kivu", "Sud-Kivu"]),
    "Rakhine": ("MMR", ["Rakhine"]),
    "Cabo Delgado": ("MOZ", ["Cabo Delgado"]),
    "Borno": ("NGA", ["Borno"]),
    "Idlib province": ("SYR", ["Idlib"]),
    "Kherson region": ("UKR", ["Kherson"]),
}

# City names that are also ordinary English words or given names. They stay in
# the gazetteer only as capitals or when the country is named alongside.
COMMON_WORDS = {
    "nice", "mobile", "reading", "bath", "split", "male", "victoria", "george",
    "orange", "man", "of", "hope", "enterprise", "independence", "liberty",
    "union", "columbia", "washington", "santiago", "san", "david", "linda",
    "police", "central", "northern", "southern", "eastern", "western", "north",
    "south", "east", "west", "sale", "march", "bar", "van", "batman", "moss",
    "troy", "paradise", "surprise", "eagle", "normal", "university", "york",
    "best", "trump", "kent", "flint", "champion", "phoenix", "mission",
    "progress", "republic", "state", "general", "president", "colonel",
    "angel", "bell", "buffalo", "gary", "carol", "florence", "marion",
    "henderson", "jackson", "lincoln", "madison", "austin", "houston",
    "dallas", "charlotte", "chester", "howard", "warren", "wa", "ali", "taza",
    "obo", "long", "bo", "kindly", "same", "nan", "most", "born", "bam",
}


def fold(text):
    """Lower-case, strip diacritics and apostrophes: the gazetteer's match key."""
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return " ".join(text.replace("’", "'").replace("'", "").replace("-", " ").lower().split())


def load(src, name):
    path = os.path.join(src, name)
    with open(path, "rb") as fh:
        raw = fh.read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SOURCES[name]:
        raise SystemExit(f"{name}: SHA-256 {digest} does not match the pinned {SOURCES[name]}")
    return json.loads(raw)["features"]


def rings(geometry):
    polys = geometry["coordinates"] if geometry["type"] == "MultiPolygon" \
        else [geometry["coordinates"]]
    return [ring for poly in polys for ring in poly], polys


def in_ring(lon, lat, ring):
    inside = False
    j = len(ring) - 1
    for i in range(len(ring)):
        xi, yi = ring[i][0], ring[i][1]
        xj, yj = ring[j][0], ring[j][1]
        if (yi > lat) != (yj > lat) and lon < (xj - xi) * (lat - yi) / (yj - yi) + xi:
            inside = not inside
        j = i
    return inside


def land_mask(countries):
    """One bit per cell centre: is it inside any country polygon."""
    boxed = []
    for feature in countries:
        _, polys = rings(feature["geometry"])
        for poly in polys:
            outer = poly[0]
            xs = [p[0] for p in outer]
            ys = [p[1] for p in outer]
            boxed.append((min(xs), min(ys), max(xs), max(ys), poly))
    bits = bytearray((MASK_W * MASK_H + 7) // 8)
    count = 0
    for row in range(MASK_H):
        lat = 90 - (row + 0.5) * 180 / MASK_H
        for col in range(MASK_W):
            lon = -180 + (col + 0.5) * 360 / MASK_W
            for x0, y0, x1, y1, poly in boxed:
                if x0 <= lon <= x1 and y0 <= lat <= y1 and in_ring(lon, lat, poly[0]) \
                        and not any(in_ring(lon, lat, hole) for hole in poly[1:]):
                    index = row * MASK_W + col
                    bits[index >> 3] |= 1 << (index & 7)
                    count += 1
                    break
    return base64.b64encode(bytes(bits)).decode("ascii"), count


def borders(countries):
    """Country outlines as flat [lon, lat, ...] rings, rounded to 0.01 degree."""
    out = []
    for feature in countries:
        all_rings, _ = rings(feature["geometry"])
        for ring in all_rings:
            flat, last = [], None
            for lon, lat in ring:
                point = (round(lon, 2), round(lat, 2))
                if point != last:
                    flat.extend(point)
                    last = point
            if len(flat) >= 8:
                out.append(flat)
    return out


def build(src):
    countries = load(src, "ne_50m_admin_0_countries.geojson")
    places = load(src, "ne_10m_populated_places_simple.geojson")
    regions = load(src, "ne_10m_admin_1_states_provinces.geojson")
    warnings = []

    gaz_countries = []
    for feature in countries:
        p = feature["properties"]
        names = {p["NAME"], p["NAME_LONG"], p.get("NAME_EN") or ""}
        names.update(COUNTRY_ALIASES.get(p["ADM0_A3"], []))
        names = sorted(n for n in names if n and "." not in n and len(n) > 2
                       or n in ("UK", "UAE", "DRC", "CAR"))
        gaz_countries.append({
            "a3": p["ADM0_A3"], "name": p.get("NAME_EN") or p["NAME_LONG"], "names": names,
            "lat": round(p["LABEL_Y"], 3), "lon": round(p["LABEL_X"], 3),
            "weak": p["ADM0_A3"] in WEAK_COUNTRIES})
    known_a3 = {c["a3"] for c in gaz_countries}

    gaz_places, by_name = [], {}
    for feature in places:
        p = feature["properties"]
        capital = bool(p.get("adm0cap"))
        pop = int(p.get("pop_max") or 0)
        if pop < MIN_PLACE_POP and not capital:
            continue
        names = {p["name"], p.get("nameascii") or ""}
        names.update((p.get("namealt") or "").split("|"))
        names = sorted(n.strip() for n in names if n and len(n.strip()) > 2)
        entry = {"name": p["name"], "names": names, "a3": p["adm0_a3"],
                 "lat": round(p["latitude"], 4), "lon": round(p["longitude"], 4),
                 "pop": pop, "cap": capital,
                 "common": fold(p["name"]) in COMMON_WORDS}
        gaz_places.append(entry)
        by_name.setdefault((p["adm0_a3"], p["name"]), entry)
    for alias, (a3, name) in PLACE_ALIASES.items():
        entry = by_name.get((a3, name))
        if entry is None:
            warnings.append(f"place alias {alias!r}: no {name!r} in {a3}")
        elif alias not in entry["names"]:
            entry["names"].append(alias)

    admin = {}
    for feature in regions:
        p = feature["properties"]
        if p.get("latitude") is None or p.get("longitude") is None:
            continue
        for name in {p.get("name"), p.get("name_en")}:
            if name:
                admin.setdefault(name, []).append(p)
    gaz_regions = []
    for name, (a3, parts) in KNOWN_REGIONS.items():
        points = []
        for part in parts:
            found = admin.get(part) or admin.get(part + " State") or []
            if len(found) > 1:
                found = [p for p in found if p["adm0_a3"] == a3] or found[:1]
            if not found:
                warnings.append(f"region {name!r}: no admin-1 {part!r}")
                continue
            points.append((found[0]["latitude"], found[0]["longitude"]))
        if len(points) != len(parts):
            continue
        if a3 not in known_a3:
            warnings.append(f"region {name!r}: unknown country {a3}")
            continue
        gaz_regions.append({
            "name": name, "names": [name], "a3": a3,
            "lat": round(sum(p[0] for p in points) / len(points), 3),
            "lon": round(sum(p[1] for p in points) / len(points), 3)})

    mask, land = land_mask(countries)
    world = {
        "source": f"Natural Earth {TAG} (public domain), ne_50m_admin_0_countries",
        "borders": borders(countries),
        "mask": {"w": MASK_W, "h": MASK_H, "bits": mask, "land": land},
    }
    gazetteer = {
        "source": f"Natural Earth {TAG} (public domain)",
        "countries": gaz_countries, "places": gaz_places, "regions": gaz_regions,
    }
    for path, payload in ((GAZETTEER, gazetteer), (WORLD, world)):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            fh.write("\n")
        with open(path, "rb") as fh:
            print(f"{os.path.relpath(path, ROOT)}  {os.path.getsize(path)} bytes  "
                  f"sha256 {hashlib.sha256(fh.read()).hexdigest()}")
    print(f"countries {len(gaz_countries)}  places {len(gaz_places)}  "
          f"regions {len(gaz_regions)}  border rings {len(world['borders'])}  land cells {land}")
    for line in warnings:
        print("warning:", line)
    return 1 if warnings else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    sys.exit(build(sys.argv[1]))
