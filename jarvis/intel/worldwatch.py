"""World watch: where armed conflict is being reported, placed on a map honestly.

GeoSecurity knows where this device is. This adds what is happening in the
world around it: headlines and videos from named newsrooms, and machine-coded
armed-force events from GDELT, reduced to the ones about armed conflict and
placed on the globe at `/world`.

It is context for the owner, never a verdict about this machine. It raises no
security finding, moves no score and authorizes nothing.

What it will and will not do:

  Position.   A report is placed only where its own text names a place found in
              the Natural Earth gazetteer, or where its publisher geocoded it
              (GDELT). The precision travels with it: city, region or country.
              A report naming only a country is shown as country-level, at the
              country's label point, and never feeds a zone. A report whose
              place cannot be established stays in the list as unmapped.
  Zones.      A conflict zone here is a cluster of located reports: several
              reports from several independent publishers, at least two of
              them a newsroom's own, within a few hundred kilometres over two
              days. Machine-coded events add to a cluster a newsroom already
              reports; they never make one. It is drawn as the outline of those
              reports. It is not a front line and not an official boundary.
  Privacy.    Every request is the same whoever and wherever the owner is: a
              fixed list of public feeds, fetched whole. The device position
              and the trusted zones are never sent anywhere; distance to a zone
              is worked out here. The page itself contacts nothing but JARVIS.
  Trust.      Feed content is untrusted. It is parsed with entities refused,
              reduced to plain bounded text, and a link is kept only when it
              points at the publisher's own site (http or https for GDELT, whose
              links go to arbitrary news sites and are labelled by domain).
  Bounds.     Byte caps per source, a cap on stored reports, three days of
              retention and a cap on GDELT files fetched per run.
"""

import csv
import hashlib
import html
import io
import json
import math
import os
import re
import unicodedata
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

try:
    from jarvis.core.finding import LOCAL_HOST
except ImportError:  # releases that predate native hosts: Linux is the WSL side
    LOCAL_HOST = "win" if os.name == "nt" else "wsl"
from jarvis.core.util import now
from jarvis.intel import feeds

GAZETTEER_PATH = os.path.join(os.path.dirname(__file__), "data", "gazetteer.json")

# key -> (publisher, feed URL, hosts a report link may point at). Several feeds
# of one publisher count as one publisher when a zone needs independent sources.
_BBC = ("bbc.co.uk", "bbc.com")
NEWS = {
    "bbc_world": ("BBC News", "https://feeds.bbci.co.uk/news/world/rss.xml", _BBC),
    "bbc_africa": ("BBC News", "https://feeds.bbci.co.uk/news/world/africa/rss.xml", _BBC),
    "bbc_mideast": ("BBC News", "https://feeds.bbci.co.uk/news/world/middle_east/rss.xml", _BBC),
    "bbc_europe": ("BBC News", "https://feeds.bbci.co.uk/news/world/europe/rss.xml", _BBC),
    "bbc_asia": ("BBC News", "https://feeds.bbci.co.uk/news/world/asia/rss.xml", _BBC),
    "aljazeera": ("Al Jazeera", "https://www.aljazeera.com/xml/rss/all.xml",
                  ("aljazeera.com",)),
    "dw": ("DW", "https://rss.dw.com/rdf/rss-en-all", ("dw.com",)),
    "france24": ("France 24", "https://www.france24.com/en/rss", ("france24.com",)),
    "france24_africa": ("France 24", "https://www.france24.com/en/africa/rss",
                        ("france24.com",)),
    "france24_mideast": ("France 24", "https://www.france24.com/en/middle-east/rss",
                         ("france24.com",)),
    "guardian": ("The Guardian", "https://www.theguardian.com/world/rss",
                 ("theguardian.com",)),
    "sky": ("Sky News", "https://feeds.skynews.com/feeds/rss/world.xml", ("sky.com",)),
    "npr": ("NPR", "https://feeds.npr.org/1004/rss.xml", ("npr.org",)),
    "un": ("UN News",
           "https://news.un.org/feed/subscribe/en/news/topic/peace-and-security/feed/rss.xml",
           ("un.org",)),
}
# Newsroom channels, read through YouTube's public per-channel Atom feed.
YOUTUBE_FEED = "https://www.youtube.com/feeds/videos.xml?channel_id="
VIDEO = {
    "yt_aljazeera": ("Al Jazeera", "UCNye-wNBqNL5ZzHSJj3l8Bg"),
    "yt_bbc": ("BBC News", "UC16niRr50-MSBwiO3YDb3RA"),
    "yt_dw": ("DW", "UCknLrEdhRCp1aegoMqRaCZg"),
    "yt_france24": ("France 24", "UCQfwfsi5VrQ8yKZ-UWmAEFg"),
    "yt_sky": ("Sky News", "UCoMdktPbSTixAyNGwb-UYkQ"),
    "yt_reuters": ("Reuters", "UChqUTb7kYRX8-EiaN3XFrSQ"),
    "yt_ap": ("Associated Press", "UC52X5wxOL_s5yw0dQk7NtgA"),
}
VIDEO_HOSTS = ("youtube.com",)
GDELT_LAST = "http://data.gdeltproject.org/gdeltv2/lastupdate.txt"
GDELT_FILE = "http://data.gdeltproject.org/gdeltv2/{stamp}.export.CSV.zip"

FEED_MAX_BYTES = 2 * 1024 * 1024
GDELT_MAX_BYTES = 4 * 1024 * 1024
GDELT_MAX_INFLATED = 48 * 1024 * 1024
FETCH_TIMEOUT_S = 20
GDELT_FILES_PER_RUN = 8
GDELT_BACKFILL_S = 24 * 3600
GDELT_STEP_S = 900

WINDOW_S = 72 * 3600               # reports older than this are forgotten
MAX_ITEMS = 2500
MAX_TITLE, MAX_SUMMARY, MAX_URL = 200, 280, 400

ZONE_WINDOW_S = 48 * 3600
ZONE_EPS_KM = 250.0                # reports this close belong together
ZONE_CORE_REPORTS = 3              # reports within eps for a point to seed a zone
ZONE_MIN_REPORTS = 5
ZONE_MIN_SOURCES = 3               # independent publishers
ZONE_MIN_NEWSROOM = 2              # of the reports, this many must be a newsroom's own
ZONE_BUFFER_KM = 60.0
ZONE_MAX = 40
STALE_S = 45 * 60                  # the view calls its data stale past this

META_ITEMS = "world_items"
META_SOURCES = "world_sources"
META_GDELT = "world_gdelt_seen"
META_STATE = "world_state"
META_SINCE = "world_since"
HISTORY_BUCKET_S = 6 * 3600

EARTH_KM = 6371.0

# CAMEO codes GDELT uses for the use of armed force.
CAMEO = {
    "183": "Bombing reported", "1831": "Suicide bombing reported",
    "1832": "Vehicle bombing reported", "1833": "Roadside bombing reported",
    "1834": "Bombing of a location reported",
    "190": "Use of military force reported", "191": "Blockade reported",
    "192": "Occupation of territory reported", "193": "Small-arms fighting reported",
    "194": "Artillery or tank fighting reported", "195": "Air attack reported",
    "196": "Ceasefire violation reported",
    "200": "Mass violence reported", "201": "Mass expulsion reported",
    "202": "Mass killing reported", "203": "Ethnic cleansing reported",
    "204": "Use of mass-casualty weapons reported",
}

# One strong term, or three weak ones, makes a report about armed conflict.
# Figurative uses are removed first.
_FIGURATIVE = re.compile(
    r"\b(?:trade|price|bidding|culture|turf|star|world|cold|tariff|currency) wars?\b"
    r"|\bwar of words\b|\bwar on (?:drugs|poverty|waste|cancer)\b"
    r"|\b(?:hunger|general|rail|train|doctors'?|nurses'?|teachers'?|workers'?|pilots'?|"
    r"dockers'?|labou?r|writers'?|actors'?|transport|tube|bus|postal) strikes?\b"
    r"|\bstrikes? (?:action|ballot|deal)\b|\bon strike\b|\blightning strikes?\b"
    r"|\b(?:heart|panic|shark|bear|dog|acid|knife|cyber|ransomware|phishing) ?-?attacks?\b"
    r"|\bcyberattacks?\b|\bfighting (?:for|fires?|a fire|the fire|blazes?|inflation|corruption|"
    r"cancer|crime|poverty|climate|back tears|talk)\b|\bfire ?fighting\b|\bfirefighters?\b"
    r"|\bcustody battle\b|\blegal battle\b|\bcourt battle\b|\bbattle (?:with|against) "
    r"(?:cancer|illness|addiction|depression)\b|\bbox office bomb\b|\bphoto ?bomb",
    re.I)
_STRONG = re.compile(
    r"\b(?:air ?strikes?|air raids?|shelling|shelled|artillery|missiles?|rocket (?:attack|fire|strike)s?"
    r"|drone (?:attack|strike)s?|bombardments?|bombings?|bombed|car bomb|suicide bomb\w*"
    r"|offensive|counter-?offensive|front ?lines?|troops|rebels?|rebel forces|militants?"
    r"|insurgen\w+|jihadists?|militias?|paramilitar\w+|armed groups?|gunmen|ceasefire|truce"
    r"|invaded|invades|clashes|fighting|besieged|siege|warplanes?"
    r"|fighter jets?|military operation|ground operation|war crimes?|civil war|coup"
    r"|mortars?|landmines?|ambush(?:ed)?|massacres?|hostages?|shot down|shoots? down"
    r"|blockade|occupation forces|killed in (?:an? )?(?:strike|attack|raid|blast|explosion)"
    r"|strikes? kills?|cross-border (?:attack|raid|fire)|warring|guerrillas?)\b", re.I)
_WEAK = re.compile(
    r"\b(?:attacks?|attacked|killed|kills|strikes?|war|military|army|forces|conflict|violence"
    r"|explosions?|blast|wounded|casualties|displaced|raids?|soldiers?|weapons?|armed|invasion|battle)\b", re.I)

# "Moscow says", "Kyiv accuses": the place is the speaker, not where it happened.
_SPEECH = frozenset("""says said say warns warned accuses accused denies denied claims
    claimed vows vowed urges urged rejects rejected condemns condemned blames blamed
    announces announced insists insisted threatens threatened calls called demands
    demanded confirms confirmed tells told pledges pledged seeks wants hails backs""".split())

_WORD = re.compile(r"[^\W\d_]+(?:['’][^\W\d_]+)*")
_TAG = re.compile(r"<[^>]{0,400}>")
_SPACE = re.compile(r"\s+")
_STAMP = re.compile(r"^\d{14}$")
_INVISIBLE = {"Cc", "Cf", "Cs", "Co", "Cn"}


# -- text ---------------------------------------------------------------------

def clean(text, limit):
    """Untrusted feed text as plain, bounded, visible characters."""
    text = html.unescape(_TAG.sub(" ", str(text or "")))
    text = "".join(" " if unicodedata.category(ch) in _INVISIBLE else ch for ch in text)
    text = _SPACE.sub(" ", text).strip()
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def fold(text):
    """The gazetteer's match key: no case, diacritics, apostrophes or hyphens."""
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return " ".join(text.replace("’", "'").replace("'", "").replace("-", " ").lower().split())


def is_conflict(title, summary=""):
    """Is this report about armed conflict. The headline has to say so itself:
    a summary can confirm a headline, never carry one that names no violence."""
    title = _FIGURATIVE.sub(" ", title or "")
    if _STRONG.search(title):
        return True
    weak = {m.group(0).lower() for m in _WEAK.finditer(title)}
    if len(weak) >= 3:
        return True
    return bool(weak) and bool(_STRONG.search(_FIGURATIVE.sub(" ", summary or "")))


def link(url, hosts=None):
    """An http(s) link, on one of `hosts` when given; else ''."""
    url = str(url or "").strip()
    if len(url) > MAX_URL or any(ch.isspace() or ord(ch) < 32 for ch in url):
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    if not host or parts.username or parts.password:
        return ""
    if hosts is None:
        return url if parts.scheme in ("http", "https") else ""
    if parts.scheme != "https":
        return ""
    return url if any(host == h or host.endswith("." + h) for h in hosts) else ""


def domain(url):
    host = (urlsplit(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


# -- gazetteer ----------------------------------------------------------------

class Gazetteer:
    """Natural Earth names -> coordinates. Built by scripts/tools/build_world_assets.py."""

    MAX_WORDS = 4
    SOLO_POP = 100000              # a city named without its country must be this large

    def __init__(self, data):
        self.country = {c["a3"]: c for c in data["countries"]}
        self.index = {}
        for kind in ("countries", "regions", "places"):
            for entry in data[kind]:
                for name in entry["names"]:
                    key = fold(name)
                    if key:
                        self.index.setdefault(key, []).append((kind, entry))

    @classmethod
    def load(cls, path=GAZETTEER_PATH):
        with open(path, encoding="utf-8", errors="replace") as fh:
            return cls(json.load(fh))

    def mentions(self, text, in_title):
        words = [(m.group(0), m.start()) for m in _WORD.finditer(text or "")]
        keys = []
        for word, _ in words:
            if word.lower().endswith(("'s", "’s")):
                word = word[:-2]
            keys.append(fold(word))
        out, i = [], 0
        while i < len(words):
            hit = None
            if words[i][0][:1].isupper():
                for n in range(min(self.MAX_WORDS, len(words) - i), 0, -1):
                    found = self.index.get(" ".join(keys[i:i + n]))
                    if found:
                        hit = (n, found)
                        break
            if not hit:
                i += 1
                continue
            n, found = hit
            after = words[i + n][0].lower() if i + n < len(words) else ""
            out.append({"entries": found, "pos": words[i][1], "in_title": in_title,
                        "actor": after in _SPEECH})
            i += n
        return out

    def locate(self, title, summary=""):
        """Where a report's own words put it, or None. Never a guess.

        -> {lat, lon, place, country, a3, precision, ambiguous}
        """
        found = self.mentions(title, True) + self.mentions(summary, False)
        if not found:
            return None
        named = {e["a3"] for m in found for kind, e in m["entries"]}
        countries = {e["a3"] for m in found for kind, e in m["entries"] if kind == "countries"}
        best = None
        for m in found:
            options = [(kind, e) for kind, e in m["entries"] if kind != "countries"]
            if not options or m["actor"]:
                continue
            options.sort(key=lambda o: (o[1]["a3"] in countries, o[0] == "regions",
                                        o[1].get("cap", False), o[1].get("pop", 0)),
                         reverse=True)
            kind, entry = options[0]
            backed = entry["a3"] in countries
            if kind == "places" and not backed:
                # Named without its country: only a capital or a large city, with a
                # name long enough not to be an abbreviation, and a higher bar when
                # it appears only in the summary.
                floor = self.SOLO_POP if m["in_title"] else 5 * self.SOLO_POP
                if entry.get("common") or len(entry["name"]) < 4 \
                        or not (entry["cap"] or entry["pop"] >= floor):
                    continue
            rivals = [e for k, e in options[1:] if e.get("pop", 0) * 5 >= entry.get("pop", 1)]
            rank = (m["in_title"], backed, -m["pos"])
            if best is None or rank > best[0]:
                best = (rank, kind, entry, bool(rivals) and not backed)
        if best:
            _, kind, entry, ambiguous = best
            return {"lat": entry["lat"], "lon": entry["lon"], "place": entry["name"],
                    "country": self.country.get(entry["a3"], {}).get("name", ""),
                    "a3": entry["a3"], "precision": "city" if kind == "places" else "region",
                    "ambiguous": ambiguous and kind == "places"}
        pick = None
        for m in found:
            for kind, entry in m["entries"]:
                if kind != "countries":
                    continue
                # A weak name (Georgia, Jordan, Chad) needs a place of that country too.
                if entry["weak"] and not any(
                        e["a3"] == entry["a3"] for o in found for k, e in o["entries"]
                        if k != "countries"):
                    continue
                rank = (not m["actor"], m["in_title"], -m["pos"])
                if pick is None or rank > pick[0]:
                    pick = (rank, entry)
        if pick is None or not named:
            return None
        entry = pick[1]
        return {"lat": entry["lat"], "lon": entry["lon"], "place": entry["name"],
                "country": entry["name"], "a3": entry["a3"], "precision": "country",
                "ambiguous": False}


_gazetteer = None


def gazetteer():
    global _gazetteer
    if _gazetteer is None:
        _gazetteer = Gazetteer.load()
    return _gazetteer


# -- parsing ------------------------------------------------------------------

def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _when(text):
    """Epoch seconds from an RSS or Atom date, or None."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        stamp = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        try:
            stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.timestamp()


def parse_feed(raw):
    """RSS 2.0, RDF or Atom -> [{title, summary, url, ts}]. Entities are refused."""
    head = raw[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in raw.lower():
        raise ValueError("feed declares a DTD or entities; refused")
    root = ET.fromstring(raw)
    out = []
    for node in root.iter():
        if _local(node.tag) not in ("item", "entry"):
            continue
        row = {"title": "", "summary": "", "url": "", "ts": None}
        for child in node:
            name = _local(child.tag)
            if name == "title":
                row["title"] = child.text or ""
            elif name in ("description", "summary") and not row["summary"]:
                row["summary"] = child.text or ""
            elif name == "group":                      # YouTube media:group
                for sub in child:
                    if _local(sub.tag) == "description" and not row["summary"]:
                        row["summary"] = sub.text or ""
            elif name == "link":
                href = child.attrib.get("href") or child.text or ""
                if child.attrib.get("rel", "alternate") == "alternate" and not row["url"]:
                    row["url"] = href
            elif name in ("pubDate", "published", "date") and row["ts"] is None:
                row["ts"] = _when(child.text)
        out.append(row)
    return out


def _slug(url):
    """Readable words from a link's last path segment, or ''."""
    path = urlsplit(url).path.rstrip("/")
    for segment in reversed(path.split("/")):
        words = [w for w in re.split(r"[-_]+", segment.rsplit(".", 1)[0])
                 if w.isalpha() and len(w) < 24]
        if len(words) >= 4:
            return clean(" ".join(words), 110)
    return ""


def parse_gdelt(raw, ts_now, gaz=None):
    """GDELT 2.0 event export -> armed-force events GDELT placed at a city or region.

    GDELT codes every place an article mentions, speakers' capitals included, so
    these positions are unverified: they are kept apart from newsroom reports
    and never start a zone on their own (see `zones`). When the article's link
    names countries and none is the country GDELT chose, the event is dropped.
    """
    out, seen = [], set()
    for row in csv.reader(io.StringIO(raw.decode("utf-8", "replace")), delimiter="\t"):
        if len(row) != 61:
            continue
        code, root, geo_type = row[26], row[28], row[51]
        if not (root in ("19", "20") or code.startswith("183")) or geo_type not in ("3", "4", "5"):
            continue
        try:
            lat, lon = float(row[56]), float(row[57])
            added = datetime.strptime(row[59], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
            day = datetime.strptime(row[1], "%Y%m%d").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if not (-90 <= lat <= 90 and -180 <= lon <= 180) or (lat == 0 and lon == 0):
            continue
        # GDELT also codes events an article merely recalls; keep the current ones.
        if abs((added - day).total_seconds()) > 2 * 86400:
            continue
        ts = added.timestamp()
        if ts > ts_now + 3600 or ts < ts_now - WINDOW_S:
            continue
        url = link(row[60])
        if not url:
            continue
        hint = _slug(url)
        if hint and not is_conflict(hint):
            continue
        place = clean(row[52], 90)
        country = place.rsplit(",", 1)[-1].strip()
        if hint and gaz is not None:
            # Slugs are lower-case; title-case them so names can match.
            named = {e["a3"] for m in gaz.mentions(hint.title(), True)
                     for kind, e in m["entries"]}
            here = {e["a3"] for kind, e in gaz.index.get(fold(country), [])
                    if kind == "countries"}
            if named and here and not named & here:
                continue
        key = (url, round(lat, 1), round(lon, 1))
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "kind": "event", "src": "gdelt", "source": domain(url),
            "title": CAMEO.get(code) or CAMEO.get(code[:3]) or "Use of armed force reported",
            "summary": hint, "url": url, "ts": ts, "lat": round(lat, 4), "lon": round(lon, 4),
            "place": place.split(",")[0].strip(), "country": country,
            "a3": "", "precision": "region" if geo_type == "5" else "city", "ambiguous": False})
    return out


def _item_id(item):
    basis = f"{item['source']}|{item['kind']}|{item['url']}|{item.get('place', '')}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def reports(rows, key, source, hosts, kind, gaz, ts_now):
    """Feed rows -> the conflict reports among them, located where their text allows."""
    out = []
    for row in rows:
        title = clean(row["title"], MAX_TITLE)
        summary = clean(row["summary"], MAX_SUMMARY)
        url = link(row["url"], hosts)
        ts = row["ts"]
        if not title or not url or ts is None or ts > ts_now + 3600 or ts < ts_now - WINDOW_S:
            continue
        # A video description is mostly channel boilerplate; judge videos by title.
        if not is_conflict(title, "" if kind == "video" else summary):
            continue
        where = gaz.locate(title, "" if kind == "video" else summary)
        item = {"kind": kind, "src": key, "source": source, "title": title,
                "summary": "" if kind == "video" else summary, "url": url, "ts": ts}
        item.update(where or {"lat": None, "lon": None, "place": "", "country": "", "a3": "",
                              "precision": "unmapped", "ambiguous": False})
        out.append(item)
    return out


# -- geometry -----------------------------------------------------------------

def distance_km(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    a = (math.sin((p2 - p1) / 2) ** 2
         + math.cos(p1) * math.cos(p2) * math.sin(math.radians(lon2 - lon1) / 2) ** 2)
    return 2 * EARTH_KM * math.asin(min(1.0, math.sqrt(a)))


def _bearing(lat1, lon1, lat2, lon2):
    p1, p2, dl = math.radians(lat1), math.radians(lat2), math.radians(lon2 - lon1)
    return math.atan2(math.sin(dl) * math.cos(p2),
                      math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl))


def _plane(lat0, lon0, lat, lon):
    """Azimuthal-equidistant km offsets of a point from (lat0, lon0)."""
    d = distance_km(lat0, lon0, lat, lon)
    b = _bearing(lat0, lon0, lat, lon)
    return d * math.sin(b), d * math.cos(b)


def _sphere(lat0, lon0, x, y):
    """Inverse of _plane."""
    d = math.hypot(x, y) / EARTH_KM
    if d == 0:
        return lat0, lon0
    b, p0 = math.atan2(x, y), math.radians(lat0)
    lat = math.asin(math.sin(p0) * math.cos(d) + math.cos(p0) * math.sin(d) * math.cos(b))
    lon = math.radians(lon0) + math.atan2(math.sin(b) * math.sin(d) * math.cos(p0),
                                          math.cos(d) - math.sin(p0) * math.sin(lat))
    return math.degrees(lat), (math.degrees(lon) + 540) % 360 - 180


def _hull(points):
    """Convex hull (monotone chain) of (x, y) points, counter-clockwise."""
    points = sorted(set(points))
    if len(points) < 3:
        return points

    def half(seq):
        out = []
        for p in seq:
            while len(out) >= 2 and ((out[-1][0] - out[-2][0]) * (p[1] - out[-2][1])
                                     - (out[-1][1] - out[-2][1]) * (p[0] - out[-2][0])) <= 0:
                out.pop()
            out.append(p)
        return out[:-1]
    return half(points) + half(reversed(points))


def _inside(x, y, ring):
    inside, j = False, len(ring) - 1
    for i in range(len(ring)):
        xi, yi, xj, yj = ring[i][0], ring[i][1], ring[j][0], ring[j][1]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            inside = not inside
        j = i
    return inside


def _centroid(points):
    """Mean position of (lat, lon, weight) points on the sphere."""
    x = y = z = 0.0
    for lat, lon, weight in points:
        p, l = math.radians(lat), math.radians(lon)
        x += weight * math.cos(p) * math.cos(l)
        y += weight * math.cos(p) * math.sin(l)
        z += weight * math.sin(p)
    return math.degrees(math.atan2(z, math.hypot(x, y))), math.degrees(math.atan2(y, x))


def zones(items, ts_now):
    """Clusters of located reports.

    Country-level reports never take part. A machine-coded event takes part
    only within ZONE_EPS_KM of a newsroom report, and is marked `corroborated`
    on the item; elsewhere its position is nobody's but GDELT's.
    """
    spots, anchors = {}, set()
    for item in items:
        item.pop("corroborated", None)
        if item["precision"] not in ("city", "region") or item["ts"] < ts_now - ZONE_WINDOW_S:
            continue
        key = (round(item["lat"], 1), round(item["lon"], 1))
        spots.setdefault(key, []).append(item)
        if item["kind"] != "event":
            anchors.add(key)
    for key in list(spots):
        if key in anchors or any(
                abs(key[0] - a[0]) <= 3 and distance_km(key[0], key[1], a[0], a[1]) <= ZONE_EPS_KM
                for a in anchors):
            for item in spots[key]:
                if item["kind"] == "event":
                    item["corroborated"] = True
        else:
            del spots[key]
    keys = list(spots)
    near = {k: [] for k in keys}
    for i, a in enumerate(keys):
        for b in keys[i + 1:]:
            if abs(a[0] - b[0]) <= 3 and distance_km(a[0], a[1], b[0], b[1]) <= ZONE_EPS_KM:
                near[a].append(b)
                near[b].append(a)
    weight = {k: len(spots[k]) for k in keys}
    core = {k for k in keys
            if weight[k] + sum(weight[n] for n in near[k]) >= ZONE_CORE_REPORTS}
    label, clusters = {}, []
    for k in sorted(core, key=lambda k: -weight[k]):
        if k in label:
            continue
        members, queue = [], [k]
        label[k] = len(clusters)
        while queue:
            cur = queue.pop()
            members.append(cur)
            if cur not in core:
                continue
            for n in near[cur]:
                if n not in label:
                    label[n] = len(clusters)
                    queue.append(n)
        clusters.append(members)
    out = []
    for members in clusters:
        group = [item for k in members for item in spots[k]]
        sources = {item["source"] for item in group}
        if len(group) < ZONE_MIN_REPORTS or len(sources) < ZONE_MIN_SOURCES \
                or sum(1 for item in group if item["kind"] != "event") < ZONE_MIN_NEWSROOM:
            continue
        lat0, lon0 = _centroid([(k[0], k[1], weight[k]) for k in members])
        ring = []
        for k in members:
            x, y = _plane(lat0, lon0, k[0], k[1])
            ring.extend((x + ZONE_BUFFER_KM * math.cos(t * math.pi / 8),
                         y + ZONE_BUFFER_KM * math.sin(t * math.pi / 8)) for t in range(16))
        hull = _hull(ring)
        places, countries = {}, {}
        for item in group:
            places[item["place"]] = places.get(item["place"], 0) + 1
        # Named after what newsrooms call it; a zone always holds one such report.
        for item in group:
            if item["kind"] != "event" and item["country"]:
                countries[item["country"]] = countries.get(item["country"], 0) + 1
        top = sorted(places, key=lambda p: (-places[p], p))
        named = sorted({i["place"] for i in group if i["kind"] != "event"},
                       key=lambda p: (-places[p], p))
        if not named:
            continue
        country = max(sorted(countries), key=lambda c: countries[c]) if countries else ""
        recent = sum(1 for item in group if item["ts"] >= ts_now - 86400)
        earlier = len(group) - recent
        # Newsroom reports first: they are what the zone stands on.
        group.sort(key=lambda item: (item["kind"] == "event", -item["ts"]))
        out.append({
            "id": hashlib.sha256(f"{round(lat0)}|{round(lon0)}|{country}".encode()).hexdigest()[:12],
            "name": f"{named[0]} · {country}" if country and named[0] != country else named[0],
            "country": country, "lat": round(lat0, 3), "lon": round(lon0, 3),
            "polygon": [[round(v, 3) for v in reversed(_sphere(lat0, lon0, x, y))]
                        for x, y in hull],
            "radius_km": round(max(math.hypot(x, y) for x, y in hull)),
            "reports": len(group), "sources": len(sources), "places": top[:5],
            "newsroom": sum(1 for item in group if item["kind"] != "event"),
            # Reports per six hours across the zone window, oldest first.
            "history": [sum(1 for item in group
                            if int((ts_now - item["ts"]) // HISTORY_BUCKET_S) == bucket)
                        for bucket in range(ZONE_WINDOW_S // HISTORY_BUCKET_S - 1, -1, -1)],
            "last_24h": recent, "prior_24h": earlier,
            "last_ts": max(item["ts"] for item in group),
            "items": [item["id"] for item in group[:8]],
        })
    out.sort(key=lambda z: (-z["reports"], z["name"]))
    return out[:ZONE_MAX]


def zone_distance_km(zone, lat, lon):
    """Distance from a point to a zone's outline; 0 when inside it."""
    ring = [_plane(zone["lat"], zone["lon"], p[1], p[0]) for p in zone["polygon"]]
    x, y = _plane(zone["lat"], zone["lon"], lat, lon)
    if len(ring) >= 3 and _inside(x, y, ring):
        return 0.0
    best = None
    for i, (ax, ay) in enumerate(ring):
        bx, by = ring[(i + 1) % len(ring)]
        dx, dy = bx - ax, by - ay
        span = dx * dx + dy * dy
        t = 0.0 if span == 0 else max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / span))
        d = math.hypot(x - ax - t * dx, y - ay - t * dy)
        best = d if best is None or d < best else best
    return best if best is not None else distance_km(zone["lat"], zone["lon"], lat, lon)


# -- store --------------------------------------------------------------------

def _meta(store, key, default):
    try:
        value = json.loads(store.get_meta(key, "") or "null")
    except (ValueError, AttributeError):
        return default
    return value if isinstance(value, type(default)) else default


def _gdelt_stamps(latest, seen, ts_now):
    """Stamps to fetch this run: the newest unseen files of the last day."""
    try:
        end = datetime.strptime(latest, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return []
    end = min(end, ts_now + GDELT_STEP_S)
    out, t = [], end
    while t > end - GDELT_BACKFILL_S and len(out) < GDELT_FILES_PER_RUN:
        stamp = datetime.fromtimestamp(t, timezone.utc).strftime("%Y%m%d%H%M%S")
        if stamp not in seen:
            out.append(stamp)
        t -= GDELT_STEP_S
    return out


def refresh(store, fetch=feeds.fetch, ts_now=None, gaz=None):
    """Fetch every source once, merge, forget old reports, recompute zones.

    A source that fails keeps its last good reports until they age out, and its
    failure is recorded against it. -> {sources, items, mapped, zones, failed}
    """
    ts_now = now() if ts_now is None else ts_now
    gaz = gaz or gazetteer()
    status = _meta(store, META_SOURCES, {})
    fresh = []

    def attempt(key, name, work):
        entry = status.setdefault(key, {})
        entry.update({"name": name, "tried": ts_now})
        try:
            got = work()
        except Exception as exc:               # one bad source must not stop the rest
            entry["error"] = clean(f"{type(exc).__name__}: {exc}", 160)
            return
        entry.update({"ok": ts_now, "error": "", "reports": len(got),
                      "mapped": sum(1 for g in got if g["precision"] != "unmapped")})
        fresh.extend(got)

    for key, (name, url, hosts) in NEWS.items():
        attempt(key, name, lambda url=url, key=key, name=name, hosts=hosts: reports(
            parse_feed(fetch(url, FEED_MAX_BYTES, timeout=FETCH_TIMEOUT_S)),
            key, name, hosts, "news", gaz, ts_now))
    for key, (name, channel) in VIDEO.items():
        attempt(key, name, lambda channel=channel, key=key, name=name: reports(
            parse_feed(fetch(YOUTUBE_FEED + channel, FEED_MAX_BYTES, timeout=FETCH_TIMEOUT_S)),
            key, name, VIDEO_HOSTS, "video", gaz, ts_now))

    seen = [s for s in _meta(store, META_GDELT, []) if isinstance(s, str) and _STAMP.match(s)]

    def gdelt():
        text = fetch(GDELT_LAST, 4096, timeout=FETCH_TIMEOUT_S).decode("ascii", "replace")
        match = re.search(r"/(\d{14})\.export\.CSV\.zip", text)
        if not match:
            raise ValueError("no export file listed")
        got, errors = [], []
        for stamp in _gdelt_stamps(match.group(1), set(seen), ts_now):
            try:
                raw = fetch(GDELT_FILE.format(stamp=stamp), GDELT_MAX_BYTES,
                            timeout=FETCH_TIMEOUT_S, max_inflated=GDELT_MAX_INFLATED)
            except Exception as exc:
                errors.append(f"{stamp}: {type(exc).__name__}")
                continue
            got.extend(parse_gdelt(raw, ts_now, gaz))
            seen.append(stamp)
        if errors and not got:
            raise ValueError("; ".join(errors[:3]))
        return got

    attempt("gdelt", "GDELT events", gdelt)

    merged = {item["id"]: item for item in _meta(store, META_ITEMS, [])
              if isinstance(item, dict) and item.get("ts", 0) >= ts_now - WINDOW_S}
    for item in fresh:
        item["id"] = _item_id(item)
        merged.setdefault(item["id"], item)
    items = sorted(merged.values(), key=lambda item: -item["ts"])[:MAX_ITEMS]
    cutoff = datetime.fromtimestamp(ts_now - GDELT_BACKFILL_S - 3600, timezone.utc)
    seen = sorted({s for s in seen if s >= cutoff.strftime("%Y%m%d%H%M%S")})

    found = zones(items, ts_now)
    if not _meta(store, META_SINCE, 0.0):
        store.set_meta(META_SINCE, json.dumps(float(ts_now)))
    failed = sorted(k for k, v in status.items() if v.get("error"))
    state = {"generated_at": ts_now, "zones": found,
             "oldest": min((item["ts"] for item in items), default=None)}
    for key, value in ((META_ITEMS, items), (META_SOURCES, status),
                       (META_GDELT, seen), (META_STATE, state)):
        store.set_meta(key, json.dumps(value, separators=(",", ":")))
    store.commit()
    return {"sources": len(status), "failed": failed, "items": len(items),
            "mapped": sum(1 for item in items if item["precision"] != "unmapped"),
            "zones": len(found)}


def _near(found, lat, lon):
    best = None
    for zone in found:
        d = zone_distance_km(zone, lat, lon)
        if best is None or d < best["distance_km"]:
            best = {"zone": zone["id"], "name": zone["name"], "distance_km": round(d),
                    "inside": d == 0}
    return best


def state(store, location=None, trusted=None, ts_now=None):
    """The payload `/world` draws. `location` and `trusted` never leave this machine."""
    ts_now = now() if ts_now is None else ts_now
    saved = _meta(store, META_STATE, {})
    items = [item for item in _meta(store, META_ITEMS, [])
             if isinstance(item, dict) and item.get("ts", 0) >= ts_now - WINDOW_S]
    found = saved.get("zones") or []
    generated = saved.get("generated_at")
    anchors = []
    if (location or {}).get("status") == "ok" and "lat" in location:
        anchors.append({"name": "this device", "kind": "device",
                        "source": location.get("source") or "",
                        "lat": location["lat"], "lon": location["lon"]})
    for zone in trusted or []:
        anchors.append({"name": zone["name"], "kind": "trusted zone", "source": "you",
                        "lat": zone["lat"], "lon": zone["lon"]})
    for anchor in anchors:
        anchor["nearest"] = _near(found, anchor["lat"], anchor["lon"])
    sources = _meta(store, META_SOURCES, {})
    return {
        "generated_at": generated,
        # When collection began. Feeds carry about a day of items, so a trend is
        # only meaningful once JARVIS itself has collected for the whole window.
        "since": _meta(store, META_SINCE, 0.0) or None,
        "trend_ready": bool(_meta(store, META_SINCE, 0.0))
        and ts_now - _meta(store, META_SINCE, 0.0) >= ZONE_WINDOW_S,
        "age_s": None if generated is None else max(0, round(ts_now - generated)),
        "stale": generated is None or ts_now - generated > STALE_S,
        "window_s": WINDOW_S, "zone_window_s": ZONE_WINDOW_S,
        "items": items, "zones": found, "anchors": anchors,
        "counts": {
            "reports": len(items),
            "mapped": sum(1 for i in items if i["precision"] != "unmapped"),
            "unmapped": sum(1 for i in items if i["precision"] == "unmapped"),
            "country_level": sum(1 for i in items if i["precision"] == "country"),
        },
        "sources": [{"key": key, "name": v.get("name", key), "ok": v.get("ok"),
                     "tried": v.get("tried"), "error": v.get("error", ""),
                     "reports": v.get("reports", 0), "mapped": v.get("mapped", 0)}
                    for key, v in sorted(sources.items())],
        "rules": {
            "zone": f"{ZONE_MIN_REPORTS}+ located reports from {ZONE_MIN_SOURCES}+ publishers, "
                    f"at least {ZONE_MIN_NEWSROOM} of them a newsroom's own, "
                    f"within {int(ZONE_EPS_KM)} km over {ZONE_WINDOW_S // 3600} h",
            "note": "A zone outlines where reports cluster. It is not a front line or an "
                    "official boundary, and report volume follows media attention.",
        },
    }


def audit(store, hosts=None):
    """Scheduled job. Context only: its findings are never above `low`."""
    result = refresh(store)
    live = result["sources"] - len(result["failed"])
    if not live:
        return [{"category": "world", "severity": "low", "host": LOCAL_HOST,
                 "title": "World watch could not reach any source",
                 "detail": "The conflict map keeps its last reports and marks them stale. "
                           "This is context, not a protection signal.", "where": ""}]
    detail = (f"{result['mapped']} of {result['items']} conflict reports placed, "
              f"{result['zones']} report clusters, {live} of {result['sources']} sources reached")
    if result["failed"]:
        detail += "; unreachable: " + ", ".join(result["failed"])
    return [{"category": "world", "severity": "ok", "host": LOCAL_HOST,
             "title": "World watch refreshed", "detail": detail, "where": ""}]
