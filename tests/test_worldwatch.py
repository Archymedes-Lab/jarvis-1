"""World watch: honest placement, bounded untrusted input, and no location leak.

The invariants under test:
  - a report is placed only where its own words (or its publisher) put it, with
    the precision carried; otherwise it stays unmapped. Nothing is guessed.
  - a zone needs several located reports from several publishers; country-level
    reports and uncorroborated machine-coded events never form one.
  - every outbound request is the same whatever the device position is.
  - feed content is untrusted: entities refused, text bounded, links restricted.
  - a failing source loses nothing already held and is reported, and the job
    never raises a finding above `low` or touches the score.
"""
import hashlib
import json
import os
import re
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.utils import format_datetime
from http.server import ThreadingHTTPServer
from pathlib import Path

from jarvis.core import governor
from jarvis.core.store import Store
from jarvis.intel import worldwatch as w
from jarvis.response.reporting import score
from jarvis.service import geosecurity, schedule
from tests import _apiauth

STATIC = Path(__file__).parents[1] / "jarvis/web/static"
NOW = 1_800_000_000.0


def rss(rows, host="www.bbc.co.uk"):
    items = "".join(
        f"<item><title>{title}</title><description>{summary}</description>"
        f"<link>https://{host}/news/{i}</link>"
        f"<pubDate>{format_datetime(datetime.fromtimestamp(NOW - age, timezone.utc))}</pubDate></item>"
        for i, (title, summary, age) in enumerate(rows))
    return f"<rss><channel>{items}</channel></rss>".encode()


def gdelt_row(code="190", geo_type="4", place="Kharkiv, Kharkivs'ka Oblast', Ukraine",
              lat="49.98", lon="36.25", url="https://example.org/a/shelling-hits-kharkiv-again-today",
              age=600, day_offset=0):
    added = datetime.fromtimestamp(NOW - age, timezone.utc)
    day = datetime.fromtimestamp(NOW - age - day_offset * 86400, timezone.utc)
    row = [""] * 61
    row[1], row[26], row[28] = day.strftime("%Y%m%d"), code, code[:2]
    row[51], row[52], row[56], row[57] = geo_type, place, lat, lon
    row[59], row[60] = added.strftime("%Y%m%d%H%M%S"), url
    return "\t".join(row)


def item(place, lat, lon, source, kind="news", age=3600, precision="city", n=0):
    return {"id": f"{source}-{place}-{n}", "kind": kind, "src": source, "source": source,
            "title": f"Shelling reported in {place}", "summary": "", "url": f"https://x/{n}",
            "ts": NOW - age, "lat": lat, "lon": lon, "place": place, "country": "Ukraine",
            "a3": "UKR", "precision": precision, "ambiguous": False}


class ClassifierTests(unittest.TestCase):
    def test_armed_conflict_headlines_are_recognised(self):
        for title in ("Russian drone attack hits Kyiv bridge",
                      "Ethiopian rebel forces withdraw from Tigray regional capital",
                      "Dozens killed in air strike on market",
                      "Army and militia clashes displace thousands"):
            self.assertTrue(w.is_conflict(title), title)

    def test_figurative_and_unrelated_headlines_are_not(self):
        for title in ("Trade war fears rattle markets", "Rail strike halts trains across the country",
                      "Man dies after heart attack at stadium", "Firefighters battle wildfire near resort",
                      "One activist's battle for acceptance", "Election polls open in Brazil",
                      "Star Wars actor on strike action deal"):
            self.assertFalse(w.is_conflict(title), title)

    def test_a_summary_cannot_carry_a_headline_that_names_no_violence(self):
        self.assertFalse(w.is_conflict("Tsar laid to rest in Sofia", "He died fleeing an invasion by rebels."))
        self.assertTrue(w.is_conflict("Dozens killed in capital", "Shelling hit a market, officials said."))


class GazetteerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gaz = w.gazetteer()

    def where(self, title, summary=""):
        return self.gaz.locate(title, summary)

    def test_a_named_city_is_placed_at_the_city(self):
        got = self.where("Kyiv bridge hit in further Russian drone attack")
        self.assertEqual((got["place"], got["precision"], got["a3"]), ("Kyiv", "city", "UKR"))
        self.assertAlmostEqual(got["lat"], 50.44, delta=0.1)
        self.assertAlmostEqual(got["lon"], 30.51, delta=0.1)

    def test_a_speaking_capital_is_not_where_it_happened(self):
        got = self.where("Moscow says its forces struck Kharkiv overnight")
        self.assertEqual(got["place"], "Kharkiv")

    def test_only_a_speaking_capital_falls_back_to_nothing_or_country(self):
        got = self.where("Moscow says talks on truce have failed")
        self.assertTrue(got is None or got["precision"] == "country")

    def test_a_country_only_report_is_country_level_at_the_label_point(self):
        got = self.where("Yemen's leader announces counter-offensive against Houthis")
        self.assertEqual((got["precision"], got["a3"]), ("country", "YEM"))

    def test_hyphenated_country_names_are_found(self):
        self.assertEqual(self.where("48 hours inside the Yemen-Houthi fighting")["a3"], "YEM")

    def test_news_spellings_resolve_to_natural_earth_coordinates(self):
        taiz = self.where("Fighting intensifies in Yemen's Taiz governorate")
        self.assertEqual((taiz["place"], taiz["a3"]), ("Taizz", "YEM"))
        self.assertEqual(self.where("Strike kills five in Gaza")["precision"], "region")

    def test_demonyms_and_given_names_do_not_place_a_report(self):
        self.assertIsNone(self.where("Russian and Ukrainian envoys trade accusations"))
        self.assertIsNone(self.where("Jordan scores twice as rebels fall short"))
        self.assertIsNone(self.where("Troops deployed, minister says"))

    def test_common_word_and_small_unbacked_city_names_are_not_matched(self):
        self.assertIsNone(self.where("Nice weather as troops parade"))
        self.assertIsNone(self.where("Rebels seize Mobile unit in Reading"))

    def test_a_shared_name_follows_the_named_country(self):
        self.assertEqual(self.where("Clashes in Tripoli as Lebanon army deploys")["a3"], "LBN")
        self.assertEqual(self.where("Militias clash in Tripoli")["a3"], "LBY")


class FeedParsingTests(unittest.TestCase):
    def test_rss_atom_and_rdf_are_read(self):
        self.assertEqual(len(w.parse_feed(rss([("A", "b", 60)]))), 1)
        atom = (b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>T</title>'
                b'<link rel="alternate" href="https://www.youtube.com/watch?v=x"/>'
                b"<published>2027-01-15T08:00:00+00:00</published></entry></feed>")
        row = w.parse_feed(atom)[0]
        self.assertEqual((row["title"], row["url"]), ("T", "https://www.youtube.com/watch?v=x"))
        self.assertIsNotNone(row["ts"])

    def test_a_feed_declaring_entities_is_refused(self):
        bomb = (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]>'
                b"<rss><channel><item><title>&lol;</title></item></channel></rss>")
        with self.assertRaises(ValueError):
            w.parse_feed(bomb)

    def test_reports_keep_only_dated_conflict_items_with_the_publishers_link(self):
        gaz = w.gazetteer()
        rows = w.parse_feed(rss([
            ("Shelling hits Kharkiv overnight", "Officials said &lt;b&gt;three&lt;/b&gt; died.\u200b", 60),
            ("Election polls open in Brazil", "", 60),
            ("Clashes reported, officials say", "", 60),
            ("Shelling hits Kharkiv again", "", w.WINDOW_S + 60),
        ]))
        got = w.reports(rows, "bbc_world", "BBC News", ("bbc.co.uk",), "news", gaz, NOW)
        self.assertEqual([g["precision"] for g in got], ["city", "unmapped"])
        self.assertEqual(got[0]["summary"], "Officials said three died.")
        self.assertIsNone(got[1]["lat"])                                   # never a guessed position
        evil = w.parse_feed(rss([("Shelling hits Kharkiv", "", 60)], host="evil.example"))
        self.assertEqual(w.reports(evil, "bbc_world", "BBC News", ("bbc.co.uk",), "news", gaz, NOW), [])

    def test_links_must_be_plain_web_links(self):
        self.assertEqual(w.link("javascript:alert(1)"), "")
        self.assertEqual(w.link("https://user:pw@bbc.co.uk/x", ("bbc.co.uk",)), "")
        self.assertEqual(w.link("http://www.bbc.co.uk/x", ("bbc.co.uk",)), "")
        self.assertEqual(w.link("https://notbbc.co.uk/x", ("bbc.co.uk",)), "")
        self.assertEqual(w.link("https://www.bbc.co.uk/x", ("bbc.co.uk",)), "https://www.bbc.co.uk/x")

    def test_text_is_bounded_and_stripped_of_markup_and_invisible_characters(self):
        text = w.clean("<script>x</script> A\u202eB " + "z" * 500, 40)
        self.assertLessEqual(len(text), 40)
        self.assertNotIn("<", text)
        self.assertNotIn("\u202e", text)


class GdeltTests(unittest.TestCase):
    def parse(self, *rows):
        return w.parse_gdelt("\n".join(rows).encode(), NOW, w.gazetteer())

    def test_only_located_current_armed_force_events_are_kept(self):
        got = self.parse(
            gdelt_row(),
            gdelt_row(code="043", url="https://example.org/a/leaders-meet-for-talks-on-trade"),
            gdelt_row(geo_type="1", place="Ukraine", url="https://example.org/b/shelling-hits-towns-across-ukraine"),
            gdelt_row(day_offset=30, url="https://example.org/c/remembering-the-shelling-of-kharkiv-city"),
            gdelt_row(lat="", url="https://example.org/d/shelling-hits-kharkiv-city-centre"),
            "too\tfew\tcolumns")
        self.assertEqual(len(got), 1)
        self.assertEqual((got[0]["kind"], got[0]["precision"], got[0]["place"]), ("event", "city", "Kharkiv"))
        self.assertEqual(got[0]["source"], "example.org")

    def test_an_event_whose_link_names_other_countries_is_dropped(self):
        got = self.parse(gdelt_row(place="Berlin, Berlin, Germany", lat="52.5", lon="13.4",
                                   url="https://example.org/ukraine-russia-war-live-drone-strikes-bridge"))
        self.assertEqual(got, [])

    def test_a_non_conflict_link_text_drops_the_event(self):
        self.assertEqual(self.parse(gdelt_row(url="https://example.org/fire-prevention-starts-with-being-prepared")), [])


class ZoneTests(unittest.TestCase):
    def cluster(self, sources, precision="city", kind="news"):
        spots = [("Kharkiv", 49.98, 36.25), ("Chuhuiv", 49.84, 36.69), ("Izyum", 49.21, 37.26)]
        return [item(*spots[i % 3], source=sources[i % len(sources)], kind=kind, precision=precision, n=i)
                for i in range(6)]

    def test_located_reports_from_several_publishers_form_a_zone_around_them(self):
        items = self.cluster(["BBC News", "DW", "France 24"])
        zones = w.zones(items, NOW)
        self.assertEqual(len(zones), 1)
        zone = zones[0]
        self.assertEqual((zone["reports"], zone["sources"]), (6, 3))
        for it in items:
            self.assertEqual(w.zone_distance_km(zone, it["lat"], it["lon"]), 0.0)
        self.assertLess(zone["radius_km"], 250)

    def test_zone_history_accounts_for_every_report_oldest_first(self):
        items = self.cluster(["BBC News", "DW", "France 24"])
        items[0]["ts"] = NOW - 40 * 3600
        zone = w.zones(items, NOW)[0]
        self.assertEqual(len(zone["history"]), w.ZONE_WINDOW_S // w.HISTORY_BUCKET_S)
        self.assertEqual(sum(zone["history"]), zone["reports"])
        self.assertEqual((zone["history"][1], zone["history"][-1]), (1, 5))
        self.assertEqual((zone["last_24h"], zone["prior_24h"], zone["newsroom"]), (5, 1, 6))

    def test_too_few_publishers_or_reports_form_no_zone(self):
        self.assertEqual(w.zones(self.cluster(["BBC News", "DW"]), NOW), [])
        self.assertEqual(w.zones(self.cluster(["BBC News", "DW", "France 24"])[:4], NOW), [])

    def test_country_level_reports_never_form_a_zone(self):
        self.assertEqual(w.zones(self.cluster(["BBC News", "DW", "France 24"], precision="country"), NOW), [])

    def test_old_reports_do_not_count(self):
        items = self.cluster(["BBC News", "DW", "France 24"])
        for it in items:
            it["ts"] = NOW - w.ZONE_WINDOW_S - 60
        self.assertEqual(w.zones(items, NOW), [])

    def test_machine_coded_events_alone_never_form_a_zone(self):
        events = self.cluster(["a.example", "b.example", "c.example"], kind="event")
        self.assertEqual(w.zones(events, NOW), [])
        self.assertFalse(any(e.get("corroborated") for e in events))

    def test_events_count_only_near_a_newsroom_report(self):
        events = self.cluster(["a.example", "b.example", "c.example"], kind="event")
        far = item("Vladivostok", 43.1, 131.9, "d.example", kind="event", n=99)
        news = item("Kharkiv", 49.98, 36.25, "BBC News", n=50)
        self.assertEqual(w.zones(events + [far, news], NOW), [])     # one newsroom report is not enough
        zones = w.zones(events + [far, news, item("Kharkiv", 49.98, 36.25, "DW", n=51)], NOW)
        self.assertEqual(len(zones), 1)
        self.assertEqual((zones[0]["reports"], zones[0]["newsroom"]), (8, 2))
        self.assertTrue(all(e["corroborated"] for e in events))
        self.assertNotIn("corroborated", far)

    def test_distance_to_a_zone_is_zero_inside_and_true_outside(self):
        zone = w.zones(self.cluster(["BBC News", "DW", "France 24"]), NOW)[0]
        kyiv = w.zone_distance_km(zone, 50.45, 30.52)
        self.assertGreater(kyiv, 250)
        self.assertLess(kyiv, 420)                 # Kyiv to Kharkiv is about 410 km

    def test_a_cluster_across_the_antimeridian_stays_one_zone(self):
        spots = [("A", -17.0, 179.6), ("B", -17.2, -179.7), ("C", -16.8, 179.9)]
        items = [item(*spots[i % 3], source=["BBC News", "DW", "France 24"][i % 3], n=i) for i in range(6)]
        zones = w.zones(items, NOW)
        self.assertEqual(len(zones), 1)
        self.assertLess(zones[0]["radius_km"], 200)


class FakeFetch:
    """Stands in for feeds.fetch: records every URL, serves canned bodies."""

    def __init__(self, bodies=None, fail=()):
        self.urls, self.bodies, self.fail = [], bodies or {}, set(fail)

    def __call__(self, url, max_bytes, timeout=None, max_inflated=None):
        self.urls.append(url)
        if any(mark in url for mark in self.fail):
            raise urllib.error.URLError("unreachable")
        if url == w.GDELT_LAST:
            stamp = datetime.fromtimestamp(NOW - 300, timezone.utc).strftime("%Y%m%d%H") + "0000"
            return f"1 x http://data.gdeltproject.org/gdeltv2/{stamp}.export.CSV.zip\n".encode()
        if "gdeltv2/" in url:
            return self.bodies.get("gdelt", b"")
        for key, body in self.bodies.items():
            if key in url:
                return body
        return rss([])


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.addCleanup(self.store.close)
        self.kharkiv = rss([("Shelling hits Kharkiv overnight", "", 600)])

    def run_refresh(self, fetch, ts=NOW):
        return w.refresh(self.store, fetch=fetch, ts_now=ts)

    def test_requests_are_fixed_and_identical_whatever_the_device_position(self):
        first = FakeFetch()
        self.run_refresh(first)
        geosecurity.set_here(self.store, -1.9441, 30.0619, "somewhere private")
        geosecurity.add_zone(self.store, "HOME", -1.9441, 30.0619)
        self.store.set_meta(w.META_GDELT, "[]")
        second = FakeFetch()
        self.run_refresh(second)
        self.assertEqual(first.urls, second.urls)
        fixed = {spec[1] for spec in w.NEWS.values()} | {w.YOUTUBE_FEED + c for _, c in w.VIDEO.values()}
        for url in second.urls:
            self.assertTrue(url in fixed or url == w.GDELT_LAST
                            or re.fullmatch(r"http://data\.gdeltproject\.org/gdeltv2/\d{14}\.export\.CSV\.zip", url), url)
            for secret in ("1.94", "30.06", "HOME", "private"):
                self.assertNotIn(secret, url)

    def test_reports_are_merged_once_and_located(self):
        fetch = FakeFetch({"bbci.co.uk/news/world/rss.xml": self.kharkiv})
        self.run_refresh(fetch)
        result = self.run_refresh(FakeFetch({"bbci.co.uk/news/world/rss.xml": self.kharkiv}))
        self.assertEqual((result["items"], result["mapped"]), (1, 1))
        state = w.state(self.store, ts_now=NOW)
        self.assertEqual(state["items"][0]["place"], "Kharkiv")
        self.assertFalse(state["stale"])

    def test_a_failed_source_keeps_its_reports_and_is_named(self):
        self.run_refresh(FakeFetch({"bbci.co.uk/news/world/rss.xml": self.kharkiv}))
        result = self.run_refresh(FakeFetch(fail=("bbci.co.uk", "gdeltproject")), ts=NOW + 900)
        self.assertEqual(result["items"], 1)
        self.assertIn("bbc_world", result["failed"])
        self.assertIn("gdelt", result["failed"])
        sources = {s["key"]: s for s in w.state(self.store, ts_now=NOW + 900)["sources"]}
        self.assertTrue(sources["bbc_world"]["error"])
        self.assertEqual(sources["bbc_world"]["ok"], NOW)                  # last success, not this run
        self.assertFalse(sources["dw"]["error"])

    def test_a_malformed_feed_is_one_failed_source_not_a_failed_run(self):
        result = self.run_refresh(FakeFetch({"aljazeera": b"<rss><channel><item>", "bbci.co.uk/news/world/rss.xml": self.kharkiv}))
        self.assertEqual(result["failed"], ["aljazeera"])
        self.assertEqual(result["items"], 1)

    def test_old_reports_are_forgotten_and_the_store_is_bounded(self):
        self.run_refresh(FakeFetch({"bbci.co.uk/news/world/rss.xml": self.kharkiv}))
        later = NOW + w.WINDOW_S + 3600
        self.assertEqual(self.run_refresh(FakeFetch(), ts=later)["items"], 0)
        self.assertEqual(w.state(self.store, ts_now=later)["items"], [])
        many = rss([(f"Shelling hits Kharkiv district {i}", "", 600 + i) for i in range(w.MAX_ITEMS + 40)])
        result = self.run_refresh(FakeFetch({"bbci.co.uk/news/world/rss.xml": many}))
        self.assertEqual(result["items"], w.MAX_ITEMS)

    def test_gdelt_files_are_capped_per_run_and_never_fetched_twice(self):
        # feeds.fetch returns decompressed bytes. Returning a ZIP from the
        # fake sent timestamp-dependent binary headers into the CSV parser.
        raw = gdelt_row().encode()
        first = FakeFetch({"gdelt": raw})
        result = self.run_refresh(first)
        self.assertNotIn("gdelt", result["failed"])
        self.assertGreater(result["items"], 0)
        files = [u for u in first.urls if u.endswith(".zip")]
        self.assertEqual(len(files), w.GDELT_FILES_PER_RUN)
        second = FakeFetch({"gdelt": raw})
        self.run_refresh(second)
        self.assertFalse(set(files) & {u for u in second.urls if u.endswith(".zip")})

    def test_a_trend_is_offered_only_after_two_days_of_collecting(self):
        self.assertFalse(w.state(self.store, ts_now=NOW)["trend_ready"])
        self.run_refresh(FakeFetch())
        self.run_refresh(FakeFetch(), ts=NOW + 3600)
        early = w.state(self.store, ts_now=NOW + 3600)
        self.assertEqual((early["since"], early["trend_ready"]), (NOW, False))   # first run, kept
        self.assertTrue(w.state(self.store, ts_now=NOW + w.ZONE_WINDOW_S)["trend_ready"])

    def test_stale_and_empty_states_say_so(self):
        empty = w.state(self.store, ts_now=NOW)
        self.assertTrue(empty["stale"])
        self.assertIsNone(empty["generated_at"])
        self.assertEqual((empty["items"], empty["zones"], empty["anchors"]), ([], [], []))
        self.run_refresh(FakeFetch())
        self.assertTrue(w.state(self.store, ts_now=NOW + w.STALE_S + 1)["stale"])

    def test_distance_is_worked_out_locally_for_the_device_and_trusted_zones(self):
        rows = [(f"Shelling hits Kharkiv, day {i}", "", 600 + i) for i in range(2)]
        bodies = {"bbci.co.uk/news/world/rss.xml": rss(rows), "dw.com": rss(rows, host="www.dw.com"),
                  "france24.com/en/rss": rss(rows, host="www.france24.com")}
        self.assertEqual(self.run_refresh(FakeFetch(bodies))["zones"], 1)
        state = w.state(self.store, location={"status": "ok", "lat": 50.45, "lon": 30.52, "source": "user-set"},
                        trusted=[{"name": "HOME", "lat": 49.98, "lon": 36.25}], ts_now=NOW)
        device, home = state["anchors"]
        self.assertFalse(device["nearest"]["inside"])
        self.assertGreater(device["nearest"]["distance_km"], 250)
        self.assertTrue(home["nearest"]["inside"])
        denied = w.state(self.store, location={"status": "denied"}, ts_now=NOW)
        self.assertEqual(denied["anchors"], [])                            # no position, no marker

    def test_the_job_reports_context_only_never_above_low(self):
        real = w.refresh
        try:
            w.refresh = lambda store: real(store, fetch=FakeFetch(fail=("",)), ts_now=NOW)
            findings = w.audit(self.store)
            self.assertEqual([f["severity"] for f in findings], ["low"])
            w.refresh = lambda store: real(store, fetch=FakeFetch(), ts_now=NOW)
            self.assertEqual([f["severity"] for f in w.audit(self.store)], ["ok"])
        finally:
            w.refresh = real


class WiringTests(unittest.TestCase):
    def test_the_job_is_scheduled_unscored_and_deferrable(self):
        self.assertIn("world", schedule.JOBS)
        self.assertIn("world", score.UNSCORED)
        self.assertNotIn("world", score.AREA_OF)
        self.assertIn("world", governor.GOVERNED_JOBS)
        self.assertNotIn("world", schedule.WINDOWS_ONLY | schedule.LINUX_ONLY)

    def test_every_source_is_https_or_the_fixed_gdelt_host(self):
        for _name, url, hosts in w.NEWS.values():
            self.assertTrue(url.startswith("https://"), url)
            self.assertTrue(hosts)
        self.assertTrue(w.YOUTUBE_FEED.startswith("https://www.youtube.com/"))
        self.assertTrue(w.GDELT_LAST.startswith("http://data.gdeltproject.org/"))

    def test_the_gazetteer_is_built_from_natural_earth_only(self):
        with open(w.GAZETTEER_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIn("Natural Earth", data["source"])
        for kind in ("countries", "places", "regions"):
            for entry in data[kind]:
                self.assertTrue(-90 <= entry["lat"] <= 90 and -180 <= entry["lon"] <= 180)


class PageTests(unittest.TestCase):
    """The view renders untrusted text and must talk to this origin only."""

    def setUp(self):
        self.js = (STATIC / "world.js").read_text()
        self.html = (STATIC / "world.html").read_text()

    def test_feed_text_is_never_parsed_as_markup(self):
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(sink, self.js)

    def test_report_links_open_detached_and_only_on_click(self):
        self.assertIn("rel = 'noopener noreferrer'", self.js)
        self.assertEqual(re.findall(r"fetch\('([^']+)'", self.js), ["/api/world", "/static/vendor/world-50m.json"])
        self.assertNotIn("http://", self.js)
        self.assertNotIn("https://", self.js)

    def test_page_loads_one_same_origin_script_and_nothing_foreign(self):
        # session.js (the shared 403->/pair helper) and the page's own module.
        self.assertEqual(self.html.count("<script"), 2)
        self.assertIn('<script src="/static/session.js"></script>', self.html)
        self.assertIn('<script type="module" src="/static/world.js"></script>', self.html)
        self.assertNotIn("http://", self.html)
        self.assertNotIn("https://", self.html)

    def test_search_looks_only_at_collected_reports(self):
        self.assertIn("No collected report names that place.", self.js)
        self.assertNotIn("nominatim", self.js.lower())

    def test_nothing_turns_or_pulses_without_cause(self):
        self.assertIn("spin: false", self.js)                 # the globe turns only when asked
        self.assertIn("data.trend_ready && zone.last_24h", self.js)
        self.assertNotIn("uSun", self.js)                     # no terminator: the reports carry no such thing

    def test_the_view_states_what_a_zone_is_and_goes_quiet_when_stale(self):
        self.assertIn("not a front line", self.js)
        self.assertIn("unverified", self.js)
        self.assertIn('body[data-link="stale"] canvas#scene', self.html)
        self.assertIn("prefers-reduced-motion", self.js)


class RouteTests(unittest.TestCase):
    def setUp(self):
        from jarvis.web import server
        self.server = server
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db = os.path.join(self.tmp.name, "t.db")
        Store(db).close()
        handler = type("H", (server.Handler,), {"db_path": db, "scheduler": None,
                                                "log_message": lambda *a: None})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.base = f"http://localhost:{self.httpd.server_address[1]}"

    def get(self, path):
        req = urllib.request.Request(self.base + path, headers=_apiauth.grant(self))
        try:
            with urllib.request.urlopen(req, timeout=10) as res:
                return res.status, dict(res.headers), res.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def test_the_view_is_served_under_the_same_origin_only_policy(self):
        for path in ("/world", "/static/world.js", "/static/vendor/world-50m.json"):
            status, headers, body = self.get(path)
            self.assertEqual(status, 200, path)
            csp = headers["Content-Security-Policy"]
            self.assertIn("default-src 'none'", csp)
            self.assertIn("connect-src 'self'", csp)
            self.assertNotIn("https:", csp)
            self.assertNotIn("'unsafe-inline' 'wasm", csp)
            self.assertTrue(body)

    def test_map_data_matches_its_pin_and_a_modified_file_is_refused(self):
        name, ctype, digest = self.server.COVERAGE_ASSETS["/static/vendor/world-50m.json"]
        self.assertEqual(hashlib.sha256((STATIC / name).read_bytes()).hexdigest(), digest)
        tampered = dict(self.server.COVERAGE_ASSETS)
        tampered["/static/vendor/world-50m.json"] = (name, ctype, "0" * 64)
        original = self.server.COVERAGE_ASSETS
        self.server.COVERAGE_ASSETS = tampered
        try:
            self.assertEqual(self.get("/static/vendor/world-50m.json")[0], 500)
        finally:
            self.server.COVERAGE_ASSETS = original

    def test_api_answers_before_anything_was_collected(self):
        status, _headers, body = self.get("/api/world")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["stale"])
        self.assertEqual((payload["items"], payload["zones"]), ([], []))

    def test_geo_page_links_to_the_world_view(self):
        self.assertIn(b'href="/world"', self.get("/geo")[2])


if __name__ == "__main__":
    unittest.main()
