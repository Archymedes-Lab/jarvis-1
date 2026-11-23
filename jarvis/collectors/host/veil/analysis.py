"""Deterministic analysis for the opt-in JARVIS Veil browser sensor.

The sensor deliberately cannot submit page text, typed characters, pointer
coordinates, screenshots, cookies, URL paths/query strings, request bodies, or
browser identifiers.  This module accepts only bounded counters and origins;
external pages and extension messages are untrusted evidence, not authority.
"""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from jarvis.core.finding import finding

MAX_ORIGINS = 16
MAX_COUNTER = 10_000
INTERACTION = {"mousemove", "pointermove", "scroll", "input", "keydown"}
FINGERPRINT_SURFACES = {
    "canvas", "webgl", "webgpu", "audio", "fonts", "screen", "hardware",
    "media_devices", "performance", "opfs",
}
TRANSPORTS = {"fetch", "xhr", "beacon", "pixel"}

# Session-replay products: scripts that record pointer movement, clicks,
# scrolling and DOM changes so a visit can be played back, and that capture
# typed text wherever the site fails to mask it. Matched on registrable
# domain suffix of script or egress origins. This is also the blocklist
# shipped as browser-sensor/rules/replay.json; a test keeps them equal.
REPLAY_VENDORS = {
    "hotjar.com": "Hotjar", "hotjar.io": "Hotjar",
    "clarity.ms": "Microsoft Clarity",
    "fullstory.com": "FullStory",
    "lr-ingest.io": "LogRocket", "lr-ingest.com": "LogRocket",
    "lr-in.com": "LogRocket", "lr-in-prod.com": "LogRocket",
    "logr-ingest.com": "LogRocket",
    "mouseflow.com": "Mouseflow",
    "smartlook.com": "Smartlook", "smartlook.cloud": "Smartlook",
    "contentsquare.net": "Contentsquare", "contentsquare.com": "Contentsquare",
    "quantummetric.com": "Quantum Metric",
    "glassboxdigital.io": "Glassbox", "glassboxcdn.com": "Glassbox",
    "inspectlet.com": "Inspectlet",
    "luckyorange.com": "Lucky Orange", "luckyorange.net": "Lucky Orange",
    "crazyegg.com": "Crazy Egg",
    "sessioncam.com": "SessionCam",
    "decibelinsight.net": "Decibel",
    "openreplay.com": "OpenReplay",
    "mc.yandex.ru": "Yandex Metrica (Webvisor)",
    "mc.yandex.com": "Yandex Metrica (Webvisor)",
}

# Analytics and monitoring products that offer session replay as an option.
# Their presence says a recording is possible, not that one is running, and
# blocking them breaks error reporting, so they are named but never blocked.
REPLAY_CAPABLE = {
    "posthog.com": "PostHog", "sentry.io": "Sentry",
    "datadoghq.com": "Datadog RUM", "heapanalytics.com": "Heap",
    "highlight.io": "Highlight", "amplitude.com": "Amplitude",
}

TRACKING_PARAMS = {
    "fbclid", "gclid", "dclid", "msclkid", "mc_cid", "mc_eid", "_ga",
    "_gl", "igshid", "vero_id", "yclid",
}


def _origin(value):
    if not isinstance(value, str) or len(value) > 255:
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    return f"{parsed.scheme}://{parsed.hostname.lower()}" + (
        f":{port}" if port else "")


def _counts(value, allowed):
    if not isinstance(value, dict):
        return {}
    out = {}
    for key, count in value.items():
        if key in allowed and isinstance(count, int) and 0 <= count <= MAX_COUNTER:
            out[key] = count
    return out


def _origins(value):
    """A bounded list of origins, reduced; ``None`` when malformed."""
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_ORIGINS:
        return None
    return sorted({o for o in map(_origin, value) if o})


def _vendors(origins, table):
    """Product names whose domain is a suffix of one of ``origins``."""
    found = set()
    for origin in origins:
        host = urlsplit(origin).hostname or ""
        for domain, name in table.items():
            if host == domain or host.endswith("." + domain):
                found.add(name)
    return sorted(found)


def validate_report(report):
    """Return a minimal, normalized report or ``None`` if it is malformed.

    No coercion is used for counts: accepting strings or floats makes a hostile
    page able to create ambiguous evidence.  Origins are reduced before storage.
    """
    if not isinstance(report, dict):
        return None
    top = _origin(report.get("top_origin"))
    if top is None:
        return None
    if not isinstance(report.get("egress_origins"), list):
        return None
    egress = _origins(report.get("egress_origins"))
    # Optional, added with the 0.2 sensor; older reports simply lack them.
    scripts = _origins(report.get("script_origins"))
    pixels = _origins(report.get("pixel_origins"))
    if egress is None or scripts is None or pixels is None:
        return None
    listeners = _counts(report.get("listeners"), INTERACTION)
    surfaces = _counts(report.get("surfaces"), FINGERPRINT_SURFACES)
    transports = _counts(report.get("transports"), TRANSPORTS)
    if not (listeners or surfaces or transports or scripts or pixels):
        return None
    return {"top_origin": top, "egress_origins": egress,
            "script_origins": scripts, "pixel_origins": pixels,
            "listeners": listeners, "surfaces": surfaces,
            "transports": transports}


def classify(report):
    """Classify aggregate behavior; this function never performs blocking.

    The browser sensor is evidence-only. A count by itself is not malicious.
    Interaction listeners alone cannot separate a recorder from a framework:
    React 17+ attaches mousemove, pointermove, input and keydown to the root
    of every React page, so listener aggregation is only ever low. Naming the
    recorder is what raises it: a known session-replay product among the
    page's script or egress origins.
    """
    report = validate_report(report)
    if report is None:
        return []
    top = report["top_origin"]
    third_party = [o for o in report["egress_origins"] if o != top]
    exported = bool(third_party and sum(report["transports"].values()))
    interaction = {name for name, n in report["listeners"].items() if n}
    surfaces = {name for name, n in report["surfaces"].items() if n}
    seen = [o for o in report["script_origins"] + report["egress_origins"]
            if o != top]
    replay = _vendors(seen, REPLAY_VENDORS)
    capable = [n for n in _vendors(seen, REPLAY_CAPABLE) if n not in replay]
    out = []
    if replay:
        out.append(finding(
            "privacy-veil", "medium",
            "session recorder on this site: " + ", ".join(replay),
            "session-replay software records mouse movement, clicks, scrolling "
            "and page changes so the visit can be played back, and captures "
            "typed text wherever the site fails to mask it. Interaction "
            "listeners seen: %s. JARVIS retained no typed text, timing series, "
            "or pointer coordinates." % (", ".join(sorted(interaction)) or "none"),
            top, host="browser"))
    elif capable and interaction:
        out.append(finding(
            "privacy-veil", "low",
            "analytics that can record sessions: " + ", ".join(capable),
            "these products offer session replay as an option; whether this "
            "site has it switched on is not visible from metadata.",
            top, host="browser"))
    elif exported and len(interaction) >= 4:
        out.append(finding(
            "privacy-veil", "low", "interaction listeners with cross-origin export",
            "aggregate listener observation: " + ", ".join(sorted(interaction))
            + "; cross-origin network export via "
            + ", ".join(sorted(k for k, v in report["transports"].items() if v))
            + ". Common frameworks register these same listeners, so this is an "
            "indicator only, not evidence of recording.", top, host="browser"))
    if report["pixel_origins"]:
        out.append(finding(
            "privacy-veil", "low", "tracking pixel loaded",
            "%d cross-origin image(s) of 2x2 pixels or smaller from %s. An image "
            "that small carries no content; loading it tells that server this "
            "page was viewed, when, and from which address."
            % (report["transports"].get("pixel", 0) or len(report["pixel_origins"]),
               ", ".join(report["pixel_origins"][:4])), top, host="browser"))
    if exported and len(surfaces) >= 4:
        out.append(finding(
            "privacy-veil", "medium", "fingerprinting surface aggregation detected",
            "%d high-entropy surfaces (%s) were read before cross-origin export. "
            "This is a behavioral indicator, not a compromise verdict."
            % (len(surfaces), ", ".join(sorted(surfaces))), top, host="browser"))
    elif exported and "opfs" in surfaces and "performance" in surfaces:
        out.append(finding(
            "privacy-veil", "low", "storage timing surface used before network export",
            "OPFS and performance APIs were both observed with cross-origin export; "
            "review in a hardened browser mode if this is unexpected.", top, host="browser"))
    return out


def clean_link(url):
    """Remove common decoration without changing a link's destination path."""
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return url
    kept = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if not (key.lower().startswith("utm_") or key.lower() in TRACKING_PARAMS)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                       urlencode(kept, doseq=True), parsed.fragment))
