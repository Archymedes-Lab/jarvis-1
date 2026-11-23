"""Popular domains: the false-positive filter every indicator match passes.

Threat intelligence names legitimate infrastructure all the time. A writeup
about malware "hiding in trusted services" mentions azure.com; URLhaus lists
one tenant's payload on res.cloudinary.com. Stored as domain indicators, those
turn every machine that talks to Azure or Cloudinary into a compromise. Measured
here on 2026-09-17: nine Windows telemetry hosts (onedscolprd*.cloudapp.azure.com)
matched a research-extracted `azure.com`, and Cloudinary's shared asset host
was a "known attacker domain" — a critical finding about a CDN.

MISP solves this with warninglists built from the Tranco ranking; this is the
same idea against the same list (downloaded by intel.feeds.refresh_tranco).
The rules, in order:

  * a popular registrable domain, or anything above it, is never an indicator;
  * one customer's exact host under a shared-hosting zone is specific, from any
    source (evil.eastus.cloudapp.azure.com identifies one tenant);
  * prose-extracted indicators on a top-100k domain are dropped — a writeup
    names the brand being impersonated far more often than the attacker's host;
  * feed indicators on a top-10k domain count only as the exact host, and then
    only as weak evidence (res.cloudinary.com identifies everyone).
"""

import re

# Indicators the writeup reader extracts get the schema's default source.
RESEARCH_SOURCE = "exa"

KEEP = 100_000
FEED_POPULAR = 10_000

# Used until the first ranking download lands, and as a floor if it never does.
FALLBACK = {
    "google.com", "googleapis.com", "gstatic.com", "gmail.com", "youtube.com",
    "microsoft.com", "azure.com", "azure.net", "azureedge.net", "windows.net",
    "windows.com", "live.com", "office.com", "office.net", "office365.com",
    "microsoftonline.com", "msftconnecttest.com", "bing.com", "skype.com",
    "apple.com", "icloud.com", "amazon.com", "amazonaws.com", "cloudfront.net",
    "cloudflare.com", "cloudflare.net", "akamai.net", "akamaihd.net",
    "akamaiedge.net", "fastly.net", "github.com", "githubusercontent.com",
    "cloudinary.com", "dropbox.com", "discord.com", "discordapp.com",
    "mozilla.org", "mozilla.net", "firefox.com", "facebook.com", "whatsapp.net",
}

# Zones whose next label is a customer's own name.
TENANT_ZONES = (
    "cloudapp.azure.com", "azurewebsites.net", "cloudapp.net", "blob.core.windows.net",
    "trafficmanager.net", "azurefd.net", "herokuapp.com", "appspot.com", "web.app",
    "firebaseapp.com", "pages.dev", "workers.dev", "netlify.app", "vercel.app",
    "github.io", "gitlab.io", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    "blogspot.com", "wordpress.com", "s3.amazonaws.com", "elasticbeanstalk.com",
)

# Region labels that sit between a customer and a regional zone
# (<name>.<region>.cloudapp.azure.com). A bare region is shared, not a tenant.
REGION = re.compile(
    r"^(north|south|east|west|central|uk|us|eu|asia|japan|korea|india|canada|brazil|"
    r"france|germany|switzerland|norway|uae|australia|italy|poland|sweden|qatar|"
    r"israel|mexico|spain|newzealand|southafrica|chile|indonesia|malaysia|taiwan)"
    r"[a-z0-9-]*$")


def popular(store, name):
    """-> (registrable popular parent of `name`, its rank), or ("", 0)."""
    parts = (name or "").lower().rstrip(".").split(".")
    for i in range(len(parts) - 1):
        parent = ".".join(parts[i:])
        try:
            row = store.db.execute(
                "SELECT rank FROM popular_domains WHERE domain=?", (parent,)).fetchone()
        except Exception:
            row = None
        if row:
            return parent, row[0]
        if parent in FALLBACK:
            return parent, 1
    return "", 0


def tenant_host(name):
    """Is `name` one customer's host under a shared-hosting zone?"""
    name = (name or "").lower().rstrip(".")
    for zone in TENANT_ZONES:
        if name.endswith("." + zone):
            labels = name[: -len(zone) - 1].split(".")
            return not (len(labels) == 1 and REGION.match(labels[0]))
    return False


def judge_domain(store, resolved, indicator, source):
    """What a match of `indicator` (equal to, or a parent of, `resolved`) is
    worth: "full", "weak", or "none"."""
    parent, rank = popular(store, resolved)
    if not parent:
        return "full"
    if len(indicator) <= len(parent):
        return "none"
    if indicator == resolved and tenant_host(resolved):
        return "full"
    if (source or RESEARCH_SOURCE) == RESEARCH_SOURCE:
        return "none"
    if rank > FEED_POPULAR:
        return "full"
    if indicator != resolved:
        return "none"
    return "weak"


def match_domain(store, name):
    """The one domain matcher: walk `name` and its parents against active
    indicators, weighed by the rules above.

    -> None, or {"indicator", "hit", "severity", "qualifier"} where `hit` is the
    indicators row (context, source_url, malware, source, confidence).
    """
    from jarvis.core import vet
    name = (name or "").lower().rstrip(".")
    parts = name.split(".")
    for i in range(len(parts) - 1):
        parent = ".".join(parts[i:])
        if not vet.vet_domain(parent)[0]:
            continue
        hit = store.db.execute(
            "SELECT context, source_url, malware, source, confidence FROM indicators "
            "WHERE kind='domain' AND norm=? AND status='active'", (parent,)).fetchone()
        if not hit:
            continue
        worth = judge_domain(store, name, parent, hit["source"])
        if worth == "none":
            continue
        if worth == "weak":
            return {"indicator": parent, "hit": hit, "severity": "low",
                    "qualifier": "shared host listed in threat intelligence"}
        severity = "critical" if hit["confidence"] == "high" else "medium"
        return {"indicator": parent, "hit": hit, "severity": severity,
                "qualifier": "known attacker" if severity == "critical" else "threat-intelligence"}
    return None


def store_ranking(store, rows):
    """Replace the stored ranking with [(domain, rank), ...]."""
    store.db.execute("DELETE FROM popular_domains")
    store.db.executemany(
        "INSERT OR REPLACE INTO popular_domains(domain, rank) VALUES(?,?)", rows)
    store.commit()
