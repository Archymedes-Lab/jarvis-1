"""Is there a newer Argus release? (Not `collectors/host/updates.py`: that lists outdated *other* software.) One read of the public release manifest, and nothing else.

The desktop app has no network permission, so it asks the service (`GET /api/update`). The service reads
`manifest.json` from the release site and answers with the newest published version. That is all it does:

* it sends nothing about this machine (a plain GET, no identifier, no version, no cookie);
* it never downloads or installs anything: the person opens the download page and chooses;
* the answer is cached for six hours, and a failure is a quiet "could not check", never an alert;
* `ARGUS_UPDATE_CHECK=0` turns it off.

The version order is the release tool's own (YYYY.MM.DD, then -N for the Nth release that day), kept
here as a small copy because release/ is a build tool and is not shipped in the service.
"""

import json
import os
import re
import time
import urllib.request
from urllib.parse import urlsplit

MANIFEST = "https://www.archymedes.xyz/downloads/argus/manifest.json"
PAGE = "https://www.archymedes.xyz/en/solutions/argus/#download"
CACHE_S = 6 * 3600
RETRY_S = 15 * 60          # after a failure, try again sooner than a full cache period
MAX_BYTES = 256 * 1024
TIMEOUT_S = 6

_VERSION = re.compile(r"^(20\d{2})\.(\d{2})\.(\d{2})(?:[-.](\d+))?$")
_cache = {"at": 0.0, "answer": None, "ttl": 0.0}


def version_key(version):
    """(year, month, day, n) for a release version, or None when it is not one."""
    m = _VERSION.match(version or "")
    if not m:
        return None
    if not (1 <= int(m.group(2)) <= 12 and 1 <= int(m.group(3)) <= 31):
        return None
    n = max(int(m.group(4)), 1) if m.group(4) else 1       # -0 (CI's first build of a day) is the first
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), n)


def is_newer(latest, current):
    """True only when both are release versions and `latest` is strictly after `current`."""
    a, b = version_key(latest), version_key(current)
    return bool(a and b and a > b)


def _manifest_url():
    url = os.environ.get("ARGUS_UPDATE_MANIFEST") or MANIFEST
    parts = urlsplit(url)
    local = parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost")
    if parts.scheme != "https" and not local:
        raise ValueError("the update manifest must be https")
    return url


def _read(url, opener):
    req = urllib.request.Request(url, headers={"User-Agent": "argus-update-check", "Accept": "application/json"})
    with opener(req, timeout=TIMEOUT_S) as r:
        body = r.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("manifest too large")
    return json.loads(body)


def latest(now=None, opener=urllib.request.urlopen, force=False):
    """{"enabled", "latest", "page", "checked", "error"}. Never raises."""
    now = time.time() if now is None else now
    if os.environ.get("ARGUS_UPDATE_CHECK", "1") == "0":
        return {"enabled": False, "latest": None, "page": PAGE, "checked": 0, "error": ""}
    cached = _cache["answer"]
    if cached and not force and now - _cache["at"] < _cache["ttl"]:
        return cached
    try:
        manifest = _read(_manifest_url(), opener)
        version = str(manifest.get("version", "")) if isinstance(manifest, dict) else ""
        if version_key(version) is None:
            raise ValueError("the manifest has no release version")
        answer = {"enabled": True, "latest": version, "page": PAGE, "checked": int(now), "error": ""}
        ttl = CACHE_S
    except Exception as e:                           # offline, blocked, malformed: all the same to the person
        answer = {"enabled": True, "latest": (cached or {}).get("latest"), "page": PAGE,
                  "checked": (cached or {}).get("checked", 0), "error": f"could not check ({type(e).__name__})"}
        ttl = RETRY_S
    _cache.update(at=now, answer=answer, ttl=ttl)
    return answer
