"""The metered search API: credentials, the daily spend brake, and transport."""

import json
import os
import stat
import time
import urllib.error
import urllib.request

from jarvis.intel.corpus import SOURCES

from .extraction import EXTRACTION_PROMPT, EXTRACTION_SCHEMA

API_URL = "https://api.exa.ai/search"


CONFIG_PATH = os.path.expanduser("~/.jarvis/config.json")


class IntelError(RuntimeError):
    pass


class BudgetExceeded(IntelError):
    pass


# A metered API on a 24/7 timer is a standing invitation to a surprise bill, so
# spend is capped per day and the cap is enforced before each query rather than
# reported after the fact.
DEFAULT_DAILY_BUDGET = 0.50


def _today():
    return time.strftime("%Y%m%d")


def daily_budget():
    try:
        with open(CONFIG_PATH, errors="replace") as fh:
            return float(json.load(fh).get("daily_budget", DEFAULT_DAILY_BUDGET))
    except (OSError, ValueError, TypeError):
        return DEFAULT_DAILY_BUDGET


def spent_today(store):
    return float(store.get_meta(f"intel_spend_{_today()}", 0) or 0)


def _charge(store, amount):
    key = f"intel_spend_{_today()}"
    store.set_meta(key, round(spent_today(store) + float(amount or 0), 4))


def load_key():
    """API key from the environment, else from a 0600 file outside the repo.

    The repository is public. The key never goes in a tracked file, and the
    config lives beside the database in ~/.jarvis rather than in the checkout.
    """
    env = os.environ.get("JARVIS_EXA_KEY", "").strip()
    if env:
        return env
    try:
        with open(CONFIG_PATH, errors="replace") as fh:
            return (json.load(fh).get("exa_api_key") or "").strip()
    except (OSError, ValueError):
        return ""


def save_key(key):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    cfg = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, errors="replace") as fh:
                cfg = json.load(fh)
        except ValueError:
            cfg = {}
    cfg["exa_api_key"] = key.strip()
    fd = os.open(CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(cfg, fh, indent=2)
    os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)
    return CONFIG_PATH


def _post(payload, key, timeout=90):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        API_URL, data=body, method="POST",
        headers={"x-api-key": key, "Content-Type": "application/json",
                 "User-Agent": "jarvis-intel/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise IntelError(f"HTTP {exc.code}: {detail}") from None
    except urllib.error.URLError as exc:
        raise IntelError(f"network error: {exc.reason}") from None
    except (TimeoutError, OSError) as exc:
        raise IntelError(f"request failed: {exc}") from None


def search(query, key, num_results=6, days=365, domains=None):
    """One Exa search with structured extraction attached to every result."""
    start = time.strftime(
        "%Y-%m-%dT00:00:00.000Z", time.gmtime(time.time() - days * 86400))
    payload = {
        "query": query,
        "type": "auto",
        "numResults": max(1, min(int(num_results), 25)),
        "startPublishedDate": start,
        "includeDomains": domains if domains is not None else SOURCES,
        "contents": {
            "summary": {"query": EXTRACTION_PROMPT, "schema": EXTRACTION_SCHEMA},
        },
    }
    return _post(payload, key)
