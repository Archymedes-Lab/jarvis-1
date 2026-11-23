"""The paired phones this server seals alerts for (0600 JSON beside the store).

The relay keeps its own copy for routing, but trust lives here: a device is
active only after the owner confirmed its pairing code on this machine, and
a device revoked here is never sealed for again, whatever the relay says.
"""

import json
import os
import time

REGISTRY = os.path.expanduser("~/.jarvis/notify/devices.json")
MAX_DEVICES = 20


def load(path=None):
    path = path or REGISTRY
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) and isinstance(doc.get("devices"), list) else {"devices": []}
    except (OSError, ValueError):
        return {"devices": []}


def save(doc, path=None):
    path = path or REGISTRY
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def active(path=None):
    return [d for d in load(path)["devices"] if not d.get("revoked_at")]


def add(device, path=None, now=None):
    doc = load(path)
    if len([d for d in doc["devices"] if not d.get("revoked_at")]) >= MAX_DEVICES:
        raise ValueError(f"at most {MAX_DEVICES} devices")
    doc["devices"] = [d for d in doc["devices"] if d.get("dev") != device["dev"]]
    doc["devices"].append({**device, "paired_at": int(time.time() if now is None else now)})
    save(doc, path)


MIN_PREFIX = 4


def mark_active(dev, path=None):
    """The relay confirmed the activation: the device is no longer pending."""
    doc = load(path)
    for d in doc["devices"]:
        if d.get("dev") == dev:
            d.pop("relay_pending", None)
    save(doc, path)


def revoke(dev, path=None, now=None):
    """Revoke the one active device whose id is `dev` or starts with it.

    An empty, too short or ambiguous prefix revokes nothing: it used to revoke
    every match here while the relay was told about only the last one."""
    doc = load(path)
    dev = str(dev or "")
    live = [d for d in doc["devices"] if not d.get("revoked_at")]
    hits = [d for d in live if d.get("dev") == dev]
    if not hits and len(dev) >= MIN_PREFIX:
        hits = [d for d in live if str(d.get("dev", "")).startswith(dev)]
    if len(hits) != 1:
        return False
    hits[0]["revoked_at"] = int(time.time() if now is None else now)
    save(doc, path)
    return hits[0]["dev"]


def get(dev, path=None):
    """The active device with exactly this id, or None."""
    for d in load(path)["devices"]:
        if d.get("dev") == dev and not d.get("revoked_at"):
            return d
    return None


def update(dev, path=None, **fields):
    """Set fields on the active device `dev` (passkey, last_counter, ...). False if there is none."""
    doc = load(path)
    for d in doc["devices"]:
        if d.get("dev") == dev and not d.get("revoked_at"):
            d.update(fields)
            save(doc, path)
            return True
    return False
