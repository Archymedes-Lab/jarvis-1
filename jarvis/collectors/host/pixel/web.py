"""Browser anti-tracking posture.

The same beacon that works in mail works on a page, and the browser is where
most of it happens. What matters is not whether trackers exist — they always
do — but whether the browser is configured to refuse them: tracking
protection on, and third-party cookies blocked so a beacon cannot correlate
you across sites.

Extension permissions are deliberately not repeated here; jarvis toolchain
already reports which extensions can read page content.
"""

import glob
import json
import os
import re

from jarvis.core.finding import win_finding as finding

# Firefox: 0 accepts every cookie, 1 blocks third-party, 4 blocks trackers,
# 5 is total cookie protection (the modern default).
FF_COOKIE_OK = {1, 3, 4, 5}
FF_ROOTS = ("~/.mozilla/firefox", "~/snap/firefox/common/.mozilla/firefox")

CHROMIUM_ROOTS = (
    "~/.config/google-chrome", "~/.config/chromium",
    "~/.config/microsoft-edge", "~/.config/BraveSoftware/Brave-Browser",
)


def _pref(text, name):
    m = re.search(r'user_pref\(\s*"%s"\s*,\s*([^)]+?)\s*\)'
                  % re.escape(name), text or "")
    return m.group(1).strip().strip('"') if m else None


def rules_firefox(prefs_text, where=""):
    """Read tracking protection and cookie policy out of a prefs.js."""
    out = []
    tp = _pref(prefs_text, "privacy.trackingprotection.enabled")
    # Absent means the pref was never changed; Firefox enables tracking
    # protection in its default ("standard") mode, so absence is not a fault.
    if tp == "false":
        out.append(finding(
            "tracking-web", "medium", "Firefox tracking protection is off",
            "privacy.trackingprotection.enabled is false, so known tracking "
            "beacons and pixels load on every page", where, host="wsl"))
    else:
        out.append(finding(
            "tracking-web", "ok", "Firefox tracking protection is on",
            "known trackers are blocked%s"
            % ("" if tp == "true" else " (browser default, pref not overridden)"),
            where, host="wsl"))

    behavior = _pref(prefs_text, "network.cookie.cookieBehavior")
    if behavior is not None and behavior.isdigit():
        value = int(behavior)
        if value not in FF_COOKIE_OK:
            out.append(finding(
                "tracking-web", "medium",
                "Firefox accepts third-party cookies",
                "network.cookie.cookieBehavior is %d, which lets a beacon on "
                "two different sites recognise the same browser" % value,
                where, host="wsl"))
        else:
            out.append(finding(
                "tracking-web", "ok", "Firefox restricts third-party cookies",
                "network.cookie.cookieBehavior is %d" % value, where,
                host="wsl"))
    return out


def rules_chromium(prefs, where="", browser="Chromium"):
    """Read the cookie controls out of a Chromium Preferences document.

    `profile.cookie_controls_mode`: 0 allows all, 1 blocks third-party in
    incognito only, 2 blocks third-party everywhere.
    """
    out = []
    if not isinstance(prefs, dict):
        return out
    profile = prefs.get("profile") or {}
    mode = profile.get("cookie_controls_mode")
    if mode in (0, 1):
        out.append(finding(
            "tracking-web", "medium",
            "%s allows third-party cookies" % browser,
            "cookie_controls_mode is %s, so tracking pixels can correlate "
            "this browser across sites%s"
            % (mode, " outside incognito" if mode == 1 else ""),
            where, host="wsl"))
    elif mode == 2:
        out.append(finding(
            "tracking-web", "ok",
            "%s blocks third-party cookies" % browser,
            "cookie_controls_mode is 2", where, host="wsl"))

    # Do Not Track is advisory, but its absence alongside permissive cookies
    # is worth stating plainly rather than implying it would have helped.
    if prefs.get("enable_do_not_track") is False and mode in (0, 1):
        out.append(finding(
            "tracking-web", "low",
            "%s does not send Do Not Track" % browser,
            "DNT is only a request and most trackers ignore it; blocking "
            "third-party cookies is what actually stops correlation",
            where, host="wsl"))
    return out


def _read_json(path, limit=8_000_000):
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def audit(hosts=("wsl", "win"), home=None):
    out = []
    if "wsl" not in hosts:
        return out
    expand = (lambda p: os.path.join(home, p.lstrip("~/"))) if home \
        else os.path.expanduser

    found = False
    for root in FF_ROOTS:
        for prefs in glob.glob(os.path.join(expand(root), "*", "prefs.js")):
            found = True
            try:
                with open(prefs, "r", encoding="utf-8", errors="replace") as fh:
                    out.extend(rules_firefox(fh.read(), prefs))
            except OSError:
                continue

    for root in CHROMIUM_ROOTS:
        name = os.path.basename(root.rstrip("/")).replace("-", " ").title()
        for prefs in glob.glob(os.path.join(expand(root), "*", "Preferences")):
            data = _read_json(prefs)
            if data is not None:
                found = True
                out.extend(rules_chromium(data, prefs, name))

    if not found:
        out.append(finding("tracking-web", "ok",
                           "no browser profile on the Linux side",
                           "nothing to configure here", "", host="wsl"))
    return out
