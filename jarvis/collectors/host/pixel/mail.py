"""Tracking pixels in mail, and whether the mail client blocks them.

A tracking pixel is a remote image, usually 1x1 and transparent, whose only
job is to tell the sender that a message was opened, from which IP address,
at what time, and how often. Blocking remote images stops it: the request is
never made, so there is nothing to report.

Two things are checked. Whether the mail clients on this machine load remote
content by default, and whether JARVIS's own alert mail carries tracking —
a security tool that beacons every time you read an alert is its own problem.
"""

import os
import re

from jarvis.core.finding import win_finding as finding
from jarvis.core.paths import load_win_script
from jarvis.platform.windows import aslist, ps_json

# A beacon is a remote image that is too small to be content, or one whose URL
# is a tracking endpoint. Neither test alone is reliable, so both are reported
# with what was actually matched.
BEACON_SIZE = re.compile(
    r"<img\b[^>]*?\b(?:width|height)\s*=\s*[\"']?\s*([0-3])\s*[\"']?[^>]*>",
    re.I | re.S)
BEACON_STYLE = re.compile(
    r"<img\b[^>]*style=[\"'][^\"']*(?:width|height)\s*:\s*[0-3]\s*px", re.I)
BEACON_HOSTS = re.compile(
    r"\b(?:open|track|trk|beacon|pixel|px|email|click|mailstat|"
    r"list-manage|sendgrid\.net|mailgun\.org|mcusercontent|"
    r"awstrack\.me|resend\.com|customeriomail|hubspotemail|"
    r"sparkpostmail|mandrillapp|cmail\d*\.com)\b", re.I)
IMG_SRC = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.I | re.S)

# Thunderbird blocks remote content when this pref is true (the default).
TB_PREF = "mailnews.message_display.disable_remote_image"


def scan_html(html):
    """Report the tracking beacons in one HTML message body."""
    hits = []
    for src in IMG_SRC.findall(html or ""):
        if not src.lower().startswith(("http://", "https://")):
            continue
        reasons = []
        if BEACON_HOSTS.search(src):
            reasons.append("tracking-style URL")
        # A 1x1 image is a beacon regardless of where it is hosted.
        tag = next((m.group(0) for m in re.finditer(
            r"<img\b[^>]*>", html or "", re.I | re.S) if src in m.group(0)), "")
        if BEACON_SIZE.search(tag) or BEACON_STYLE.search(tag):
            reasons.append("1x1 or invisible image")
        if reasons:
            hits.append({"src": src, "why": ", ".join(reasons)})
    return hits


def rules_message(html, where=""):
    hits = scan_html(html)
    if not hits:
        return [finding("tracking-mail", "ok", "no tracking pixel in this "
                        "message", "no remote beacon image was found in the "
                        "HTML body", where, host="wsl")]
    return [finding(
        "tracking-mail", "medium", "tracking pixel in a mail message",
        "%d beacon image(s); the first is %s (%s). Opening this message tells "
        "the sender when you read it and from which address."
        % (len(hits), hits[0]["src"][:120], hits[0]["why"]),
        where, host="wsl")]


def _thunderbird_profiles(home=None):
    home = home or os.path.expanduser("~")
    roots = [os.path.join(home, ".thunderbird"),
             os.path.join(home, ".mozilla-thunderbird"),
             os.path.join(home, "snap/thunderbird/common/.thunderbird")]
    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            entries = os.listdir(root)
        except OSError:
            continue
        for name in entries:
            prefs = os.path.join(root, name, "prefs.js")
            if os.path.isfile(prefs):
                yield prefs


def rules_thunderbird(prefs_text, where=""):
    """Thunderbird blocks remote images unless the pref is explicitly false."""
    m = re.search(r'user_pref\(\s*"%s"\s*,\s*(true|false)\s*\)'
                  % re.escape(TB_PREF), prefs_text or "")
    if m and m.group(1) == "false":
        return [finding(
            "tracking-mail", "high", "Thunderbird loads remote images "
            "automatically",
            "%s is set to false, so every tracking pixel in every message "
            "fires as soon as the message is displayed." % TB_PREF,
            where, host="wsl")]
    return [finding(
        "tracking-mail", "ok", "Thunderbird blocks remote images",
        "remote content is blocked by default, so tracking pixels do not "
        "load until you allow them per message", where, host="wsl")]


PS_MAIL = load_win_script("pixel_mail.ps1")


def rules_outlook(data):
    out = []
    entries = aslist((data or {}).get("outlook"))
    if data is not None and not entries:
        return [finding("tracking-mail", "ok", "no Outlook profile found",
                        "no Office mail configuration is present to check", "")]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        version = entry.get("version", "?")
        block = entry.get("blockHttp")
        where = "HKCU\\Software\\Microsoft\\Office\\%s\\Outlook" % version
        # 1 means "do not download pictures automatically", which is the
        # Outlook default; 0 means every beacon fires on preview.
        if block == 0:
            out.append(finding(
                "tracking-mail", "high",
                "Outlook downloads remote images automatically",
                "BlockHTTPimages is 0 for Office %s, so a tracking pixel "
                "fires in the reading pane before you decide to open the "
                "message." % version, where))
        else:
            out.append(finding(
                "tracking-mail", "ok", "Outlook blocks remote images",
                "Office %s does not download pictures in messages "
                "automatically" % version, where))
    return out


def audit(hosts=("wsl", "win"), home=None):
    out = []
    if "wsl" in hosts:
        seen = False
        for prefs in _thunderbird_profiles(home):
            seen = True
            try:
                with open(prefs, "r", encoding="utf-8", errors="replace") as fh:
                    out.extend(rules_thunderbird(fh.read(), prefs))
            except OSError:
                continue
        if not seen:
            out.append(finding("tracking-mail", "ok",
                               "no Thunderbird profile on the Linux side",
                               "nothing to configure here", "", host="wsl"))
    if "win" in hosts:
        out.extend(rules_outlook(ps_json(PS_MAIL)))
    return out
