"""Everyday words for every notification the daemon sends.

The owner asked that every alert (email, phone, webhook, ntfy, syslog, desktop
toast) be understandable by anyone: what happened and what, if anything, to do,
in plain words, with the exact facts kept beside it ("What it saw: <title>").
The desktop app's pop-ups say the same thing from the same sentences
(desktop/src/watch.rs, desktop/ui/src/lib/guide.json).

Invariants (tests/test_plainalert.py):
  * A fact is never removed or softened: the finding's own title, where it was
    seen and its severity stay in every message.
  * A plain sentence never claims a confirmed compromise, and never claims the
    computer is safe.
  * Deterministic: no model writes any of this.
  * GUIDE is a copy of the interface's guide (the daemon package does not ship
    desktop/ui); a test keeps it identical to guide.json and to the dashboard.
"""

from __future__ import annotations

from jarvis.response import categories

PRODUCT = "ARGUS-INSTINCT"
PREFIX = f"[{PRODUCT}]"
# The phone shows at most this much of a title on the lock screen
# (notify/channel.py LOCK_SCREEN_TITLE); subjects are built to fit it.
SUBJECT_LIMIT = 90

# Words a person who is not an engineer would not follow. The human-facing
# part of every message is tested against this list.
JARGON = ("daemon", "collector", "telemetry", "blind", "finding", "unobserved",
          "jarvis serve", "`", "observation", "digest", "interrupt", "snapshot",
          "stale", "remediation", "triage")

# [what it is, why it matters, what to do] per finding category: a copy of
# desktop/ui/src/lib/guide.json (itself the dashboard's GUIDE).
GUIDE = {
    "data at rest": (
        "A file on your computer seems to have a password or secret key written inside it in plain text.",
        "If anyone else can open that file, they could use that password or key as if they were you.",
        "Open the file and see if you put it there on purpose. If it is a real password you still use, change it on the website or service it belongs to.",
    ),
    "persistence": (
        "A program is set up to start by itself, for example every time you turn on your computer.",
        "Many normal apps do this, like updaters. But harmful programs also do this so they come back after a restart.",
        "Look at the name. If you recognise the app, you can ignore this. If you do not, do not delete anything yet. Ask someone you trust to check it.",
    ),
    "staging": (
        "A new program file was just saved on your computer, and the computer cannot tell who made it.",
        "Programs you download or build yourself do this too. Bad programs can arrive the same way.",
        "Did you just download or install something? Then this is probably it. If not, ask someone you trust to take a look.",
    ),
    "rules": (
        "Your computer has a rule that lets other devices talk to one of its programs.",
        "The more open the rule is, the easier it is for other devices on your network to reach that program.",
        "Look at which program it is. If you do not use it, ask someone you trust if the rule can be removed.",
    ),
    "remote": (
        "Your computer is set up so someone can connect to it from far away and use it.",
        "If you did not turn this on, someone else could possibly get in.",
        "If you set this up yourself, you can ignore this. If not, ask someone you trust to check it soon.",
    ),
    "access": (
        "An app is using, or is allowed to use, your camera or microphone.",
        "That is normal during a video call. It is unexpected if you are not on a call or recording.",
        "Check which app it is. If you did not start it, close it and ask someone you trust to look.",
    ),
    "internet": (
        "A program on your computer is waiting for other devices to connect to it, or ARGUS-INSTINCT cannot fully watch your internet traffic.",
        "Programs that can be reached from outside are an easier target if they have a mistake in them.",
        "If you know this program and want it open, there is nothing to do. If not, ask someone you trust.",
    ),
    "impersonation": (
        "Sign-ins you saved on this computer, like passwords kept in your browser, could be used to log in as you.",
        "Any program that runs on your account could use them.",
        "Remove saved sign-ins for accounts you no longer use.",
    ),
    "accounts": (
        "A user account on this computer is hidden from the sign-in screen or looks unusual.",
        "Hidden accounts are sometimes used to keep access to a computer. Some apps also make them for normal reasons.",
        "Do not delete it. First find out which app made it, or ask someone you trust.",
    ),
    "interception": (
        "Your computer trusts a security certificate that does not come from the usual list.",
        "A certificate like this can let its owner read private web traffic, such as sign-ins.",
        "Companies and some developer tools add these on purpose. If you do not know where it came from, ask someone you trust.",
    ),
    "injected code": (
        "A program has hidden instructions running in its memory that are not from a file on your computer.",
        "Browsers and game tools do this for normal reasons. Harmful programs also use it to hide.",
        "Check whether it is a program you know and use. If it is not, ask someone you trust.",
    ),
    "clickfix": (
        "Your computer's history shows commands that look like they were copied from a website and pasted in.",
        "Fake \"fix this problem\" pages trick people into running a harmful command themselves.",
        "Think: did you paste a command from a website lately? If you did not, tell someone you trust right away.",
    ),
    "av": (
        "Windows' built-in protection, called Defender, found something it did not like.",
        "Defender has already raised a flag, so it is worth a look.",
        "Open Windows Security to see what it found and what it already did about it.",
    ),
    "posture": (
        "A protection feature in Windows is turned off, or ARGUS-INSTINCT could not read whether it is on.",
        "A protection that is off gives you less cover.",
        "Open the details to see which one. If you did not switch it off, turn it back on.",
    ),
    "malware defense": (
        "A feature that helps stop harmful programs is switched off.",
        "With it off, your computer has one fewer guard.",
        "Decide if you want it on. Most people do.",
    ),
    "defense": (
        "ARGUS-INSTINCT could not check one of Windows' protection settings.",
        "ARGUS-INSTINCT cannot say whether that protection is working if it cannot read it.",
        "Open the details to see which one.",
    ),
    "mitigations": (
        "A program is running without an extra safety feature that makes it harder to attack.",
        "If that program has a mistake in it, it would be easier to break into.",
        "You usually do not need to do anything. Keep the program up to date.",
    ),
    "screen": (
        "An app may be able to record what is on your screen without showing you.",
        "A screen recording can capture anything you have open, like messages or passwords.",
        "Check whether you use a screen-sharing or recording app. If you do not, ask someone you trust.",
    ),
    "extension": (
        "An add-on is installed in your web browser.",
        "Add-ons can see the web pages you visit, so each one has to be trusted.",
        "Keep only the add-ons you know. Remove the rest from your browser's add-ons page.",
    ),
    "daemon": (
        "The part of ARGUS-INSTINCT that watches your computer is not running the way it should.",
        "ARGUS-INSTINCT cannot watch that part of your computer until it is fixed.",
        "Open the Monitoring page. It tells you why and how to fix it.",
    ),
    "collectors": (
        "One of ARGUS-INSTINCT's checks could not finish.",
        "Until it does, ARGUS-INSTINCT cannot tell you whether that part of your computer is okay.",
        "Open the Monitoring page to see why.",
    ),
    "visibility": (
        "ARGUS-INSTINCT can only see part of what is going on in one area of your computer.",
        "It cannot tell you about anything it cannot see.",
        "Open the Monitoring page to see what is hidden from it, and why.",
    ),
}

# When the category has no guide entry: the kind of news decides the sentence.
FALLBACK = {
    "threat": (f"{PRODUCT} noticed activity on this computer that could be an attack, or could be "
               "something you or your software did.",
               "Look at what it saw and decide whether you expect it. Do not delete anything "
               "based on this alone."),
    "exposure": (f"{PRODUCT} found a setting or gap that could make this computer easier to attack.",
                 "Look at what it saw and decide whether to change it."),
    "updates": ("Software on this computer has an update that is not installed yet.",
                "Install it when you can."),
    "monitoring": (GUIDE["collectors"][0], GUIDE["collectors"][2]),
    "system": (GUIDE["daemon"][0], GUIDE["daemon"][2]),
    "test": ("This is a test message you asked for.", "Nothing to do."),
}

# Short forms for the desktop toast, whose body holds 160 characters.
SHORT = {
    "threat": "This could be an attack, or something you did.",
    "exposure": "A setting or gap could make this computer easier to attack.",
    "updates": "An update is waiting to be installed.",
    "monitoring": "A check stopped working, so part of this computer is not being watched.",
    "system": f"Part of {PRODUCT} is not working as expected.",
    "test": "This is a test.",
}


def _outage(finding):
    from jarvis.response import alert
    return alert.is_outage(finding)


def kind(finding, job=""):
    """The kind of news one finding is (response/categories.py), with a check that
    stopped working always filed as such."""
    f = finding or {}
    if _outage(f) and f.get("category") != "daemon":
        return "monitoring"
    return categories.of_finding(f, job)


# Finding categories that are the same kind of thing as a guide entry.
ALIASES = {"present": "data at rest"}


def guide(finding, job=""):
    """(what it is, what to do) for one finding, in everyday words."""
    cat = str((finding or {}).get("category") or "")
    g = GUIDE.get(ALIASES.get(cat, cat))
    if g:
        return g[0], g[2]
    return FALLBACK[kind(finding, job)]


def headline(finding, job="", tag=None):
    """A few words saying how much this needs you: the start of a subject."""
    f = finding or {}
    if tag == "RESOLVED":
        return "No longer seen"
    k = kind(f, job)
    if k == "monitoring":
        return "A check stopped working" if _outage(f) else "Something is not being checked"
    if k == "system":
        return f"Part of {PRODUCT} stopped working"
    if k == "updates":
        return "An update is waiting"
    sev = f.get("severity")
    if sev == "critical":
        return "Please look at this now"
    if sev == "high":
        return "Worth a look soon"
    return "Worth a look"


def title_of(finding):
    return " ".join(str((finding or {}).get("title") or "something it could not name").split())


def facts(finding):
    """The exact facts, unchanged: what it saw, where, how serious."""
    f = finding or {}
    out = [f"What it saw: {title_of(f)}"]
    if f.get("where"):
        out.append(f"Where: {f['where']}")
    if f.get("severity"):
        out.append(f"How serious: {f['severity']}")
    return out


def lead(finding, job="", tag=None):
    """Lines for one item: the plain sentence, then the facts."""
    if tag == "RESOLVED":
        return [f"{headline(finding, job, tag)}. That alone does not prove it was fixed.",
                *facts(finding)]
    means, todo = guide(finding, job)
    return [f"{headline(finding, job, tag)}. {means} {todo}", *facts(finding)]


def clip(text, limit):
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:max(0, limit - 1)].rstrip() + "…"


def subject(items, need=None, limit=SUBJECT_LIMIT):
    """One subject for [(finding, job, tag)], worst first: what it is, the title
    of the first thing seen and, with several, how many need you. Fits the
    lock-screen limit."""
    items = list(items)
    if not items:
        return f"{PREFIX} Nothing needs you right now"
    active = [i for i in items if i[2] != "RESOLVED"] or items
    f, job, tag = active[0]
    more = ""
    if len(items) > 1:
        more = f" (and {len(items) - 1} more" + (f", {need} need you)" if need is not None else ")")
    head = f"{PREFIX} {headline(f, job, tag)}: "
    # Branded first: delivery renames JARVIS, and the limit holds for what is sent.
    from jarvis.core import brand
    return head + clip(brand.brand(title_of(f)), limit - len(head) - len(more)) + more


def jargon(text):
    """The jargon words present in `text` (empty when it is plain)."""
    low = (text or "").lower()
    return [w for w in JARGON if w in low]
