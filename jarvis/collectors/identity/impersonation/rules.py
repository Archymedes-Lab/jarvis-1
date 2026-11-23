"""Turning the identity sample into findings.

Two different claims live here and are kept apart on purpose:

  someone else is acting   a logon session, remote desktop connection or
                           automatic logon that is not you sitting here

  something is acting AS   assistive technology, stored credentials and
  you                      automatic logon let software authenticate and
                           drive the desktop with your identity and leave
                           input telemetry that looks exactly like yours

Neither is a verdict. Each names what was observed and what would distinguish
a legitimate cause from an impersonation.
"""

from jarvis.platform.windows import aslist

# Win32_LogonSession logon types. 2/11 are someone at the keyboard, 3 is a
# network authentication, 10 is Remote Desktop, 5 is a service.
LOGON_TYPES = {
    0: "system", 2: "interactive", 3: "network", 4: "batch", 5: "service",
    7: "unlock", 8: "network-cleartext", 9: "new-credentials",
    10: "remote-interactive", 11: "cached-interactive",
}

# Types that mean a human session, as opposed to a service or a share access.
HUMAN_TYPES = {2, 7, 10, 11}

# Credential targets Windows itself creates. Present so the report can say
# "these are yours" instead of listing every entry as a risk.
BENIGN_CRED_PREFIXES = (
    "virtualapp/didlogical", "windowslive:target=virtualapp/didlogical",
    "legacygeneric:target=microsoftaccount", "microsoftaccount:",
    "domain:target=", "wsl/",
)


def _finding(severity, title, detail, where="", host="win"):
    return {"category": "impersonation", "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


def sessions(data):
    """Who holds a logon session, and is any of it not you?"""
    me = (data.get("me") or "").lower()
    out, others, remote = [], [], []
    for s in aslist(data.get("logons")):
        if not isinstance(s, dict):
            continue
        t = int(s.get("type", -1))
        user = (s.get("user") or "").strip()
        if t not in HUMAN_TYPES or not user:
            continue
        if t == 10:
            remote.append(s)
        if me and user.lower() != me and not user.lower().endswith("$"):
            others.append(s)

    for s in remote:
        out.append(_finding(
            "high", "a Remote Desktop session is logged on",
            "%s holds a remote-interactive session (started %s). Anything it "
            "types or clicks arrives as ordinary input — the keyboard hook "
            "cannot tell it from you at this machine."
            % (s.get("user") or "?", s.get("start") or "unknown"),
            "LogonId %s" % s.get("id", "?")))

    for s in others:
        if int(s.get("type", -1)) == 10:
            continue
        out.append(_finding(
            "medium", "an interactive session belongs to another account",
            "%s holds a %s session (started %s) while you are signed in as %s"
            % (s.get("user"), LOGON_TYPES.get(int(s.get("type", -1)), "?"),
               s.get("start") or "unknown", data.get("me") or "?"),
            "LogonId %s" % s.get("id", "?")))

    if not remote and not others:
        out.append(_finding(
            "ok", "no session belongs to anyone but you",
            "every interactive logon session on this machine is %s"
            % (data.get("me") or "your account"), ""))
    return out


def input_while_locked(data, real_keys=0, real_clicks=0, window_label="the last sample"):
    """Real, unflagged input while the workstation is locked.

    This is the strongest single impersonation signal available here. Input
    that carries no injected flag is normally indistinguishable from a person
    typing — unless the screen is locked, because then there is no person.
    """
    locked = int(data.get("locked", -1))
    if locked < 0:
        return []
    if not locked:
        return []
    if real_keys <= 0 and real_clicks <= 0:
        return [_finding(
            "ok", "no input while the workstation was locked",
            "the session is locked and nothing typed or clicked during "
            "%s" % window_label, "")]
    return [_finding(
        "critical", "real input arrived while the workstation was locked",
        "%d keystroke(s) and %d click(s) during %s carried no injected flag, "
        "so they present as a person at the keyboard — but the session is "
        "locked. Driver-level injection, a hardware implant and a remote "
        "session all produce exactly this."
        % (real_keys, real_clicks, window_label), "LogonUI present")]


# The ATs key holds two unrelated kinds of entry. Most are accessibility
# *settings* whose "ATExe" value is a number or a flag name — stickykeys,
# highcontrast, filterkeys. Those launch nothing and are not an automation
# surface. Only an entry naming a real executable is an assistive *program*
# able to run on the secure desktop and drive other windows.
STOCK_ATS = {
    "narrator.exe", "magnify.exe", "osk.exe", "voiceaccess.exe",
    "sapisvr.exe", "eoaexperiences.exe", "livecaptions.exe",
    "utilman.exe", "displayswitch.exe", "atbroker.exe",
}


def _at_executable(entry):
    """The executable an ATs entry actually launches, or "" if it launches none."""
    for value in (entry.get("exe"), entry.get("startExe")):
        text = (value or "").strip().strip('"')
        if text.lower().endswith(".exe"):
            return text
    return ""


def automation(data):
    """Software able to drive the desktop without producing input events."""
    out = []
    programs = []
    for a in aslist(data.get("atServices")):
        if not isinstance(a, dict):
            continue
        exe = _at_executable(a)
        if exe:
            programs.append((a.get("name") or "?", exe))

    for name, exe in sorted(programs):
        base = exe.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        stock = base in STOCK_ATS or exe.lower().startswith(
            ("%systemroot%", "c:\\windows", "c:/windows"))
        out.append(_finding(
            "low" if stock else "high",
            "assistive technology is registered"
            + ("" if stock else " by a non-Windows program"),
            "%s -> %s.%s Registered assistive technology can read and drive any "
            "window through UI Automation, which produces no keyboard or mouse "
            "event at all — nothing in the input log would show it."
            % (name, exe,
               " This one ships with Windows." if stock
               else " This one does not ship with Windows."),
            "Accessibility\\ATs\\%s" % name))

    if not programs:
        out.append(_finding(
            "ok", "no assistive program is registered",
            "the ATs key holds only accessibility settings; nothing is "
            "registered to run on the secure desktop and drive other windows",
            "Accessibility\\ATs"))
    return out


def credentials(data):
    """Stored secrets that let software authenticate as you with no prompt."""
    out = []
    creds = [c for c in aslist(data.get("creds")) if isinstance(c, str)]
    interesting = [c for c in creds
                   if not c.lower().startswith(BENIGN_CRED_PREFIXES)]
    if interesting:
        out.append(_finding(
            "medium", "stored credentials can authenticate as you",
            "%d saved credential target(s), including %s. Any process running "
            "as you can use these without a prompt, so a stolen session and a "
            "legitimate one look the same to the service at the other end."
            % (len(interesting), ", ".join(interesting[:3])),
            "Credential Manager"))
    auto = data.get("autoLogon") or {}
    if str(auto.get("enabled", "0")) == "1":
        out.append(_finding(
            "high", "automatic logon is enabled",
            "this machine signs %s in without anyone present%s — an unattended "
            "interactive session is indistinguishable from you being here"
            % (auto.get("user") or "an account",
               ", and the password is stored in the registry in clear text"
               if auto.get("hasPassword") else ""),
            "Winlogon\\AutoAdminLogon"))
    return out


def audit_data(data, real_keys=0, real_clicks=0, window_label="the last sample"):
    """Every rule, over one sample. Pure, so it is testable without Windows."""
    if not data:
        return [_finding(
            "low", "identity state unavailable",
            "the Windows bridge did not return a sample; who is acting on "
            "this machine is unknown for this run", "")]
    out = []
    out.extend(sessions(data))
    out.extend(input_while_locked(data, real_keys, real_clicks, window_label))
    out.extend(automation(data))
    out.extend(credentials(data))
    for err in aslist(data.get("errors")):
        out.append(_finding("low", "part of the identity sample is unavailable",
                            str(err), ""))
    return out
