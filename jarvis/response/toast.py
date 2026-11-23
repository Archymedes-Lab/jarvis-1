"""Desktop toast for the findings that must interrupt you, mail or no mail.

Email through Resend is the only outbound channel JARVIS had, and on this
machine it has been unconfigured or paused for weeks while criticals piled up
on the dashboard (PROTECTION-REVIEW-2026-10-21 F1). A Windows toast needs no
key and no third party: the dead-man already uses the same API from a scheduled
task, and the daemon can raise one through PowerShell interop.

Bounded on purpose: only critical findings that are new, reopened or worsened,
and outages; one toast per finding key every TOAST_REPEAT_S; at most TOAST_CAP
toasts per hour; a title and a short detail, never a command line, a secret or
an address list. The user's own session can suppress toasts (Focus Assist), so
this is a channel, not a guarantee; the "no alert channel" finding stays
critical until mail works too.
"""

import json
import time

from jarvis.core import brand
from jarvis.platform.windows import ps_json, stdin_text  # noqa: F401  (stdin contract)
from jarvis.response import alert, plainalert

STATE_META = "toast_state_v1"
TOAST_REPEAT_S = 6 * 3600
TOAST_CAP = 6               # per hour
TITLE_LIMIT = 90
BODY_LIMIT = 160

# Shows one toast; title and body arrive on stdin as JSON, never on the command line.
PS_TOAST = r"""
$in = [Console]::In.ReadToEnd() | ConvertFrom-Json
[void][Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
$esc = [System.Security.SecurityElement]::Escape
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml("<toast scenario='urgent'><visual><binding template='ToastGeneric'><text>$($esc.Invoke($in.title))</text><text>$($esc.Invoke($in.body))</text></binding></visual></toast>")
$t = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('JARVIS').Show($t)
$o = @{ shown = $true } | ConvertTo-Json -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($o))
"""


def _load(store):
    try:
        state = json.loads(store.get_meta(STATE_META, "{}") or "{}")
        return state if isinstance(state, dict) else {}
    except (TypeError, ValueError):
        return {}


def select(findings, state, now):
    """Pure: which findings deserve a toast now, and the updated state.

    `state` maps finding key -> last toast time, plus "_sent": [times]."""
    sent = [t for t in state.get("_sent", []) if isinstance(t, (int, float)) and now - t < 3600]
    chosen = []
    for f in findings or ():
        if not isinstance(f, dict):
            continue
        sev = f.get("severity")
        outage = alert.is_outage(f)
        if sev != "critical" and not outage:
            continue
        if f.get("category") in alert.NOPAGE_CATEGORIES and not outage:
            continue
        key = alert.finding_key(f)
        last = state.get(key)
        if isinstance(last, (int, float)) and now - last < TOAST_REPEAT_S:
            continue
        if len(sent) + len(chosen) >= TOAST_CAP:
            break
        chosen.append((key, f))
    new_state = {k: v for k, v in state.items() if k != "_sent"
                 and isinstance(v, (int, float)) and now - v < TOAST_REPEAT_S}
    for key, _ in chosen:
        new_state[key] = now
    new_state["_sent"] = sent + [now] * len(chosen)
    return chosen, new_state


def text(finding, job):
    """(title, body) in everyday words (response/plainalert.py), facts kept: the
    title is the finding's own, the body says what kind of thing it is, then
    what was seen. Both fit TITLE_LIMIT / BODY_LIMIT after branding."""
    title = plainalert.clip(f"{plainalert.PRODUCT}: {brand.brand(plainalert.title_of(finding))}",
                            TITLE_LIMIT)
    short = plainalert.SHORT[plainalert.kind(finding, job)]
    seen = alert.stable_text(brand.brand(finding.get("detail") or ""))
    body = (f"{short} What it saw: {seen}" if seen
            else f"{short} Open {plainalert.PRODUCT} to see what this means and what to do.")
    return title, plainalert.clip(body, BODY_LIMIT)


def show(title, body, runner=None):
    """Raise one toast. Returns True when Windows reported it shown."""
    run = runner or (lambda script, payload: ps_json(script, timeout=20, payload=payload))
    result = run(PS_TOAST, json.dumps({"title": title, "body": body}))
    return bool(isinstance(result, dict) and result.get("shown"))


def deliver(store, job, findings, now=None, runner=None):
    """Toast the findings `select` chooses. Never raises."""
    try:
        now = int(time.time() if now is None else now)
        chosen, state = select(findings, _load(store), now)
        shown = 0
        for _key, f in chosen:
            title, body = (brand.brand(x) for x in text(f, job))
            if show(title, body, runner):
                shown += 1
        if chosen:
            store.set_meta(STATE_META, json.dumps(state))
        return shown
    except Exception:
        return 0
