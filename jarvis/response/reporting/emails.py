"""The emails JARVIS sends, as a plain-text part and an HTML part.

Every message answers the same question first — what needs you, and what is
JARVIS already handling — before it says anything else. The grouping comes
from triage.py; the HTML comes from email_ui.py; the plain-text part carries
the same structure for clients that do not render HTML.
"""

import time

from jarvis.response import acknowledge, alert, plainalert, protocols

from . import email_ui as ui
from . import score, triage, voice

RULE = "─" * 58


# ── plain text ────────────────────────────────────────────────────────────

def _text_health(result, delta):
    return score.summary_lines(result, delta)


def _text_group(owner, entries, limit=25):
    if not entries:
        return []
    lines = ["", RULE, f"{triage.LABEL[owner].upper()} ({len(entries)})",
             f"  {triage.BLURB[owner]}", RULE]
    for n, (f, job, t, tag) in enumerate(entries[:limit], 1):
        lines.append(f"{n}. [{(f.get('severity') or '?').upper()}]"
                     + (f" {tag}:" if tag else "") + f" {f.get('title', '')}")
        if f.get("detail"):
            lines.append(f"   {f['detail'][:300]}")
        if f.get("forensics"):
            lines.append("   what happened, step by step:")
            lines.extend(f"     {line}" for line in f["forensics"])
        lines.append(f"   → {t['action']}")
        if t.get("command"):
            lines.append(f"   $ {t['command']}")
        if owner == triage.YOU_CONFIRM and t.get("id"):
            lines.append(f"   if this was you: jarvis ack {t['id']} --reason \"…\"")
        meta = " · ".join(x for x in (job, f.get("host"), f.get("where")) if x)
        if meta:
            lines.append(f"   ({meta})")
    if len(entries) > limit:
        lines.append(f"   … and {len(entries) - limit} more on the dashboard")
    return lines


def _grouped(entries):
    """entries: [(finding, job, tag)] -> {owner: [(finding, job, triage, tag)]}"""
    out = {owner: [] for owner in triage.ORDER}
    for f, job, tag in entries:
        t = triage.classify(f, job)
        out[t["owner"]].append((f, job, t, tag))
    for owner in out:
        out[owner].sort(key=lambda e: alert.SEV_RANK.get(e[0].get("severity"), 9))
    return out


def _counts(grouped):
    return {owner: len(items) for owner, items in grouped.items()}


def _needs_you(counts):
    return counts.get(triage.YOU_DO, 0) + counts.get(triage.YOU_CONFIRM, 0)


# ── change digest / priority changes ──────────────────────────────────────

def _related_chains(active):
    """Multi-observation stories among digest findings. Pure wrapper.

    Only chains with more than one member qualify: a single observation
    is already listed in its triage group, and restating it as a "story"
    would be the alert inflation this exists to reduce.
    """
    try:
        from jarvis.core import activity as activity_mod
        items = [{**f, "job": job} for f, job, _tag in active]
        return [c for c in activity_mod.correlate(items) if c["count"] > 1]
    except Exception:
        return []


def _intro(items, need, urgent):
    """The opening plain sentence: how much this needs you, never a verdict."""
    first = ("Something new needs you now." if urgent and need else
             "Something changed that you should know about right away." if urgent else
             f"{need} thing{'s' if need != 1 else ''} need{'s' if need == 1 else ''} you." if need else
             "Nothing here needs you right now.")
    threat = any(plainalert.kind(f, job) == "threat" for f, job, tag in items if tag != "RESOLVED")
    return first + (" This is not proof that something is wrong, only that it is worth a look."
                    if threat else "")


def _text_leads(items, limit=5):
    lines = []
    for n, (f, job, tag) in enumerate(items[:limit], 1):
        sentence, *facts = plainalert.lead(f, job, tag)
        lines += ["", f"{n}. {sentence}", *[f"   {x}" for x in facts]]
    if len(items) > limit:
        lines += ["", f"... and {len(items) - limit} more in the details below."]
    return lines


def digest(ordered, urgent, health, delta, now, conf=None, store=None):
    """ordered: [(key, queue item)] -> (subject, text, html).

    The message opens in plain words (plainalert.py): how much it needs you, and
    for each item what it is, what to do and exactly what was seen. The full
    details follow unchanged."""
    active = [(item["finding"], item["job"], item["tag"]) for _key, item in ordered
              if item["tag"] != "RESOLVED"]
    resolved = [item for _key, item in ordered if item["tag"] == "RESOLVED"]
    everything = active + [(i["finding"], i["job"], "RESOLVED") for i in resolved]
    grouped = _grouped(active)
    counts = _counts(grouped)

    need = _needs_you(counts)
    subject = plainalert.subject(everything, need)
    intro = _intro(everything, need, urgent)
    line, by_model = voice.opener(conf, voice.facts_for(
        "change digest", counts, urgent, health, delta, len(resolved),
        [f.get("title") for f, _job, _tag in active]),
        time.strftime("%Y-%m-%d", time.localtime(now)), store=store)

    tone = "urgent" if urgent else ("digest" if need else "calm")
    mood = ("These need you now." if urgent else
            f"{need} need you — the rest is handled or listed below." if need else
            "All quiet — nothing needs you. Splendid.")
    text = [intro, *_text_leads(everything), "", RULE, "DETAILS", RULE,
            f"{need} need you · {counts[triage.JARVIS]} handled by ARGUS-INSTINCT"
            + (f" · {len(resolved)} no longer seen" if resolved else ""),
            mood, "", line, ""]
    if health:
        text += _text_health(health, delta)
    chains = _related_chains(active)
    if chains:
        text += ["", RULE, f"RELATED ACTIVITY ({len(chains)} "
                           f"{'story' if len(chains) == 1 else 'stories'})",
                 "  Linked across several checks; each story is one sequence of events, "
                 "not separate alerts."]
        text += [f"- {c['headline']}" for c in chains]
    for owner in triage.ORDER:
        text += _text_group(owner, grouped[owner])
    if resolved:
        text += ["", RULE, f"NO LONGER SEEN ({len(resolved)})",
                 "  Not in the latest results; that alone does not prove it was fixed.", RULE]
        text += [f"- {item['finding'].get('title', '')} ({item['job']})" for item in resolved]
    text += ["", ("Urgent messages are only for something new or getting worse; everything else "
                  "waits for the next summary." if urgent else
                  "Things that have not changed stay on the dashboard and in the daily summary; "
                  "they do not cause repeat emails.")]

    for owner in triage.ORDER:
        for f, job, t, tag in grouped[owner]:
            item = next(i for _k, i in ordered if i["finding"] is f)
            if tag == "ESCALATED":
                hours = (now - item["first"]) // 3600
                grouped[owner][grouped[owner].index((f, job, t, tag))] = (
                    f, job, t, f"reminder · {hours}h open")

    inner = ui.header("ARGUS-INSTINCT · " + ("needs you now" if urgent else "what changed"),
                      subject.removeprefix(plainalert.PREFIX).strip(),
                      time.strftime("%A %d %B, %H:%M", time.localtime(now)), tone=tone)
    inner += ui.section(f'<div {ui.tw("text-base text-slate-800 leading-relaxed")}>{ui.esc(intro)}</div>',
                        "px-6 pt-5 pb-1")
    inner += ui.plain_leads(everything)
    inner += ui.section(ui.heading("Details"), "px-6 pt-6 pb-0")
    inner += ui.section(ui.hero([(need, "need you"),
                                 (counts[triage.JARVIS], "handled by ARGUS-INSTINCT"),
                                 (len(resolved), "no longer seen")]), "px-6 pt-5 pb-1")
    inner += ui.voice(line, by_model)
    inner += ui.section(ui.owner_summary(counts), "px-5 pt-5 pb-1")
    if chains:
        inner += ui.section(
            ui.heading(f"Related activity ({len(chains)})",
                       "Linked across several checks; one sequence of events, not separate alerts.")
            + "".join(ui.story_card(c) for c in chains))
    for owner in triage.ORDER:
        inner += ui.owner_section(owner, grouped[owner])
    if resolved:
        rows = "".join(
            f'<div {ui.tw("text-sm text-slate-700 py-1")}>&#10003; {ui.esc(i["finding"].get("title"))} '
            f'<span {ui.tw("text-slate-400")}>({ui.esc(i["job"])})</span></div>' for i in resolved)
        inner += ui.section(ui.heading("No longer seen",
                                       "Not in the latest results; that alone does not prove a fix.")
                            + f'<div {ui.tw("mt-2")}>{rows}</div>')
    if health:
        inner += ui.section(ui.health_panel(health, delta), "px-6 py-5 bg-slate-50")
    inner += ui.footer("Things that have not changed stay on the dashboard and in the daily summary; "
                       "they do not cause repeat emails. Passwords and keys are never included.")
    html = ui.document(subject, intro, inner)
    return subject, "\n".join(text) + "\n", html


# ── the scheduled briefing ────────────────────────────────────────────────
#
# JARVIS reports on a schedule, like a chief of staff, instead of mailing every
# change: a condition code, the one thing worth doing, what changed since the
# last briefing, what it is watching on its own, the wins, and the state of its
# own evidence. Only something new and critical, or a confirmed outage,
# interrupts between briefings (notifications.py).

def condition(need, critical):
    """(code, reason) — deterministic, from counts only."""
    if critical:
        return "RED", (f"{critical} critical matter{'s' if critical != 1 else ''} "
                       "open. Start with the mission below.")
    if need:
        return "AMBER", (f"No critical matters. {need} item{'s' if need != 1 else ''} "
                         "want your hands.")
    return "GREEN", "Nothing needs you. The watch continues."


def _custody_lines(state):
    """Plain facts about JARVIS's own evidence, from the evidence job's record."""
    if not state:
        return []
    out = []
    vault = state.get("vault_job") or {}
    if vault.get("ok"):
        out.append(f"Evidence vault: {vault.get('vaulted_segments', 0)} sealed segments held "
                   "where only administrators can write"
                   + ("; DIVERGENCE recorded" if vault.get("diverged") else "") + ".")
    elif state.get("vault_job"):
        out.append("Evidence vault: not running — sealed history is not being vaulted.")
    anchors = state.get("anchors") or {}
    if anchors.get("records"):
        confirmed = anchors.get("confirmed", 0)
        out.append(f"Public anchors: {anchors['records']} timestamped chain head"
                   f"{'s' if anchors['records'] != 1 else ''}, {confirmed} confirmed in Bitcoin"
                   + (f" (latest block {anchors['latest_confirmed_height']})"
                      if anchors.get("latest_confirmed_height") else "") + ".")
    sysmon = (state.get("sysmon") or {}).get("state")
    if sysmon == "match":
        out.append("Sysmon: running the reviewed baseline.")
    elif sysmon == "drift":
        out.append("Sysmon: NOT running the reviewed baseline — see the details on the dashboard.")
    return out


def _mission(protocol_state, grouped):
    """(title, lines) for the single most valuable thing to do, or None.

    An open critical always comes first: the condition is RED because of it.
    Then the next protocol, then the worst remaining item."""
    for owner in (triage.YOU_DO, triage.YOU_CONFIRM):
        for f, _job, t, _tag in grouped[owner]:
            if f.get("severity") == "critical":
                lines = [t["action"]] + ([t["command"]] if t.get("command") else [])
                if owner == triage.YOU_CONFIRM and t.get("id"):
                    lines.append(f"If this was you: jarvis ack {t['id']} --reason \"…\"")
                return f.get("title", ""), lines
    item = protocols.pick_next(protocol_state) if protocol_state else None
    if item:
        lines = protocols.email_lines(item, protocol_state)
        return lines[0].rsplit("[", 1)[0].strip(), lines[1:]
    for owner in (triage.YOU_DO, triage.YOU_CONFIRM):
        if grouped[owner]:
            f, _job, t, _tag = grouped[owner][0]
            lines = [t["action"]] + ([t["command"]] if t.get("command") else [])
            if owner == triage.YOU_CONFIRM and t.get("id"):
                lines.append(f"If this was you: jarvis ack {t['id']} --reason \"…\"")
            return f.get("title", ""), lines
    return None


def briefing(pending, result, delta, snapshots, now, store=None, conf=None,
             protocol_state=(), custody=None, part="morning"):
    """-> (subject, text, html) for a scheduled briefing.

    `pending` [(key, queue item)] are the changes held since the last briefing.
    Everything stated is computed here; the model writes only the opener.
    """
    acks = acknowledge.load(store) if store is not None else {}
    current, seen = [], set()
    for f, job in triage.current(snapshots, levels=("critical", "high"), acks=acks, now=now):
        if (job, f.get("title")) not in seen:
            seen.add((job, f.get("title")))
            current.append((f, job, ""))
    grouped_now = _grouped(current)
    counts = _counts(grouped_now)
    need = _needs_you(counts)
    critical = sum(1 for owner in (triage.YOU_DO, triage.YOU_CONFIRM)
                   for f, *_rest in grouped_now[owner] if f.get("severity") == "critical")
    code, reason = condition(need, critical)

    changes = [(item["finding"], item["job"], item["tag"]) for _k, item in pending
               if item["tag"] != "RESOLVED"]
    resolved = [item for _k, item in pending if item["tag"] == "RESOLVED"]
    grouped_changes = _grouped(changes)
    for owner in triage.ORDER:
        for i, (f, job, t, tag) in enumerate(grouped_changes[owner]):
            if tag == "ESCALATED":
                item = next(it for _k, it in pending if it["finding"] is f)
                days = max(1, (now - item["first"]) // 86400)
                grouped_changes[owner][i] = (f, job, t, f"reminder · open {days}d")
    new = sum(1 for _f, _j, tag in changes if tag in ("NEW", "WORSENED", "REOPENED"))
    reminders = sum(1 for _f, _j, tag in changes if tag == "ESCALATED")

    part_title = part.capitalize()
    subject = (f"[JARVIS] {part_title} briefing: "
               + (f"{need} thing{'s' if need != 1 else ''} need{'s' if need == 1 else ''} you"
                  if need else "nothing needs you")
               + (f" · security score {result['score']}%" if result else "")
               + f" · condition {code}")
    facts = voice.facts_for("security briefing", counts, False, result, delta,
                            len(resolved), [f.get("title") for f, _j, _t in current])
    facts["part_of_day"] = part
    if changes:
        facts["new_since_last_briefing"] = new
    line, by_model = voice.opener(conf, facts, time.strftime("%Y-%m-%d", time.localtime(now))
                                  + part, store=store)
    mission = _mission(protocol_state, grouped_now)
    custody_lines = _custody_lines(custody)
    watching = [f.get("title", "") for f, _job, _t, _tag in grouped_now[triage.JARVIS][:5]]
    wins = [f"{i['finding'].get('title', '')} — no longer observed" for i in resolved]
    if delta and delta > 0:
        wins.insert(0, f"Security score up {delta} point{'s' if delta != 1 else ''} in 24h.")

    text = [f"JARVIS {part.upper()} BRIEFING", f"Condition {code}: {reason}", "", line, ""]
    if mission:
        text += [RULE, f"MISSION OF THE DAY: {mission[0]}", RULE,
                 *[f"  {line_}" for line_ in mission[1]], ""]
    if changes or resolved:
        text += [RULE, f"SINCE MY LAST BRIEFING: {new} new, {reminders} reminder(s), "
                       f"{len(resolved)} no longer observed", RULE]
        for owner in triage.ORDER:
            text += _text_group(owner, grouped_changes[owner], limit=10)
    else:
        text += ["Since my last briefing: no changes worth your time."]
    if watching:
        text += ["", "ON WATCH (JARVIS is handling):", *[f"- {w}" for w in watching]]
    if wins:
        text += ["", "WINS:", *[f"- {w}" for w in wins]]
    if custody_lines:
        text += ["", "EVIDENCE CUSTODY:", *[f"- {c}" for c in custody_lines]]
    if result:
        text += [""] + _text_health(result, delta)
    footer = ("Briefings arrive on schedule; between them JARVIS writes only about something "
              "new and critical, or a stop that lasts. Everything it saw and its history: the "
              "local JARVIS dashboard.")
    text += ["", footer]

    tone = ui.CONDITION_STYLE[code][0]
    inner = ui.header(f"JARVIS · {part} briefing",
                      {"RED": "Eyes on this first", "AMBER": "A few things for your hands",
                       "GREEN": "All quiet on the perimeter"}[code],
                      time.strftime("%A %d %B, %H:%M", time.localtime(now)), tone=tone)
    stats = [(need, "for you"), (counts[triage.JARVIS], "on watch")]
    if result:
        stats.insert(0, (f"{result['score']}%", "security score"))
    inner += ui.section(ui.hero(stats), "px-6 pt-5 pb-1")
    inner += ui.condition_banner(code, reason)
    inner += ui.voice(line, by_model)
    if mission:
        inner += ui.mission(mission[0], mission[1])
    if changes or resolved:
        inner += ui.section(ui.heading(
            "Since my last briefing",
            f"{new} new · {reminders} reminder(s) · {len(resolved)} no longer observed"),
            "px-6 pt-5 pb-1")
        for owner in triage.ORDER:
            inner += ui.owner_section(owner, grouped_changes[owner], limit=8, show_detail=False)
    inner += ui.bullets("On watch", "JARVIS is handling these; nothing needed from you.", watching)
    inner += ui.bullets("Wins", "", wins)
    inner += ui.bullets("Evidence custody", "The state of JARVIS's own records.", custody_lines)
    if result:
        inner += ui.section(ui.health_panel(result, delta), "px-6 py-5 bg-slate-50")
    inner += ui.footer(footer)
    return subject, "\n".join(text) + "\n", ui.document(subject, line, inner)


# ── daily security health ─────────────────────────────────────────────────

def health(result, delta, snapshots, now, store=None, conf=None, protocol_state=()):
    """-> (subject, text, html) for the once-a-day health email.

    `protocol_state` is protocols.evaluate(): today's protocol is carried in
    full, steps included, because mail is where you read it."""
    # The daily email is a to-do list, not an inventory: critical and high only,
    # one entry per distinct finding. Mediums are counted, not listed.
    acks = acknowledge.load(store) if store is not None else {}
    seen, top = set(), []
    for f, job in triage.current(snapshots, levels=("critical", "high"), acks=acks, now=now):
        key = (job, f.get("title"))
        if key not in seen:
            seen.add(key)
            top.append((f, job, ""))
    lower = len(triage.current(snapshots, levels=("medium",), acks=acks, now=now))
    grouped = _grouped(top)
    counts = _counts(grouped)
    need = _needs_you(counts)
    trend = "" if not delta else f" ({'+' if delta > 0 else ''}{delta})"
    subject = (f"[JARVIS] security health {result['score']}% — {result['grade']}{trend} · "
               f"{need} need you")
    line, by_model = voice.opener(conf, voice.facts_for(
        "daily security health", counts, False, result, delta,
        top=[f.get("title") for f, _job, _tag in top]),
        time.strftime("%Y-%m-%d", time.localtime(now)), store=store)

    text = ["JARVIS SECURITY HEALTH",
            f"{need} need you · {counts[triage.JARVIS]} handled by JARVIS",
            ("All quiet — nothing needs you. Splendid." if not need else
             f"{need} need you — start at the top."), "", line, ""]
    text += _text_health(result, delta)
    for owner in triage.ORDER:
        text += _text_group(owner, grouped[owner], limit=10)
    briefing = protocols.pick_next(protocol_state)
    brief_lines = protocols.email_lines(briefing, protocol_state) if briefing else []
    # One plan paragraph, computed once and used in both the text and HTML
    # bodies — a second call would be a second model invocation.
    plan, plan_by_model = voice.plan_note(conf, briefing, result) if briefing else ("", False)
    if brief_lines:
        text += ["", RULE, "TODAY'S PROTOCOL", RULE]
        text += [(f"[local model] {plan}" if plan_by_model else plan), "", *brief_lines]
    text += ["", f"Plus {lower} medium-severity items on the dashboard.",
             "Everything it saw and its history: the local JARVIS dashboard."]

    inner = ui.header("JARVIS · daily security health",
                      f"Your system is {result['score']}% of the way to secure",
                      time.strftime("%A %d %B", time.localtime(now)), tone="health")
    inner += ui.section(ui.hero([(f"{result['score']}%", "security score"),
                                 (f"{result.get('coverage', '?')}%", "coverage"),
                                 (need, "need you")]), "px-6 pt-5 pb-1")
    inner += ui.voice(line, by_model)
    inner += ui.section(ui.health_panel(result, delta))
    inner += ui.section(ui.owner_summary(counts, result.get("acknowledged", 0)), "px-5 pt-1 pb-1")
    for owner in triage.ORDER:
        inner += ui.owner_section(owner, grouped[owner], limit=8, show_detail=False)
    if brief_lines:
        inner += ui.briefing(
            [f"Where to work first — {result['score']}% today", plan, *brief_lines],
            model_note=plan_by_model)
    if lower:
        inner += ui.section(f'<div {ui.tw("text-sm text-slate-500")}>Plus {lower} medium-severity '
                            f'items, listed on the dashboard rather than here.</div>', "px-6 pb-5")
    inner += ui.footer("Fixing items under “Needs you — action” raises the score the most. "
                       "Everything it saw and its history: the local JARVIS dashboard. "
                       "Set health_email_enabled to false to stop this email.")
    return subject, "\n".join(text) + "\n", ui.document(subject, line, inner)


def health_email(store, conf, now=None, jobs=None):
    """Send the daily health email. Returns an error string, or "" on success."""
    result = score.latest(store)
    if result is None:
        return "no security score recorded yet"
    now = int(time.time() if now is None else now)
    state = protocols.evaluate(store, jobs, now) if jobs else ()
    subject, text, html = health(result, score.change_since(store, 86400, now),
                                 store.get_snapshots(), now, store, conf, state)
    return alert.send_email(conf, subject, text, html=html)


# ── the action plan: everything that needs your hands ─────────────────────

def action_plan(result, protocol_state, snapshots, now, store=None, conf=None, delta=None):
    """-> (subject, text, html, personalized) for the on-request action plan email.

    Every open protocol in the order it has to happen, each with its full
    hand-written steps, then the other critical and high findings only you can
    act on. The local model writes the opening note and one line per task on
    why it matters; each is checked before use, and the steps are never its.
    `personalized` counts the lines the model wrote that passed.
    """
    tasks = [i for i in protocol_state
             if i["state"] in (protocols.READY, protocols.WAITING, protocols.BLOCKED)]
    acks = acknowledge.load(store) if store is not None else {}
    others, seen = [], set()
    for f, job in triage.current(snapshots, levels=("critical", "high"), acks=acks, now=now):
        if (job, f.get("title")) in seen or any(i["protocol"].fixes(job, f) for i in tasks):
            continue
        seen.add((job, f.get("title")))
        others.append((f, job, ""))
    others = _grouped(others)[triage.YOU_DO]

    total = len(tasks) + len(others)
    subject = (f"[JARVIS] your action plan — {total} thing{'s' if total != 1 else ''} "
               f"need{'s' if total == 1 else ''} your hands")
    day = time.strftime("%Y-%m-%d", time.localtime(now))
    line, by_model = voice.opener(conf, voice.facts_for(
        "action plan", {triage.YOU_DO: total}, False, result, delta,
        top=[i["protocol"].title for i in tasks]), day, store=store)
    personalized = int(by_model)

    text = ["JARVIS ACTION PLAN", f"{len(tasks)} protocol(s) in order, then "
            f"{len(others)} other matter(s) for your hands", "", line, ""]
    inner = ui.header("JARVIS · action plan", "What needs your hands, in order",
                      time.strftime("%A %d %B", time.localtime(now)), tone="plan")
    inner += ui.section(ui.hero([(total, "things need your hands")]), "px-6 pt-5 pb-1")
    inner += ui.voice(line, by_model)

    for n, item in enumerate(tasks, 1):
        note, note_by_model = voice.task_note(conf, item)
        personalized += int(note_by_model)
        lines = protocols.email_lines(item)
        lines[0] = f"Task {n} · {lines[0]}"
        lines[1] = note
        text += [RULE, lines[0], (f"[local model] {note}" if note_by_model else note),
                 *lines[2:], ""]
        inner += ui.briefing(lines, model_note=note_by_model)

    if others:
        text += _text_group(triage.YOU_DO, others, limit=15)
        inner += ui.owner_section(triage.YOU_DO, others, limit=15)

    footer = ("The steps are written by hand; only the italic notes marked \u201clocal model\u201d "
              "come from the model. After each task, run jarvis brief check <task> — a task counts as done "
              "only when a fresh scan agrees.")
    text += ["", footer]
    inner += ui.footer(footer)
    return subject, "\n".join(text) + "\n", ui.document(subject, line, inner), personalized


def action_plan_email(store, conf, jobs, now=None):
    """Build and send the action plan. -> (error or "", subject, personalized lines)."""
    now = int(time.time() if now is None else now)
    result = score.latest(store) or score.compute(store.get_snapshots(), jobs, now,
                                                  acknowledge.load(store))
    subject, text, html, personalized = action_plan(
        result, protocols.evaluate(store, jobs, now), store.get_snapshots(), now, store, conf,
        score.change_since(store, 86400, now))
    return alert.send_email(conf, subject, text, html=html), subject, personalized
