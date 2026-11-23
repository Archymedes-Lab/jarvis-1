"""Email HTML built from Tailwind utility classes, compiled to inline styles.

Mail clients strip <style> blocks, ignore external stylesheets and never run
scripts, so a Tailwind stylesheet cannot be linked into an email. What survives
everywhere is a `style` attribute on each element and table-based layout. This
module keeps the authoring side Tailwind — `tw("rounded-xl bg-white p-6")` —
and resolves each class to its CSS at render time, so templates read like the
dashboard and render in Gmail, Outlook and Apple Mail alike. An unknown class
raises, so a typo fails a test instead of silently losing a style.
"""

import html as html_mod

from .triage import BLURB, LABEL, ORDER

# Tailwind v3 palette, the shades the templates use.
COLORS = {
    "white": "#ffffff", "black": "#000000", "transparent": "transparent",
    "slate-50": "#f8fafc", "slate-100": "#f1f5f9", "slate-200": "#e2e8f0",
    "slate-300": "#cbd5e1", "slate-400": "#94a3b8", "slate-500": "#64748b",
    "slate-600": "#475569", "slate-700": "#334155", "slate-800": "#1e293b",
    "slate-900": "#0f172a", "slate-950": "#020617",
    "red-50": "#fef2f2", "red-100": "#fee2e2", "red-200": "#fecaca", "red-500": "#ef4444",
    "red-600": "#dc2626", "red-700": "#b91c1c",
    "orange-50": "#fff7ed", "orange-100": "#ffedd5", "orange-200": "#fed7aa",
    "orange-500": "#f97316", "orange-600": "#ea580c", "orange-700": "#c2410c",
    "amber-50": "#fffbeb", "amber-100": "#fef3c7", "amber-200": "#fde68a",
    "amber-500": "#f59e0b", "amber-600": "#d97706", "amber-700": "#b45309",
    "emerald-50": "#ecfdf5", "emerald-100": "#d1fae5", "emerald-200": "#a7f3d0",
    "emerald-500": "#10b981", "emerald-600": "#059669", "emerald-700": "#047857",
    "sky-50": "#f0f9ff", "sky-100": "#e0f2fe", "sky-200": "#bae6fd", "sky-500": "#0ea5e9",
    "sky-600": "#0284c7", "sky-700": "#0369a1",
    "violet-50": "#f5f3ff", "violet-100": "#ede9fe", "violet-200": "#ddd6fe",
    "violet-600": "#7c3aed", "violet-700": "#6d28d9",
    "indigo-500": "#6366f1", "indigo-600": "#4f46e5",
}
SPACE = {"0": "0", "0.5": "2px", "1": "4px", "1.5": "6px", "2": "8px", "2.5": "10px",
         "3": "12px", "4": "16px", "5": "20px", "6": "24px", "8": "32px", "10": "40px"}
TEXT = {"xs": ("12px", "16px"), "sm": ("14px", "20px"), "base": ("16px", "24px"),
        "lg": ("18px", "28px"), "xl": ("20px", "28px"), "2xl": ("24px", "32px"),
        "3xl": ("30px", "36px"), "4xl": ("36px", "40px"), "5xl": ("48px", "1")}
STATIC = {
    "font-normal": "font-weight:400", "font-medium": "font-weight:500",
    "font-semibold": "font-weight:600", "font-bold": "font-weight:700",
    "font-extrabold": "font-weight:800",
    "font-mono": "font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace",
    "font-sans": "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif",
    "uppercase": "text-transform:uppercase", "tracking-wide": "letter-spacing:0.025em",
    "tracking-wider": "letter-spacing:0.05em", "tracking-widest": "letter-spacing:0.1em",
    "leading-tight": "line-height:1.25", "leading-snug": "line-height:1.375",
    "leading-relaxed": "line-height:1.625",
    "text-left": "text-align:left", "text-center": "text-align:center", "text-right": "text-align:right",
    "block": "display:block", "inline-block": "display:inline-block",
    "w-full": "width:100%", "max-w-2xl": "max-width:672px",
    "rounded": "border-radius:4px", "rounded-md": "border-radius:6px",
    "rounded-lg": "border-radius:8px", "rounded-xl": "border-radius:12px",
    "rounded-2xl": "border-radius:16px", "rounded-full": "border-radius:9999px",
    "border": "border-width:1px;border-style:solid", "border-0": "border:0",
    "border-l-4": "border-left-width:4px;border-left-style:solid",
    "whitespace-nowrap": "white-space:nowrap", "break-all": "word-break:break-all",
    "break-words": "word-break:break-word", "overflow-hidden": "overflow:hidden",
    "align-top": "vertical-align:top", "align-middle": "vertical-align:middle",
    "no-underline": "text-decoration:none",
}
_SIDES = {"p": ("padding",), "px": ("padding-left", "padding-right"),
          "py": ("padding-top", "padding-bottom"), "pt": ("padding-top",),
          "pb": ("padding-bottom",), "pl": ("padding-left",), "pr": ("padding-right",),
          "m": ("margin",), "mt": ("margin-top",), "mb": ("margin-bottom",),
          "mx": ("margin-left", "margin-right"), "my": ("margin-top", "margin-bottom")}


def _one(cls):
    if cls in STATIC:
        return STATIC[cls]
    if cls.startswith("text-") and cls[5:] in TEXT:
        size, line = TEXT[cls[5:]]
        return f"font-size:{size};line-height:{line}"
    for prefix, prop in (("text-", "color"), ("bg-", "background-color"),
                         ("border-l-", "border-left-color"), ("border-", "border-color")):
        if cls.startswith(prefix) and cls[len(prefix):] in COLORS:
            return f"{prop}:{COLORS[cls[len(prefix):]]}"
    head, _, value = cls.partition("-")
    if head in _SIDES and value in SPACE:
        return ";".join(f"{p}:{SPACE[value]}" for p in _SIDES[head])
    raise ValueError(f"unsupported utility class: {cls}")


def tw(classes, extra=""):
    """style="..." attribute for a space-separated list of utility classes."""
    css = ";".join(_one(c) for c in classes.split())
    if extra:
        css = f"{css};{extra}" if css else extra
    return f'style="{html_mod.escape(css, quote=True)}"'


def esc(value):
    return html_mod.escape(str(value if value is not None else ""))


# ── components ────────────────────────────────────────────────────────────

SEVERITY_STYLE = {
    "critical": ("bg-red-600", "text-white"),
    "high": ("bg-orange-600", "text-white"),
    "medium": ("bg-amber-500", "text-slate-900"),
    "low": ("bg-slate-400", "text-white"),
    "ok": ("bg-emerald-600", "text-white"),
}

OWNER_STYLE = {
    "you_do": {"accent": "border-l-red-600", "tint": "bg-red-50", "pill": "bg-red-600 text-white",
               "icon": "&#9888;"},
    "you_confirm": {"accent": "border-l-amber-500", "tint": "bg-amber-50",
                    "pill": "bg-amber-500 text-slate-900", "icon": "&#63;"},
    "jarvis": {"accent": "border-l-emerald-600", "tint": "bg-emerald-50",
               "pill": "bg-emerald-600 text-white", "icon": "&#10003;"},
}


def score_color(score):
    if score is None:
        return "slate-400"
    return "emerald-600" if score >= 75 else "amber-500" if score >= 50 else "red-600"


def pill(text, classes):
    return (f'<span {tw("inline-block rounded-full px-2 py-0.5 text-xs font-bold uppercase tracking-wide " + classes)}>'
            f"{esc(text)}</span>")


def severity_pill(severity):
    bg, fg = SEVERITY_STYLE.get(severity, SEVERITY_STYLE["low"])
    return pill(severity or "?", f"{bg} {fg}")


def meter(score, height=10, track="slate-200"):
    pct = 0 if score is None else max(0, min(100, int(score)))
    colour = COLORS[score_color(score)]
    # Two-cell table: the filled share and the rest. Width percentages on table
    # cells are the one progress-bar construction Outlook renders.
    filled = (f'<td width="{pct}%" style="background-color:{colour};height:{height}px;'
              f'font-size:0;line-height:0">&nbsp;</td>') if pct else ""
    rest = (f'<td width="{100 - pct}%" style="background-color:{COLORS[track]};height:{height}px;'
            f'font-size:0;line-height:0">&nbsp;</td>') if pct < 100 else ""
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            f'style="border-collapse:separate;border-radius:9999px;overflow:hidden">'
            f"<tr>{filled}{rest}</tr></table>")


def document(title, preheader, inner):
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{esc(title)}</title></head>"
        f'<body {tw("bg-slate-100 m-0 p-0 font-sans")}>'
        # Preheader: the grey preview line inboxes show next to the subject.
        f'<div style="display:none;max-height:0;overflow:hidden;opacity:0">{esc(preheader)}</div>'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" {tw("bg-slate-100")}>'
        f'<tr><td align="center" {tw("px-2 py-6")}>'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'{tw("max-w-2xl bg-white rounded-2xl overflow-hidden", "max-width:640px")}>'
        f"{inner}</table></td></tr></table></body></html>")


# Header tones: the hero answers "how worried should I be?" before a word
# is read. Urgent mail arrives red, calm mail emerald, digests indigo,
# health violet, everything else the familiar slate.
TONES = {
    "slate": "bg-slate-900",
    "urgent": "bg-red-700",
    "calm": "bg-emerald-700",
    "digest": "bg-indigo-600",
    "health": "bg-violet-700",
    "plan": "bg-sky-600",
    "amber": "bg-amber-600",
}

# The briefing's condition code, chosen by deterministic rules in emails.py.
CONDITION_STYLE = {
    "GREEN": ("calm", "bg-emerald-100 text-emerald-700"),
    "AMBER": ("amber", "bg-amber-100 text-amber-700"),
    "RED": ("urgent", "bg-red-100 text-red-700"),
}


def condition_banner(code, reason):
    _tone, pill_classes = CONDITION_STYLE[code]
    return section(
        f'<div>{pill(f"Condition {code}", pill_classes)}</div>'
        f'<div {tw("text-sm text-slate-600 mt-2")}>{esc(reason)}</div>', "px-6 pt-5 pb-1")


def mission(title, lines):
    """Today's one thing: the single most valuable action, commands in mono."""
    body = "".join(
        f'<div {tw(_BRIEF_MONO if _is_command(line) else "text-sm text-slate-700 mt-2 leading-relaxed")}>'
        f"{esc(line.strip())}</div>" for line in lines if line.strip())
    return section(
        f'<div {tw("rounded-xl border-l-4 border-l-sky-500 bg-sky-50 px-4 py-3")}>'
        + heading("Mission of the day", title) + body + "</div>")


def bullets(title, sub, rows):
    """A short headed list of plain-text rows."""
    if not rows:
        return ""
    items = "".join(f'<div {tw("text-sm text-slate-700 py-1")}>&#8226; {esc(r)}</div>' for r in rows)
    return section(heading(title, sub) + f'<div {tw("mt-2")}>{items}</div>')


def header(kicker, title, subtitle="", tone="slate"):
    bg = TONES.get(tone, TONES["slate"])
    return (f'<tr><td {tw(f"{bg} px-6 pt-6 pb-5")}>'
            f'<div {tw("text-xs font-semibold uppercase tracking-widest text-sky-200")}>{esc(kicker)}</div>'
            f'<div {tw("text-2xl font-bold text-white mt-1 leading-tight")}>{esc(title)}</div>'
            + (f'<div {tw("text-sm text-slate-300 mt-2")}>{esc(subtitle)}</div>' if subtitle else "")
            + "</td></tr>")


def hero(stats):
    """One glanceable stat strip: [(value, label)] in big friendly numerals."""
    cells = "".join(
        f'<td width="{100 // max(1, len(stats))}%" {tw("align-top px-2")}>'
        f'<div {tw("text-4xl font-extrabold text-slate-900 leading-tight")}>{esc(value)}</div>'
        f'<div {tw("text-xs font-semibold uppercase tracking-wider text-slate-500")}>{esc(label)}</div></td>'
        for value, label in stats)
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
            f"{cells}</tr></table>")


def story_card(chain):
    """One correlated narrative: headline, size, and causal honesty."""
    note = ("one of these led directly to the next"
            if chain.get("causal") else
            "grouped by computer and subject; not proven to be connected")
    over = (f" · +{chain['member_overflow']} more on the dashboard"
            if chain.get("member_overflow") else "")
    jobs = ", ".join(str(j) for j in (chain.get("jobs") or [])[:4])
    return (
        f'<div {tw("rounded-xl border border-slate-200 bg-white p-4 mt-3 border-l-4 border-l-violet-600")}>'
        f'<div {tw("text-base font-semibold text-slate-900 leading-snug")}>'
        f"&#9670; {esc(chain.get('headline', ''))}</div>"
        f'<div {tw("text-sm text-slate-600 mt-1")}>{chain.get("count", 0)} '
        f'event{"s" if chain.get("count", 0) != 1 else ""}'
        f"{(' · ' + esc(jobs)) if jobs else ''}{esc(over)}</div>"
        f'<div {tw("text-xs text-slate-400 mt-1")}>{esc(note)}</div></div>')


def voice(line, by_model=False):
    """JARVIS's opening note, set apart from the report it introduces."""
    credit = "written by the local model · the report below is not" if by_model else "JARVIS"
    return section(
        f'<div {tw("border-l-4 border-l-sky-500 bg-sky-50 rounded-lg px-4 py-3")}>'
        f'<div {tw("text-base text-slate-800 leading-relaxed", "font-style:italic")}>{esc(line)}</div>'
        f'<div {tw("text-xs text-slate-500 mt-1")}>— {esc(credit)}</div></div>',
        "px-6 pt-5 pb-1")


def plain_leads(items, limit=5):
    """The plain-words part at the top of an alert: for each item, what it is and
    what to do, then exactly what was seen. items: [(finding, job, tag)]."""
    from jarvis.response import plainalert
    if not items:
        return ""
    cards = []
    for f, job, tag in items[:limit]:
        sentence, *facts = plainalert.lead(f, job, tag)
        cards.append(
            f'<div {tw("rounded-xl border border-slate-200 bg-white p-4 mt-3")}>'
            f'<div {tw("text-base text-slate-900 leading-relaxed")}>{esc(sentence)}</div>'
            + "".join(f'<div {tw("text-sm text-slate-600 mt-1 break-words")}>{esc(x)}</div>' for x in facts)
            + "</div>")
    more = (f'<div {tw("text-sm text-slate-500 mt-3")}>+ {len(items) - limit} more in the details below</div>'
            if len(items) > limit else "")
    return section(heading("What happened") + "".join(cards) + more, "px-6 pt-5 pb-1")


def section(inner, classes="px-6 py-5"):
    return f'<tr><td {tw(classes)}>{inner}</td></tr>'


def heading(text, sub=""):
    return (f'<div {tw("text-xs font-bold uppercase tracking-wider text-slate-500")}>{esc(text)}</div>'
            + (f'<div {tw("text-sm text-slate-500 mt-1")}>{esc(sub)}</div>' if sub else ""))


def health_panel(result, delta=None):
    score = result["score"]
    colour = score_color(score)
    trend = "" if delta is None else (
        f"{'+' if delta > 0 else ''}{delta} in 24h" if delta else "no change in 24h")
    rows = []
    for a in result["areas"]:
        label = "unverified" if a["score"] is None else f"{a['score']}%"
        opened = " · ".join(f"{n} {s}" for s, n in sorted(
            (a.get("open") or {}).items(),
            key=lambda kv: ("critical", "high", "medium", "low").index(kv[0])
            if kv[0] in ("critical", "high", "medium", "low") else 9) if s != "low")
        rows.append(
            f'<tr><td {tw("py-1.5 pr-3 text-sm text-slate-700 whitespace-nowrap align-middle")}>{esc(a["name"])}</td>'
            f'<td width="55%" {tw("py-1.5 align-middle")}>{meter(a["score"], 8)}</td>'
            f'<td {tw("py-1.5 pl-3 text-sm font-semibold text-slate-900 text-right whitespace-nowrap align-middle")}>{esc(label)}</td></tr>'
            + (f'<tr><td></td><td colspan="2" {tw("pb-1 text-xs text-slate-500")}>{esc(opened)}</td></tr>' if opened else ""))
    return (
        heading("Security health")
        + f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" {tw("mt-2")}><tr>'
        f'<td {tw("align-middle whitespace-nowrap pr-4")}>'
        f'<span {tw("text-5xl font-extrabold text-" + colour)}>{score}%</span></td>'
        f'<td {tw("align-middle")}>'
        + pill(result["grade"], f"bg-{colour} " + ("text-slate-900" if colour == "amber-500" else "text-white"))
        + f'<div {tw("text-sm text-slate-500 mt-1")}>monitoring coverage {result["coverage"]}%'
        + (f" · {esc(trend)}" if trend else "") + "</div></td></tr></table>"
        + f'<div {tw("mt-3")}>{meter(score, 14)}</div>'
        + f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" {tw("mt-4")}>{"".join(rows)}</table>')


def owner_summary(counts, confirmed=0):
    """Three stat tiles: action / confirm / handled, and a confirmed-by-you note."""
    cells = []
    for owner in ORDER:
        style = OWNER_STYLE[owner]
        cells.append(
            f'<td width="33%" {tw("align-top px-1")}>'
            f'<div {tw("rounded-xl p-3 border-l-4 " + style["accent"] + " " + style["tint"])}>'
            f'<div {tw("text-2xl font-bold text-slate-900")}>{counts.get(owner, 0)}</div>'
            f'<div {tw("text-xs font-semibold text-slate-600")}>{esc(LABEL[owner])}</div></div></td>')
    note = (f'<div {tw("text-xs text-slate-500 mt-2 px-1")}>{confirmed} item(s) you confirmed '
            f'as expected are not counted. List them with jarvis ack list.</div>') if confirmed else ""
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
            f'<tr>{"".join(cells)}</tr></table>{note}')


def forensics_block(lines):
    """A finding's forensic reconstruction, in full.

    Never truncated and shown even where detail is suppressed: an alert about
    injected input is only answerable with the exact key, target and suspects
    in front of you, and the email is where that question gets asked."""
    if not lines:
        return ""
    rows = "".join(
        f'<div {tw("font-mono text-xs text-slate-800 leading-snug break-words", "white-space:pre-wrap")}>'
        f"{esc(line)}</div>" for line in lines)
    return (f'<div {tw("rounded-lg border border-slate-200 bg-slate-50 p-3 mt-3")}>'
            f'<div {tw("text-xs font-semibold text-slate-600 mb-1")}>What happened, step by step</div>'
            f"{rows}</div>")


def finding_card(finding, job, triage_result, tag="", detail_limit=240, show_detail=True):
    f = finding or {}
    style = OWNER_STYLE[triage_result["owner"]]
    command = triage_result.get("command") or ""
    detail = (f.get("detail") or "")
    if len(detail) > detail_limit:
        detail = detail[:detail_limit].rstrip() + "…"
    meta = " · ".join(x for x in (job, f.get("host"), f.get("where")) if x)
    return (
        f'<div {tw("rounded-xl border border-slate-200 bg-white p-4 mt-3 border-l-4 " + style["accent"])}>'
        f'<div>{severity_pill(f.get("severity"))}'
        + (f' {pill(tag, "bg-slate-100 text-slate-600")}' if tag else "") + "</div>"
        f'<div {tw("text-base font-semibold text-slate-900 mt-2 leading-snug")}>{esc(f.get("title"))}</div>'
        + (f'<div {tw("text-sm text-slate-600 mt-1 leading-relaxed break-words")}>{esc(detail)}</div>'
           if show_detail and detail else "")
        + (f'<div {tw("text-xs text-slate-400 mt-1 break-all")}>{esc(meta)}</div>' if meta else "")
        + forensics_block(f.get("forensics"))
        + f'<div {tw("rounded-lg p-3 mt-3 " + style["tint"])}>'
        f'<div {tw("text-sm text-slate-800 leading-snug")}><b>{style["icon"]}</b> {esc(triage_result["action"])}</div>'
        + (f'<div {tw("font-mono text-xs text-slate-900 bg-white border border-slate-200 rounded-md px-2 py-1.5 mt-2 break-all")}>'
           f"{esc(command)}</div>" if command else "")
        + (f'<div {tw("text-xs text-slate-600 mt-2")}>If this was you, confirm it so it stops counting against the score:</div>'
           f'<div {tw("font-mono text-xs text-slate-900 bg-white border border-slate-200 rounded-md px-2 py-1.5 mt-1 break-all")}>'
           f'jarvis ack {esc(triage_result["id"])} --reason "…"</div>'
           if triage_result["owner"] == "you_confirm" and triage_result.get("id") else "")
        + "</div></div>")


def owner_section(owner, items, limit=12, show_detail=True):
    """items: [(finding, job, triage, tag)]"""
    if not items:
        return ""
    style = OWNER_STYLE[owner]
    cards = "".join(finding_card(f, job, t, tag, show_detail=show_detail)
                    for f, job, t, tag in items[:limit])
    more = (f'<div {tw("text-sm text-slate-500 mt-3")}>+ {len(items) - limit} more on the dashboard</div>'
            if len(items) > limit else "")
    return section(
        f'<div>{pill(f"{LABEL[owner]} · {len(items)}", style["pill"])}</div>'
        f'<div {tw("text-sm text-slate-600 mt-2")}>{esc(BLURB[owner])}</div>'
        + cards + more)


_BRIEF_MONO = "text-sm text-slate-800 font-mono mt-2 break-words"


def _is_command(line):
    stripped = line.strip()
    return (stripped.startswith(("jarvis ", "manage-bde", "$ "))
            or " | " in stripped and stripped.startswith("jarvis"))


def briefing(lines, model_note=False):
    """A protocol briefing: its rendered lines, commands in mono.

    With `model_note`, the second line was written by the local model and is set
    apart in italics with a credit, so a reader can always tell it from the
    hand-written steps."""
    title = lines[0].rsplit("[", 1)[0].strip()

    def row(index, line):
        if model_note and index == 1:
            return (f'<div {tw("text-sm text-slate-700 mt-2 leading-relaxed", "font-style:italic")}>'
                    f'{esc(line.strip())} <span {tw("text-xs text-slate-500")}>— local model</span></div>')
        style = _BRIEF_MONO if _is_command(line) else "text-sm text-slate-700 mt-2 leading-relaxed"
        return f'<div {tw(style)}>{esc(line.strip())}</div>'

    body = "".join(row(i, line) for i, line in enumerate(lines) if i)
    return section(
        f'<div {tw("rounded-xl border-l-4 border-l-violet-600 bg-violet-50 px-4 py-3")}>'
        + heading("JARVIS briefing", title) + body + "</div>")


def footer(text):
    return (f'<tr><td {tw("bg-slate-50 px-6 py-4 border-0")}>'
            f'<div {tw("text-xs text-slate-500 leading-relaxed")}>{esc(text)}</div></td></tr>')
