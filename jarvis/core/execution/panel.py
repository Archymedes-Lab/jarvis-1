"""Visibility panel: one process, every view, no verdict inflation.

Renders the PROCESS panel from the design: identity, per-view checks,
execution, CLR, network, memory, visibility confidence, security state.
Observations are factual (check/cross/question); interpretation is one
line at the end. Pure text, no IO.
"""

OK, MISSING, UNKNOWN = "\u2713", "\u2715", "?"


def render(*, pid="", image="", identity=None, views=None, execution=None,
           clr=None, network="", memory="", confidence=None,
           state="NORMAL"):
    views = views or {}
    execution = execution or {}
    clr = clr or {}
    lines = [f"PROCESS {pid} {image}".rstrip()]
    lines.append("")
    lines.append("IDENTITY")
    for k, v in (identity or {}).items():
        lines.append(f"{k} {v}")
    lines.append("")
    lines.append("VISIBILITY")
    for name in ("kernel creation", "etw creation", "sysmon event 1",
                 "current snapshot", "thread inventory", "image map"):
        mark = {True: OK, False: MISSING}.get(views.get(name), UNKNOWN)
        lines.append(f"{name:<20} {mark}")
    lines.append("")
    lines.append("EXECUTION")
    for k, v in execution.items():
        lines.append(f"{k:<20} {v}")
    if clr:
        lines.append("")
        lines.append("CLR")
        for k, v in clr.items():
            lines.append(f"{k:<20} {v}")
    lines.append("")
    lines.append("NETWORK")
    lines.append(network or "none observed")
    lines.append("")
    lines.append("MEMORY")
    lines.append(memory or "none observed")
    lines.append("")
    lines.append(f"VISIBILITY CONFIDENCE  "
                 f"{('%.0f%%' % (100 * confidence)) if confidence is not None else 'unknown'}")
    lines.append(f"SECURITY STATE         {state}")
    return "\n".join(lines)
