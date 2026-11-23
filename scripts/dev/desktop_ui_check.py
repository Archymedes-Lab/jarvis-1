"""Browser check of the desktop interface: every view, both detail levels, both themes,
the status banner a Windows install shows, languages, and partial daemon answers.

    (cd desktop/ui && bun run build)
    uv run --with playwright==1.55.0 python3 scripts/dev/desktop_ui_check.py [--shots DIR]

Serves desktop/ui/dist on 127.0.0.1:8796 and runs it inside a fake app shell
(window.__TAURI_INTERNALS__) that answers every command with made-up data and
records each call, so actions can be checked. Nothing here talks to a daemon or
holds data from a real machine. Uses Playwright's Linux chromium-headless-shell
(Windows policy blocks headless Chrome/Edge on the owner's machine).

Passes:
  views     every sidebar view x Simple/Expert x light/dark: renders, no script
            error, no sideways scroll
  partial   every daemon read answers {} (then wrong types): each view still
            renders without a script error (2026-11-09: World crashed on this)
  banner    the native Windows edition's blind list (administrator sensor,
            stale, failed): grouped, every name listed, actions call the shell
  phases    stopped / not installed / not authorised / live
  browser   "Open in your browser" from Ctrl K, Settings and the full-view buttons
  i18n      the banner headline and labels in fr, de, ja and ar (right-to-left);
            2026-11-09: counted headlines were left in English
Exit status 0 only when every check passes.
"""
import argparse
import asyncio
import functools
import http.server
import json
import sys
import threading
from pathlib import Path

DIST = Path(__file__).resolve().parents[2] / "desktop" / "ui" / "dist"
PORT = 8796
BASE = f"http://127.0.0.1:{PORT}/"

ADMIN = ["Native sensor ingestion", "Windows security posture", "Sysmon telemetry", "Memory & instruction level"]
STALE = ["Spyware & capabilities", "Brute force & auth failures"]
FAILED = ["Audio endpoints & routes", "Pre-OS boot integrity"]
BLIND = ([{"job": f"a{i}", "label": n, "reason": "Needs administrator sensor", "kind": "admin_sensor"} for i, n in enumerate(ADMIN)]
         + [{"job": f"s{i}", "label": n, "reason": "it has not reported recently", "kind": "stale"} for i, n in enumerate(STALE)]
         + [{"job": f"f{i}", "label": n, "reason": "it failed the last time it ran", "kind": "failed"} for i, n in enumerate(FAILED)])
N = len(BLIND)
STATUS = {
    "degraded": {"phase": "degraded", "message": f"ARGUS-INSTINCT is running, but {N} of its checks are not working",
                 "detail": "", "blind": BLIND},
    "edition": {"phase": "degraded", "message": f"ARGUS-INSTINCT can't fully check {len(ADMIN)} parts of your computer right now",
                "detail": "", "blind": BLIND[:len(ADMIN)]},
    "live": {"phase": "live", "message": "ARGUS-INSTINCT is watching your computer", "detail": ""},
    "stopped": {"phase": "stopped", "message": "ARGUS-INSTINCT is not running and could not be started", "detail": "The sign-in task did not start it."},
    "not_installed": {"phase": "not_installed", "message": "The part of ARGUS-INSTINCT that checks your computer is not installed",
                      "detail": "Run ARGUS-INSTINCT Setup again."},
    "not_authorised": {"phase": "not_authorised", "message": "This app is not allowed to talk to ARGUS-INSTINCT yet",
                       "detail": "ARGUS-INSTINCT is not paired with this app."},
}

NOW = 1794000000
JOBS = [{"name": f"j{i}", "label": n, "interval": 300, "ts": NOW - 60, "duration": 1.2, "error": "x" if n in FAILED else "",
         "counts": {"low": 1}, "ok": 0, "stale": n in STALE, "freshness": "STALE" if n in STALE else "FRESH",
         "running": False, "next": 30} for i, n in enumerate(ADMIN + STALE + FAILED + ["Processes & network", "Startup programs"])]
FINDINGS = [{"category": c, "severity": s, "title": t, "detail": d, "where": w, "host": "win", "job": "control", "id": f"f{i}"}
            for i, (c, s, t, d, w) in enumerate([
                ("persistence", "critical", "WMI event subscription", "__EventFilter -> ActiveScriptEventConsumer", "root\\subscription"),
                ("persistence", "high", "scheduled task", "Example updater -> C:\\Program Files\\Example\\update.exe", "\\Example updater"),
                ("network", "medium", "inbound firewall allow rule", "Example app", "Windows Firewall"),
                ("visibility", "low", "collector reported stale data", "Spyware & capabilities", "control")])]
STATE = {"now": NOW, "worst": "critical", "totals": {"critical": 1, "high": 1, "medium": 1, "low": 1},
         "by_host": {"win": 4}, "by_category": {"persistence": 2}, "jobs": JOBS, "findings": FINDINGS, "findings_total": 4,
         "checks": [], "history": [], "internet": {}, "peers": [], "events": [], "stats": {}, "intel": {}, "questions": [],
         "security": {"score": 61, "grade": "D", "state": "measured", "coverage": 66, "acknowledged": 0, "at": NOW,
                      "areas": [{"name": "Persistence & access", "score": 40}], "next_steps": [], "history": [[NOW - 3600, 58], [NOW, 61]]},
         "posture": {}, "attack": {}, "reliability": {}, "detector_health": {}, "assistant": {}, "paused_until": 0,
         "performance": {}, "continuity": {}, "fix": []}
GOOD = {
    "daemon_state": STATE,
    "coverage_state": {"at": NOW, "totals": {"validated": 5, "claimed": 40, "blind": 10, "regressed": 1, "total": 56},
                       "tactics": {}, "techniques": [{"tid": "T1053", "name": "Scheduled Task/Job", "tactics": ["persistence"], "level": "claimed"}],
                       "uptime": {"pct24": 46, "buckets": [1, 0, 1], "tracked": 10, "of": 12}},
    "geo_state": {"zones": [{"name": "Home"}], "devices": [{"name": "This PC", "kind": "pc", "trust": "trusted", "located": False}],
                  "anomalies": [], "generated_at": NOW},
    "world_state": {"generated_at": NOW, "age_s": 60, "stale": False, "window_s": 86400, "items": [], "zones": [],
                    "counts": {"reports": 0, "mapped": 0, "unmapped": 0, "country_level": 0}, "sources": [{"key": "k", "name": "Feed", "ok": 1, "reports": 0}]},
    "autopilot_status": {"needs_me": [], "policy": {"auto_handle": False, "min_age_days": 3}},
    "licence_state": {"licensed": False}, "protection_status": {"available": True, "level": "on", "summary": "Defender is on"},
    "phone_status": {"relay": "", "relay_error": "", "crypto": True, "crypto_error": "", "identity": False, "devices": 0, "pending": 0, "last_ok": None, "last_error": ""},
    "phone_devices": {"devices": []}, "procs_snapshot": {"snaps": {}, "status": None}, "procs_baseline": {},
    "check_update": {"enabled": True, "current": "2026.11.09-0", "latest": "2026.11.09-0", "newer": False},
    "get_settings": {"notify_findings": True, "notify_health": True, "notify_outage": True},
    "open_page": {"ok": True, "paired_link": True}, "run_collector": {"queued": True},
}
# A wrong-typed answer for every read: lists as strings, objects as numbers.
WRONG = {k: {kk: ("x" if isinstance(vv, list) else 7 if isinstance(vv, dict) else vv) for kk, vv in v.items()}
         for k, v in GOOD.items() if isinstance(v, dict)}

SHIM = """
window.__calls = [];
let cb = 0;
window.__TAURI_INTERNALS__ = {
  transformCallback: () => ++cb,
  invoke: async (cmd, args) => {
    if (cmd.startsWith('plugin:')) return 1;
    window.__calls.push([cmd, args || {}]);
    if (cmd === 'app_status') return window.__STATUS;
    const mode = window.__MODE;
    if (mode === 'empty' && !['open_page', 'run_collector'].includes(cmd)) return {};
    if (mode === 'wrong' && cmd in window.__WRONG) return window.__WRONG[cmd];
    return cmd in window.__GOOD ? window.__GOOD[cmd] : {};
  },
};
"""

results = []


def check(name, ok, info=""):
    results.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name + ("" if ok or not info else f"  [{info}]"), flush=True)


def serve():
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass
    handler = functools.partial(Quiet, directory=str(DIST))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


async def open_page(b, status="degraded", mode="expert", theme="light", lang="en", answers="good", expanded=False, width=1280):
    ctx = await b.new_context(viewport={"width": width, "height": 820}, color_scheme=theme)
    pg = await ctx.new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)[:200]))
    pg.on("console", lambda m: errors.append(m.text[:200]) if m.type == "error" else None)
    await pg.add_init_script(
        f"try{{localStorage.setItem('jarvis.mode','{mode}');localStorage.setItem('jarvis.lang','{lang}');"
        f"localStorage.setItem('jarvis.statusOpen','{1 if expanded else 0}')}}catch(e){{}}"
        f"window.__STATUS={json.dumps(STATUS[status])};window.__MODE='{answers}';"
        f"window.__GOOD={json.dumps(GOOD)};window.__WRONG={json.dumps(WRONG)};" + SHIM)
    await pg.goto(BASE)
    await pg.wait_for_timeout(1800)
    return ctx, pg, errors


async def calls(pg, cmd):
    return [a for c, a in await pg.evaluate("window.__calls") if c == cmd]


async def sideways(pg):
    return await pg.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth + 1")


async def every_view(pg, errors, tag, shots, min_text=40):
    count = await pg.locator("aside nav button").count()
    check(f"[{tag}] sidebar lists views", count >= 9, str(count))
    for i in range(count):
        label = (await pg.locator("aside nav button").nth(i).inner_text()).split("\n")[0].strip()
        before = len(errors)
        await pg.locator("aside nav button").nth(i).click()
        await pg.wait_for_timeout(700)
        text = (await pg.locator("main").inner_text()).strip()
        check(f"[{tag}] {label}: renders", len(text) > min_text, text[:80])
        check(f"[{tag}] {label}: no script error", len(errors) == before, "; ".join(errors[before:])[:200])
        check(f"[{tag}] {label}: no sideways scroll", not await sideways(pg))
        if shots:
            await pg.screenshot(path=str(Path(shots) / f"{tag.replace('/', '-')}-{i:02d}.png"))
    # The coverage panel in the sidebar opens the Coverage view.
    before = len(errors)
    await pg.locator("aside button[data-view=coverage]").first.click()
    await pg.wait_for_timeout(700)
    check(f"[{tag}] Coverage: no script error", len(errors) == before, "; ".join(errors[before:])[:200])


async def run(shots):
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        b = await p.chromium.launch()

        for mode in ("expert", "simple"):
            for theme in ("light", "dark"):
                ctx, pg, errors = await open_page(b, mode=mode, theme=theme)
                await every_view(pg, errors, f"{mode}/{theme}", shots)
                await ctx.close()

        for answers in ("empty", "wrong"):
            ctx, pg, errors = await open_page(b, answers=answers)
            check(f"[partial:{answers}] app starts without a script error", not errors, "; ".join(errors)[:200])
            await every_view(pg, errors, f"partial:{answers}", None, min_text=0)
            await ctx.close()

        ctx, pg, errors = await open_page(b)
        banner = pg.locator("main [role=status]").first
        text = await banner.inner_text()
        check("banner: headline", f"{N} of its checks are not working" in text, text[:120])
        check("banner: collapsed shows no names", ADMIN[0] not in text)
        check("banner: collapsed is short", (await banner.bounding_box())["height"] < 120)
        await pg.get_by_role("button", name="Show which").click()
        await pg.wait_for_timeout(300)
        text = await banner.inner_text()
        missing = [n for n in ADMIN + STALE + FAILED if n not in text]
        check("banner: every blind check is listed", not missing, str(missing))
        check("banner: the edition limit is explained", "limit of this edition, not a fault" in text)
        row = pg.locator("main [role=status] li", has_text=FAILED[0])
        await row.hover()
        await row.get_by_role("button").click()
        await pg.wait_for_timeout(300)
        ran = await calls(pg, "run_collector")
        check("banner: Run again queues that check", bool(ran) and ran[-1].get("job") == "f0", str(ran))
        check("banner: no Run again on edition limits",
              await pg.locator("main [role=status] li", has_text=ADMIN[0]).get_by_role("button").count() == 0)
        await pg.get_by_role("button", name="See collectors").click()
        await pg.wait_for_timeout(500)
        check("banner: See collectors opens Collectors", "Collectors" in await pg.locator("header h1").inner_text())
        check("sidebar: short status", f"{N} checks limited" in await pg.locator("aside").last.inner_text())
        check("banner: no script error", not errors, "; ".join(errors)[:200])
        await ctx.close()

        ctx, pg, errors = await open_page(b, mode="simple", expanded=True)
        check("simple: no Collectors button or Run again",
              await pg.get_by_role("button", name="See collectors").count() == 0
              and await pg.get_by_role("button", name="Run again").count() == 0)
        await ctx.close()
        ctx, pg, errors = await open_page(b, status="edition")
        cls = await pg.locator("main [role=status] > div").first.get_attribute("class") or ""
        check("edition limits only: neutral, not amber", "amber" not in cls, cls)
        await ctx.close()
        ctx, pg, errors = await open_page(b, status="live")
        check("live: no banner", await pg.locator("main [role=status]").count() == 0)
        await ctx.close()
        for st in ("stopped", "not_installed", "not_authorised"):
            ctx, pg, errors = await open_page(b, status=st)
            text = await pg.locator("main [role=status]").first.inner_text()
            check(f"{st}: message and next step shown", STATUS[st]["message"] in text and STATUS[st]["detail"] in text, text[:150])
            await ctx.close()

        ctx, pg, errors = await open_page(b)
        await pg.keyboard.press("Control+k")
        await pg.wait_for_timeout(300)
        await pg.get_by_role("option", name="Open in your browser").click()
        await pg.wait_for_timeout(300)
        opened = await calls(pg, "open_page")
        check("Ctrl K: Open in your browser", bool(opened) and opened[-1].get("page") == "dashboard", str(opened))
        await pg.locator("aside nav button", has_text="Settings").click()
        await pg.wait_for_timeout(500)
        await pg.locator("section", has_text="See everything in your browser too").get_by_role("button", name="Open").click()
        await pg.wait_for_timeout(300)
        check("Settings: Open in your browser", len(await calls(pg, "open_page")) == 2)
        for view, page in (("Coverage", "coverage"), ("GeoSecurity", "geo"), ("World", "world"), ("Processes", "procs")):
            if view == "Coverage":
                await pg.locator("aside button[data-view=coverage]").first.click()
            else:
                await pg.locator("aside nav button", has_text=view).first.click()
            await pg.wait_for_timeout(600)
            await pg.locator("main button", has_text="Open full").first.click()
            await pg.wait_for_timeout(300)
            opened = await calls(pg, "open_page")
            check(f"{view}: full view opens {page}", opened[-1].get("page") == page, str(opened[-1:]))
        check("browser actions: no script error", not errors, "; ".join(errors)[:200])
        await ctx.close()

        for lang, head, label in (("fr", f"mais {N} de ses", "Voir lesquels"), ("de", f"aber {N} seiner", "Welche anzeigen"),
                                  ("ja", f"{N} 件のチェック", "どれか表示"), ("ar", f"{N} من فحوصاته", "أظهر أيّها")):
            ctx, pg, errors = await open_page(b, lang=lang)
            text = await pg.locator("main [role=status]").first.inner_text()
            check(f"[{lang}] headline translated", head in text, text[:120])
            check(f"[{lang}] labels translated", label in text, text[:120])
            check(f"[{lang}] no sideways scroll", not await sideways(pg))
            if lang == "ar":
                check("[ar] right-to-left", await pg.evaluate("document.documentElement.dir") == "rtl")
            await ctx.close()
        for st in ("stopped", "not_installed"):
            ctx, pg, errors = await open_page(b, status=st, lang="fr")
            text = await pg.locator("main [role=status]").first.inner_text()
            check(f"[fr] {st} headline translated", STATUS[st]["message"] not in text, text[:120])
            await ctx.close()

        ctx, pg, errors = await open_page(b, width=900, expanded=True)
        check("900 px: no sideways scroll with the banner open", not await sideways(pg))
        await ctx.close()
        await b.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shots", help="write a screenshot of every view here")
    args = ap.parse_args()
    if not (DIST / "index.html").is_file():
        sys.exit("no desktop/ui/dist; run: (cd desktop/ui && bun run build)")
    if args.shots:
        Path(args.shots).mkdir(parents=True, exist_ok=True)
    srv = serve()
    try:
        asyncio.run(run(args.shots))
    finally:
        srv.shutdown()
    passed = sum(ok for _, ok in results)
    print(f"\n{passed}/{len(results)} checks passed")
    return 0 if results and passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
