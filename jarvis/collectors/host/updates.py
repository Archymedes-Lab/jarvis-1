"""Outdated software across every package manager on this machine, ranked.

Every outdated program that parses untrusted input or talks to the network is
attack surface a published fix already closes. `patches` reports the Linux
security fixes the distribution index knows about; this lists what each
package manager itself says is outdated, on both sides of the machine:

    Linux    apt (no removals: `upgrade --with-new-pkgs` semantics), snap, Homebrew
    Windows  winget (all scopes, and separately the user scope that needs no
             administrator prompt), Chocolatey

Reads only. Simulations and listings change nothing; the one network effect is
each manager's own index refresh (winget's source, Homebrew's API), which the
managers do on their own schedule anyway.

Invariants (tests/test_updates.py):
  * A manager that cannot be listed says so (visibility, coverage partial). It
    is never "up to date".
  * "Important" is a fixed, reviewable rule (security pocket, or a program in
    EXPOSED), never a model's opinion.
  * Auto-update eligibility is decided here and nowhere else: user-scope
    winget and Homebrew only, never an item that needs elevation.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time

from jarvis.core.finding import LOCAL_HOST

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
BREW = "/home/linuxbrew/.linuxbrew/bin/brew"
LIST_TIMEOUT_S = 120
MAX_NAMED = 8
STATE_META = "updates_plan_v1"
NOTIFY_META = "updates_notified_v1"

# Programs whose outdated versions are exposure, by package id or name
# (lowercase, regex). Each is something that parses untrusted content, talks
# to the network, holds secrets, or installs other software. Reviewable and
# deliberately coarse: a missing entry means "routine", never "safe".
EXPOSED = (
    # browsers and web runtimes
    r"firefox", r"chrome", r"chromium", r"\bedge\b", r"msedge", r"brave", r"opera", r"vivaldi",
    r"webview2",
    # language runtimes and toolchains that run downloaded code
    r"nodejs|\bnode\b", r"python", r"openjdk|\bjava\b|jre|jdk|temurin|corretto", r"dotnet",
    r"\bgo(lang)?\b", r"rustup", r"\bruby\b", r"\bphp\b", r"powershell", r"vcredist|visual c\+\+",
    # version control, transfer, remote access
    r"\bgit\b|git\.git", r"\bcurl\b", r"wget", r"openssh|\bssh\b", r"putty", r"winscp", r"filezilla",
    r"openvpn", r"wireguard", r"tailscale", r"teamviewer", r"anydesk", r"rustdesk", r"\bvnc\b",
    r"cloudflared", r"flyctl",
    # crypto libraries
    r"openssl", r"gnutls", r"gnupg|\bgpg\b", r"libssl",
    # parser and compression libraries many programs share (xz, 2024)
    r"\bxz\b|liblzma", r"zlib", r"zstd", r"sqlite", r"libxml2|expat", r"libpng|libjpeg|libwebp|libtiff|giflib",
    r"libarchive", r"freetype", r"poppler", r"ghostscript", r"\bexiv2\b",
    # documents, media and archives (parsers of files people are sent)
    r"libreoffice", r"openoffice", r"\boffice\b", r"acrobat|adobe ?reader|\bpdf\b", r"sumatra",
    r"ffmpeg", r"\bvlc\b", r"imagemagick", r"7-?zip", r"winrar|\brar\b", r"peazip", r"gimp", r"inkscape",
    r"blender",
    # mail, chat, meetings
    r"outlook", r"thunderbird", r"\bmail\b", r"zoom", r"teams", r"slack", r"discord", r"telegram",
    r"whatsapp", r"signal", r"skype",
    # password managers, sync and secrets
    r"proton", r"bitwarden", r"keepass", r"1password", r"lastpass", r"dropbox", r"onedrive",
    r"nextcloud",
    # editors that load extensions and open remote workspaces; package managers
    r"vscode|vscodium|visual studio code", r"chocolatey", r"winget|appinstaller", r"\bdocker\b",
    r"claude", r"notepad\+\+",
)
_EXPOSED = re.compile("|".join(f"(?:{p})" for p in EXPOSED), re.I)
WINGET_SOURCES = {"winget", "msstore"}
_WINGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


def _f(severity, title, detail, where="", **extra):
    return {"category": "updates", "severity": severity, "title": title, "detail": detail,
            "where": where, "host": LOCAL_HOST, **extra}


def _visibility(title, detail, where):
    return {"category": "visibility", "severity": "low", "title": title, "detail": detail,
            "where": where, "host": LOCAL_HOST}


def _run(argv, timeout=LIST_TIMEOUT_S, env=None):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                           timeout=timeout, env=env or ENV, cwd="/")
        return r.returncode, r.stdout
    except (OSError, subprocess.SubprocessError):
        return None, ""


def important(manager, pkg_id, name="", security=False):
    """(True, reason) for an update that closes exposure, else (False, '')."""
    if security:
        return True, "security update"
    text = f"{pkg_id} {name}"
    if _EXPOSED.search(text):
        return True, "handles untrusted input, the network or secrets"
    return False, ""


def _item(manager, pkg_id, name, installed, available, *, security=False, scope="",
          needs_admin=False, pinned=False):
    imp, why = important(manager, pkg_id, name, security)
    return {"manager": manager, "id": pkg_id, "name": name or pkg_id, "installed": installed,
            "available": available, "security": bool(security), "important": imp, "why": why,
            "scope": scope, "needs_admin": bool(needs_admin), "pinned": bool(pinned)}


# --- parsers (pure) --------------------------------------------------------------

def parse_apt(text):
    """Items from `apt-get -s upgrade --with-new-pkgs` output."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^Inst (\S+) (?:\[([^\]]+)\] )?\((\S+) ([^)]*)\)", line)
        if not m:
            continue
        name, old, new, rest = m.groups()
        out.append(_item("apt", name.split(":", 1)[0], name, old or "", new,
                         security="-security" in rest, needs_admin=True))
    return out


def parse_snap(text):
    if "All snaps up to date" in text:
        return []
    out = []
    lines = [ln for ln in text.splitlines() if ln.strip()]
    for line in lines[1:] if lines and lines[0].startswith("Name") else []:
        parts = line.split()
        if len(parts) >= 2:
            out.append(_item("snap", parts[0], parts[0], "", parts[1], needs_admin=True))
    return out


def parse_brew(text):
    try:
        doc = json.loads(text or "{}")
    except ValueError:
        return None
    if not isinstance(doc, dict):           # unreadable, not "no updates" (FZ-10)
        return None
    out = []
    for kind in ("formulae", "casks"):
        rows = doc.get(kind) or []
        for f in rows if isinstance(rows, list) else []:
            if not isinstance(f, dict) or not f.get("name"):
                continue
            inst = f.get("installed_versions") or []
            inst = inst if isinstance(inst, list) else [str(inst)]
            out.append(_item("brew", f["name"], f["name"], (inst[-1] if inst else ""),
                             str(f.get("current_version") or ""), scope="user",
                             pinned=bool(f.get("pinned"))))
    return out


def parse_winget(text, scope=""):
    """Items from `winget upgrade` table output.

    Parsed from the right: the last columns (Id, Version, Available, Source)
    never contain spaces, except a version written "< 3.14.7"; names do, and
    winget pads them by display width, so header offsets are not reliable."""
    out = []
    started = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not started:
            started = line.startswith("---")
            continue
        if not line.strip():
            continue
        low = line.lower()
        tok = line.split()
        # Footer phrases end the table only on a line that is not a row: a row ends in
        # its source. An installed program names itself (user-scope ones included), and
        # a display name such as "The following ..." used to drop every later row (FZ-08).
        if tok and tok[-1].lower() not in WINGET_SOURCES and (
                re.match(r"^\d+ upgrades? available", low) or "require explicit targeting" in low
                or "cannot be determined" in low or low.startswith("the following")):
            break
        if len(tok) < 4:
            continue
        if tok[-1].lower() in WINGET_SOURCES:
            tok.pop()
        available = tok.pop()
        version = tok.pop()
        if tok and tok[-1] in ("<", ">"):
            version = tok.pop() + " " + version
        if not tok:
            continue
        pkg_id = tok.pop()
        if not _WINGET_ID.match(pkg_id) or not tok:
            continue
        out.append(_item("winget", pkg_id, " ".join(tok), version, available, scope=scope,
                         needs_admin=(scope != "user")))
    return out


def parse_choco(text):
    out = []
    for line in text.splitlines():
        parts = line.strip().split("|")
        if len(parts) == 4 and parts[0] and parts[1] != parts[2]:
            out.append(_item("choco", parts[0], parts[0], parts[1], parts[2], needs_admin=True,
                             pinned=parts[3].strip().lower() == "true"))
    return out


# --- listing ------------------------------------------------------------------

PS_LIST = r"""
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$o = [ordered]@{ winget = $null; winget_user = $null; choco = $null; errors = @() }
if (Get-Command winget -ErrorAction SilentlyContinue) {
  try {
    $o.winget = (winget upgrade --include-unknown --accept-source-agreements --disable-interactivity 2>&1 | Out-String -Width 400)
    $o.winget_user = (winget upgrade --scope user --include-unknown --accept-source-agreements --disable-interactivity 2>&1 | Out-String -Width 400)
  } catch { $o.errors += 'winget: ' + $_.Exception.Message }
}
if (Get-Command choco -ErrorAction SilentlyContinue) {
  try { $o.choco = (choco outdated -r --ignore-unfound 2>&1 | Out-String -Width 400) }
  catch { $o.errors += 'choco: ' + $_.Exception.Message }
}
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Compress)))
"""


def list_linux(run=_run, brew=BREW, have=shutil.which):
    """{manager: [items]} plus {manager: error} for what could not be read."""
    found, failed = {}, {}
    if have("apt-get"):
        code, out = run(["apt-get", "-s", "-q", "-o", "Debug::NoLocking=1", "upgrade", "--with-new-pkgs"])
        if code == 0:
            found["apt"] = parse_apt(out)
        else:
            failed["apt"] = "the simulated upgrade did not run"
    if have("snap"):
        code, out = run(["snap", "refresh", "--list"])
        if code == 0 or "All snaps up to date" in out:
            found["snap"] = parse_snap(out)
        else:
            failed["snap"] = "snap refresh --list did not run"
    if brew and os.path.exists(brew):
        env = {**ENV, "PATH": os.path.dirname(brew) + ":" + ENV["PATH"], "HOME": os.path.expanduser("~"),
               "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ANALYTICS": "1"}
        code, out = run([brew, "outdated", "--json=v2"], env=env)
        items = parse_brew(out) if code == 0 else None
        if items is None:
            failed["brew"] = "brew outdated did not run"
        else:
            found["brew"] = items
    return found, failed


def list_windows(ps=None):
    """({manager: [items]}, {manager: error}). Not applicable without Windows."""
    from jarvis.platform import host
    if not host.has_windows():
        return {}, {}
    if ps is None:
        from jarvis.platform import windows as collect_windows
        ps = collect_windows.ps_json
    doc = ps(PS_LIST, timeout=LIST_TIMEOUT_S + 60)
    if not isinstance(doc, dict):
        return {}, {"winget": "PowerShell gave no answer", "choco": "PowerShell gave no answer"}
    found, failed = {}, {}
    if doc.get("winget") is not None:
        everything = parse_winget(doc.get("winget") or "")
        user = {i["id"] for i in parse_winget(doc.get("winget_user") or "", scope="user")}
        for i in everything:
            if i["id"] in user:
                i.update(scope="user", needs_admin=False)
            else:
                i["scope"] = i["scope"] or "machine"
        if not everything and "upgrade" not in (doc.get("winget") or "").lower() \
                and "no installed package" not in (doc.get("winget") or "").lower():
            failed["winget"] = "winget printed nothing recognisable"
        else:
            found["winget"] = everything
    if doc.get("choco") is not None:
        found["choco"] = parse_choco(doc.get("choco") or "")
    for err in doc.get("errors") or []:
        name = str(err).split(":", 1)[0]
        failed.setdefault(name, str(err)[:160])
    return found, failed


def plan(run=_run, ps=None, now=None):
    """The whole picture: {"at", "items", "failed", "managers"}."""
    now = time.time() if now is None else now
    found, failed = list_linux(run)
    wf, wfail = list_windows(ps)
    found.update(wf)
    failed.update(wfail)
    items = [i for group in found.values() for i in group]
    return {"at": now, "items": items, "failed": failed, "managers": sorted(found)}


# --- auto-update policy (pure) -------------------------------------------------------

MODES = ("off", "notify", "important", "all")
DEFAULT_MODE = "notify"


def policy(conf):
    """The owner's choice from the alert config. Unknown values fall back to
    notify: a typo must never enable automatic installs."""
    mode = str(conf.get("auto_update") or DEFAULT_MODE).strip().lower()
    if mode not in MODES:
        mode = DEFAULT_MODE
    exclude = {str(x).strip().lower() for x in (conf.get("auto_update_exclude") or []) if str(x).strip()}
    return {"mode": mode, "exclude": exclude}


def auto_eligible(item, pol):
    """True when Argus may update this item by itself under `pol`.

    Only what needs no elevation (a background administrator prompt is not
    something to spring on anyone): user-scope winget and Homebrew. Pinned and
    excluded items never."""
    if pol["mode"] not in ("important", "all"):
        return False
    if item.get("pinned") or item.get("needs_admin"):
        return False
    if item["manager"] == "winget" and item.get("scope") != "user":
        return False
    if item["manager"] not in ("winget", "brew"):
        return False
    if item["id"].lower() in pol["exclude"] or item["name"].lower() in pol["exclude"]:
        return False
    return pol["mode"] == "all" or item["important"]


# --- the job ------------------------------------------------------------------------

def _names(items):
    shown = [i["name"] for i in items[:MAX_NAMED]]
    more = len(items) - len(shown)
    return ", ".join(shown) + (f" and {more} more" if more > 0 else "")


def findings(p, pol, auto_state=None):
    out = []
    items = p["items"]
    imp = [i for i in items if i["important"]]
    routine = [i for i in items if not i["important"]]
    for name, err in sorted(p["failed"].items()):
        out.append(_visibility(f"could not list updates from {name}",
                               f"{err}; outdated software it manages is unknown, not up to date.", name))
    if imp:
        needs_you = [i for i in imp if not auto_eligible(i, pol)]
        auto = [i for i in imp if auto_eligible(i, pol)]
        detail = (f"{len(imp)} outdated program(s) that handle untrusted input, the network or "
                  f"secrets: {_names(imp)}. Published fixes close this exposure.")
        if auto:
            detail += f" Argus updates {len(auto)} of them itself (auto_update={pol['mode']})."
        if needs_you:
            detail += (f" {len(needs_you)} need you: run `jarvis update plan`, then "
                       f"`jarvis update apply`.")
        sev = "high" if any(i["security"] for i in imp) else "medium"
        out.append(_f(sev, f"{len(imp)} important update(s) not installed", detail, "jarvis update plan",
                      update_ids=sorted(f"{i['manager']}:{i['id']}" for i in imp)))
    if routine:
        out.append(_f("low", f"{len(routine)} other update(s) available",
                      f"{_names(routine)}. Run `jarvis update plan` to see them all.", "jarvis update plan"))
    st = auto_state or {}
    if st.get("finished_at"):
        done = st.get("results") or []
        ok = [r for r in done if r.get("verified")]
        bad = [r for r in done if not r.get("verified")]
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(st["finished_at"]))
        if ok:
            out.append(_f("low", f"Argus updated {len(ok)} program(s) at {when}",
                          ", ".join(f"{r['name']} {r.get('from') or '?'} to {r.get('to') or '?'}" for r in ok[:MAX_NAMED])
                          + ". Each was confirmed by a fresh listing; `jarvis update log` has the record.",
                          "jarvis update log"))
        if bad:
            out.append(_f("medium", f"automatic update of {len(bad)} program(s) did not complete",
                          "; ".join(f"{r['name']}: {r.get('error') or 'still outdated after the attempt'}"
                                    for r in bad[:MAX_NAMED]) + ". Nothing else was changed; run "
                          "`jarvis update apply` to retry with you present.", "jarvis update log"))
    if not items and not p["failed"]:
        out.append(_f("ok", "every package manager reports nothing outdated",
                      f"checked: {', '.join(p['managers']) or 'none present'}", "jarvis update plan"))
    return out


def audit(store, *, plan_fn=plan, conf=None, start_auto=None, last_auto=None, notify=None, now=None):
    """The `updates` job: list, rank, persist the plan, and (when the owner
    opted in) hand eligible items to the bounded updater. Never raises past
    the scheduler's observation.

    The acting parts live in the response layer and are handed in by the job
    (service/jobs.py `_updates_job`): `start_auto` (response/updater.py),
    `last_auto` and `notify`. Without them this only lists and ranks."""
    from jarvis.core import collection
    now = time.time() if now is None else now
    conf = {} if conf is None else conf
    pol = policy(conf)
    p = plan_fn()
    for name in p["failed"]:
        collection.failed("updates:" + name, p["failed"][name])
    store.set_meta(STATE_META, json.dumps(p, sort_keys=True)[:200_000])
    if pol["mode"] in ("important", "all"):
        eligible = [i for i in p["items"] if auto_eligible(i, pol)]
        if eligible and start_auto is not None:
            start_auto(store, eligible, now=now)
    out = findings(p, pol, last_auto(store) if last_auto is not None else None)
    if pol["mode"] != "off" and notify is not None:
        try:
            notify(store, conf, p, pol, now)
        except Exception:
            pass
    return out


NOTIFY_EVERY_S = 12 * 3600


def notice_text(names, auto=0):
    """(subject, text) of the updates notice, in everyday words, every name kept."""
    n = len(names)
    many = n != 1
    subject = (f"[ARGUS-INSTINCT] {n} important update{'s' if many else ''} "
               f"waiting to be installed")
    text = (f"{n} important update{'s' if many else ''} for software on this computer "
            f"{'are' if many else 'is'} not installed yet: {_names([{'name': x} for x in names])}.\n"
            "Updates often fix security problems, so it is worth installing them soon.\n"
            + (f"ARGUS-INSTINCT will install {auto} of them by itself.\n" if auto else "")
            + "What to do: open ARGUS-INSTINCT to see and install them, or run "
              "jarvis update plan and then jarvis update apply.")
    return subject, text


def notify_owner(store, conf, p, pol, now, deliver=None, enabled=None):
    """One categorized "updates" notice when the set of important pending
    updates changes (new ones appear), at most every NOTIFY_EVERY_S. Returns
    True when one was sent. `deliver` and `enabled` are response/alert.py's,
    handed in by the job; without `deliver` nothing is sent."""
    if deliver is None:
        return False
    if conf.get("notify_updates", True) is False:
        return False
    imp = sorted(f"{i['manager']}:{i['id']}:{i['available']}" for i in p["items"] if i["important"])
    try:
        last = json.loads(store.get_meta(NOTIFY_META, "{}") or "{}")
    except ValueError:
        last = {}
    new = sorted(set(imp) - set(last.get("seen") or []))
    sent_at = float(last.get("at") or 0)
    if not new or (sent_at and now - sent_at < NOTIFY_EVERY_S):
        if not imp:
            store.set_meta(NOTIFY_META, json.dumps({"at": last.get("at") or 0, "seen": []}))
        return False
    if enabled is not None and not enabled(conf):
        return False
    names = [i["name"] for i in p["items"] if i["important"]]
    auto = [i for i in p["items"] if auto_eligible(i, pol)]
    subject, text = notice_text(names, len(auto))
    err = deliver(conf, subject, text, category="updates")
    if not err:
        store.set_meta(NOTIFY_META, json.dumps({"at": now, "seen": imp}))
        return True
    return False
