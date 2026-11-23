"""`jarvis model` — the local model runtime (Ollama): status, and installing it
with your approval.

    jarvis model status              is the local model there and answering?
    jarvis model plan                what `install` would download, from where, and its SHA-256
    jarvis model install [--yes]     download, verify and install Ollama after you approve
    jarvis model uninstall [--yes]   remove what `install` installed

Installing software is the owner's decision every time: the plan is printed in
full and nothing is downloaded until you type `install` (or pass --yes
yourself). The daemon and the web pages never install anything; they only
point here. See jarvis/platform/ollama.py for what is checked.
"""

import json
import platform
import shutil
import sys
import time
from pathlib import Path

from jarvis.platform import host, ollama

AUDIT_META = "model_install_v1"


def target():
    """Where Ollama belongs: the Windows host when Argus runs on Windows or in WSL."""
    return "windows" if host.kind() in ("windows", "wsl") else "linux"


def current_plan(min_age_days=ollama.MIN_AGE_DAYS):
    releases = ollama.fetch_json()
    rel = ollama.choose_release(releases, min_age_days=min_age_days)
    sums = ""
    if rel:
        sums_asset = next((a for a in rel.get("assets") or [] if a.get("name") == "sha256sum.txt"), None)
        if sums_asset:
            sums = ollama.fetch_text(sums_asset["browser_download_url"])
    return ollama.make_plan(rel, sums, target(), platform.machine())


def approve(plan, yes, word="install"):
    """True only for a sound plan that a person approved."""
    print(plan.describe())
    if plan.problems:
        return False
    if yes:
        return True
    if not sys.stdin.isatty():
        print(f"refusing without --yes on a non-interactive terminal; nothing was {word}ed")
        return False
    answer = input(f"\nType {word} to go ahead, anything else cancels: ").strip()
    if answer != word:
        print("cancelled; nothing was changed")
        return False
    return True


def download_path(plan):
    if plan.target == "windows":
        return Path(host.local_appdata("Temp", "argus-ollama", plan.asset))
    return Path.home() / ".cache" / "argus-ollama" / plan.asset


_LAST_PRINT = [0.0]


def _progress(got, size):
    now = time.monotonic()
    if now - _LAST_PRINT[0] >= 2 or got == size:
        _LAST_PRINT[0] = now
        print(f"\r  downloading {got / 1e9:.2f} of {size / 1e9:.2f} GB", end="" if got < size else "\n", flush=True)


def _audit(store, record):
    if store is None:
        return
    try:
        history = json.loads(store.get_meta(AUDIT_META, "[]") or "[]")
    except (TypeError, ValueError):
        history = []
    store.set_meta(AUDIT_META, json.dumps((history + [record])[-20:]))


def _status():
    from jarvis.response import alert, llm
    d = llm.diagnose(alert.load_conf())
    print(f"local model: {d['label']} ({d['seconds']}s)")
    return 0 if d["state"] == "ok" else 1


def cmd_model(args, store=None):
    if args.action == "status":
        return _status()
    if args.action == "uninstall":
        print(f"This removes the Ollama that `jarvis model install` installed for this "
              f"{'Windows user' if target() == 'windows' else 'user'}, and its service.")
        if not args.yes and not (sys.stdin.isatty() and
                                 input("Type uninstall to go ahead, anything else cancels: ").strip() == "uninstall"):
            print("cancelled; nothing was changed")
            return 1
        try:
            result = ollama.uninstall(target())
        except ollama.InstallError as exc:
            print(f"not removed: {exc}")
            return 1
        _audit(store, {"at": int(time.time()), "action": "uninstall", "target": target(), "result": str(result)[:200]})
        print("Ollama removed")
        return 0

    try:
        plan = current_plan(args.min_age_days)
    except (OSError, ValueError, ollama.InstallError) as exc:
        print(f"could not read Ollama's releases from GitHub: {exc}")
        return 1
    if args.action == "plan":
        print(plan.describe())
        return 0 if not plan.problems else 1

    if not approve(plan, args.yes):
        return 1
    dest = download_path(plan)
    need = plan.size * (3 if plan.target == "linux" else 1.2)     # archive + unpacked tree
    free = shutil.disk_usage(dest.parent if dest.parent.exists() else Path.home()).free
    if free < need:
        print(f"not enough free space: {need / 1e9:.1f} GB needed, {free / 1e9:.1f} GB free")
        return 1
    try:
        ollama.download(plan.url, dest, plan.size, plan.sha256, progress=_progress)
        print(f"  verified {plan.asset}: SHA-256 {plan.sha256}")
        ollama.install(plan, dest)
    except ollama.InstallError as exc:
        print(f"not installed: {exc}")
        _audit(store, {"at": int(time.time()), "action": "install", "version": plan.version,
                       "sha256": plan.sha256, "ok": False, "error": str(exc)[:200]})
        return 1
    finally:
        try:
            dest.unlink()
        except OSError:
            pass
    _audit(store, {"at": int(time.time()), "action": "install", "version": plan.version,
                   "sha256": plan.sha256, "target": plan.target, "ok": True})
    print(f"Ollama {plan.version} installed. Checking that it answers…")
    code = _status()
    from jarvis.response import alert, llm
    print(f"Next, download the model Argus uses (several GB, your choice): ollama pull "
          f"{llm.model_name(alert.load_conf())}")
    return code


def add_parser(sub):
    p = sub.add_parser("model", help="the local model runtime (Ollama): status, install with your approval")
    p.add_argument("action", nargs="?", default="status", choices=["status", "plan", "install", "uninstall"])
    p.add_argument("--yes", action="store_true", help="install/uninstall: approve without the typed confirmation")
    p.add_argument("--min-age-days", type=int, default=ollama.MIN_AGE_DAYS,
                   help=f"newest release at least this old (default {ollama.MIN_AGE_DAYS})")
    p.set_defaults(fn=cmd_model)
    return p
