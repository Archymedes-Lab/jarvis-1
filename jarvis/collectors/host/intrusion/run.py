"""The intrusion audit: one PowerShell sample, turned into findings."""

import json
import ntpath
import re
import time

from jarvis.core.paths import load_win_script
from jarvis.platform.windows import aslist, ps_json, stdin_text

from .bits import _bits_is_vendor
from .common import _finding
from .credentials import credential_findings
from .explain import explain_threat
from .history import _history_findings

# Command shapes that show up in ClickFix lures and in pasted-payload attacks.
PASTE_ATTACK = re.compile(
    r"powershell|pwsh|cmd(\.exe)?\s*/c|mshta|curl|wget|iwr|invoke-webrequest|"
    r"invoke-expression|\biex\b|bitsadmin|certutil|msiexec\s+/i\s+http|"
    r"regsvr32|rundll32|conhost|forfiles|\bftp\b|base64|frombase64string|"
    r"\.hta\b|\bwscript\b|\bcscript\b|http://|https://|\\\\[^\\]+\\",
    re.I,
)


# Extension permissions that allow reading every page, including session tokens.
BROAD_PERMS = re.compile(r"<all_urls>|\*://\*/\*|http://\*/\*|https://\*/\*|"
                         r"webRequest|cookies|debugger|nativeMessaging|proxy",
                         re.I)


PS_INTRUSION = load_win_script("intrusion.ps1")
# A detection that is not active and never executed becomes history after this.
DETECTION_HISTORY_S = 72 * 3600


def _epoch(value):
    from datetime import datetime
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None
# SHA-256 of "# PowerShell test file to determine AppLocker lockdown mode ",
# the entire body PowerShell writes to its policy-test files.
PS_POLICY_TEST_SHA256 = "96ad1146eb96877eab5942ae0736b82d8b5e2039a80d3d6932665c1a4c87dcf7"
PS_POLICY_TEST_NAME = re.compile(r"\\__PSScriptPolicyTest_[a-z0-9]+\.[a-z0-9]+\.ps1$", re.I)

# Library source that a package manager unpacked (npm, pnpm, yarn): .js/.mjs/.cjs
# files under node_modules. Nobody Authenticode-signs these, so "NotSigned" says
# nothing about them, and an `npm install` in a scratch folder under Temp writes
# hundreds at once (one real machine: 124 of its 226 high findings). Only
# NotSigned source is lowered, and it stays listed. A native add-on (.node),
# an executable, a hash mismatch or an untrusted signature keeps its severity.
PACKAGE_SOURCE = re.compile(r"\\node_modules\\.+\.(?:js|mjs|cjs)$", re.I)

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# Extensions that ship with the browser or are installed by Windows itself.
STOCK_EXT = re.compile(r"^(Chrome Web Store Payments|Google Docs Offline|"
                       r"Microsoft Defender Browser Protection|"
                       r"Edge relevant text changes|Web Store|"
                       r"Chrome PDF Viewer|Firefox Screenshots)$", re.I)


REFUSED_META = "intrusion_refused_v1"
MAX_REFUSED = 200


def _refused(store):
    if store is None:
        return []
    try:
        keys = json.loads(store.get_meta(REFUSED_META, "") or "[]")
    except (TypeError, ValueError):
        return []
    return [k for k in keys if isinstance(k, str)][:MAX_REFUSED] if isinstance(keys, list) else []


def audit(store=None):
    """`store` remembers files Windows refused to let the audit open, so they are not
    opened (and logged by Windows as blocked) again on every pass."""
    request = json.dumps({"refused": _refused(store)})
    # The marker stays the first line of the command: Windows truncates long command lines
    # in its records, and the credential check and the block explainer recognise this
    # payload by it.
    data = ps_json(PS_INTRUSION.split("\n", 2)[1] + "\n" + stdin_text("jarvisReq") + PS_INTRUSION,
                   timeout=300, payload=request)
    if data is None:
        return [_finding("clickfix", "medium", "intrusion audit unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []

    # -- 1. ClickFix ------------------------------------------------------
    runmru = aslist(data.get("runmru"))
    for r in runmru:
        cmd = (r.get("cmd") or "").rstrip("\\1")
        if not cmd:
            continue
        if PASTE_ATTACK.search(cmd):
            out.append(_finding(
                "clickfix", "critical",
                "a command was typed or pasted into the Win+R Run dialog",
                cmd[:150],
                "RunMRU — this is the artefact ClickFix leaves. If you did not "
                "type this yourself, treat the machine as compromised."))
        else:
            out.append(_finding("clickfix", "low", "Run dialog history",
                                cmd[:100], "RunMRU"))
    if not runmru:
        out.append(_finding("clickfix", "ok", "Run dialog history is empty",
                            "nothing has been typed into Win+R", "RunMRU"))

    # -- 2. PowerShell history --------------------------------------------
    out.extend(_history_findings(data))
    out.extend(credential_findings(data))

    # -- 3. Defender's own findings ---------------------------------------
    # Grade on what is still true, not on the fact that Defender once said the
    # name. A threat Defender still calls active is critical; an inactive one
    # whose file is still sitting on disk is a live risk waiting to be run
    # again; an inactive one whose file is gone is history, and reporting it
    # forever trains you to ignore the category.
    last_seen = {}
    for d in aslist(data.get("threats")):
        stamp = _epoch(d.get("time"))
        if stamp is not None and d.get("id"):
            last_seen[str(d["id"])] = max(last_seen.get(str(d["id"]), 0), stamp)
    for t in aslist(data.get("threatNames")):
        active, on_disk = t.get("active"), t.get("onDisk")
        seen = last_seen.get(str(t.get("id") or ""))
        stale = (seen is not None and time.time() - seen > DETECTION_HISTORY_S
                 and t.get("executed") is False)
        if active:
            sev, note = "critical", "still active"
        elif on_disk:
            sev, note = "high", "not active, but the file is still on disk"
        elif on_disk is None and stale:
            sev, note = "low", ("not active, never executed, last detected "
                                f"{int((time.time() - seen) // 86400)} days ago — historical")
        elif on_disk is None:
            sev, note = "medium", "not active; names no file to verify"
        else:
            sev, note = "low", "not active, file no longer on disk — historical"
        out.append(_finding("av", sev, "Defender detected a threat",
                            f"{t.get('name')} — {note}. {explain_threat(t.get('name'))}".rstrip(),
                            (t.get("resources") or "")[:110] or "Get-MpThreat"))
    # Defender logs one detection per scan, so the same file appears repeatedly.
    # Collapse by resource and keep the worst outcome and latest time.
    detections = {}
    for d in aslist(data.get("threats")):
        key = (d.get("resources") or "")[:200]
        clean = str(d.get("action")).lower() == "true"
        e = detections.setdefault(key, {"n": 0, "clean": True, "last": ""})
        e["n"] += 1
        e["clean"] = e["clean"] and clean
        e["last"] = max(e["last"], d.get("time") or "")
    for res, e in sorted(detections.items(), key=lambda kv: kv[1]["last"],
                         reverse=True)[:10]:
        out.append(_finding(
            "av", "low" if e["clean"] else "critical",
            "Defender detection" + ("" if e["clean"] else " NOT remediated"),
            f"{res[:110]}" + (f"  (×{e['n']})" if e["n"] > 1 else ""),
            e["last"].replace("T", " ")[:19]))

    # -- 4. browser extensions --------------------------------------------
    exts = aslist(data.get("extensions"))
    for e in exts:
        name = e.get("name") or e.get("id") or "?"
        if name.startswith("__MSG_") or STOCK_EXT.match(name):
            continue
        # Browser-shipped add-ons are not "sideloaded" in any meaningful sense.
        location = (e.get("location") or "").lower()
        if location.startswith("app-") and location != "app-profile":
            continue
        # Mozilla ships several add-ons under its own IDs; they carry no update
        # URL because the browser updates them.
        if re.search(r"@mozilla\.(org|com)$", e.get("id") or "", re.I):
            continue
        perms = e.get("perms") or ""
        sideloaded = not (e.get("updateUrl") or "")
        broad = BROAD_PERMS.search(perms)
        if broad and sideloaded:
            sev, why = "critical", "broad permissions and no update URL (sideloaded)"
        elif sideloaded:
            sev, why = "high", "no update URL — installed outside the store"
        elif broad:
            sev, why = "low", "can read every page you visit"
        else:
            continue
        out.append(_finding("extension", sev, f"{e.get('browser')} extension",
                            f"{name} v{e.get('version')} — {why}",
                            f"{e.get('id')}  perms: {perms[:90]}"))
    out.append(_finding("extension", "ok", "browser extensions",
                        f"{len(exts)} installed across all browsers", ""))

    # -- 5. staged executables --------------------------------------------
    # %TEMP% and %LOCALAPPDATA%\Temp are normally the same directory and both
    # are searched, so the same file can arrive twice.
    recent_code, seen_paths = [], set()
    for item in aslist(data.get("recentExe"))[:250]:
        key = (item.get("path") or "").lower() if isinstance(item, dict) else None
        if key is None or key in seen_paths:
            continue
        seen_paths.add(key)
        recent_code.append(item)
    for f in recent_code:
        path, sig = f.get("path") or "", f.get("sig") or ""
        in_temp = re.search(r"\\temp\\|\\public\\", path, re.I)
        if sig == "Valid":
            continue
        if sig == "BlockedByWindows":
            # Windows Security refused to let the audit open it: its reputation rule blocks
            # the file, so it cannot be read here and cannot run either. Listed, not judged
            # by signature (unknown) and not opened again.
            out.append(_finding(
                "staging", "low", "recently written program Windows blocks",
                f"{path.split(chr(92))[-1]} — Windows Security blocks this file, so its signature could not be "
                f"checked and it cannot run here; written {(f.get('written') or '').replace('T', ' ')[:19]}", path))
            continue
        if (f.get("sha256") or "").lower() == EMPTY_SHA256:
            # Zero bytes cannot execute, and an empty file has no signature to
            # check — Authenticode reports UnknownError for it. Temp is full of
            # placeholder files that tools create and never fill.
            sev = "low"
        elif ((f.get("sha256") or "").lower() == PS_POLICY_TEST_SHA256
              and PS_POLICY_TEST_NAME.search(path)):
            # PowerShell probes AppLocker/WDAC by writing this exact one-line
            # comment to Temp; a crashed shell leaves it behind. Pinned to
            # the content hash, so any other body under the name stays high.
            sev = "low"
        elif sig == "NotSigned" and PACKAGE_SOURCE.search(ntpath.normpath(path)):
            sev = "low"
        elif in_temp or sig in ("HashMismatch", "NotTrusted"):
            sev = "high"
        else:
            sev = "low"
        out.append(_finding(
            "staging", sev, "recently written unsigned executable",
            f"{path.split(chr(92))[-1]} — {sig}, "
            f"{(f.get('written') or '').replace('T', ' ')[:19]}, "
            f"SHA-256 {(f.get('sha256') or 'unavailable')[:64]}", path))
    if store is not None:
        keys = [str(f.get("key")) for f in recent_code if f.get("sig") == "BlockedByWindows" and f.get("key")]
        store.set_meta(REFUSED_META, json.dumps(keys[:MAX_REFUSED]))
    valid_code = sum(1 for f in recent_code if f.get("sig") == "Valid")
    out.append(_finding(
        "staging", "ok", "recent downloaded and staged software inventoried",
        f"{len(recent_code)} executable/script files checked from the last 14 "
        f"days; {valid_code} have a valid Authenticode signature; every "
        f"non-valid item is listed separately with its SHA-256",
        "Downloads, Temp, AppData and Public"))

    # -- 6. BITS transfer jobs (T1197) ----------------------------------
    bits = aslist(data.get("bits"))
    for j in bits:
        name = j.get("name") or "(unnamed)"
        url = j.get("url") or ""
        if _bits_is_vendor(name, url):
            continue
        http = re.search(r"https?://", url, re.I)
        suspended = (j.get("state") or "").lower() in ("suspended", "queued",
                                                       "transient_error")
        if http and suspended:
            sev, why = "high", ("a suspended job with an HTTP source is how a "
                                "dropper stages a download to run later")
        elif http:
            sev, why = "medium", "downloads over HTTP under the service identity"
        else:
            sev, why = "low", "a BITS job outside the known updaters"
        out.append(_finding(
            "staging", sev, f"BITS transfer job: {name}",
            f"{why} — state {j.get('state')}, owner {j.get('owner') or '?'}, "
            f"url {url[:120] or '—'}", "Get-BitsTransfer"))
    scope = str(data.get("bitsScope") or "none")
    if scope == "none":
        out.append(_finding(
            "staging", "medium", "BITS transfer jobs are not readable",
            "neither the all-users nor the per-user query returned — queued "
            "BITS jobs are a reboot-surviving download channel and none of "
            "them are visible from here, which is not the same as there being "
            "none", "Get-BitsTransfer"))
    elif bits and not any(f["title"].startswith("BITS") for f in out):
        out.append(_finding(
            "staging", "ok", "BITS jobs",
            f"{len(bits)} queued, all served by known updater hosts"
            + ("" if scope == "all" else
               " — this account's jobs only; -AllUsers needs elevation, so "
               "jobs owned by other users or by SYSTEM are not in this view"),
            "Get-BitsTransfer"))
    elif not bits and scope == "user":
        out.append(_finding(
            "staging", "low", "no BITS jobs for this account",
            "the all-users view needs elevation and was refused, so a job "
            "owned by SYSTEM or another user would not appear here",
            "Get-BitsTransfer"))

    return out
