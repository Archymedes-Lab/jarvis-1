"""Pre-OS boot integrity: what ran before Windows, compared with a baseline.

An attack that starts below the operating system (a firmware implant, a
bootkit, a rogue option ROM, a boot from other media) is over before any
collector runs, and the beep or menu it produced is gone. What it leaves is
measurement: the firmware records every component it starts into the TPM and
into a per-boot log. This collector replays those logs, pins a baseline, and
reports every later boot that measured differently. It also reads what the
boot manager and Windows recorded about recent boots.

Limits, stated because they bound every clean result here: firmware that lies
in its own measurements (an implant below the first measured stage, SMM) is
invisible; a boot of other media leaves no Windows log at all; the sound of a
POST beep is never observed; UEFI variable contents, boot order and the EFI
partition need elevation and are not read. A drift is a difference to explain,
not a verdict: firmware and Windows updates change these values legitimately.
The baseline never advances by itself; only the owner accepts a new one.
"""
import calendar
import glob
import json
import os
import re
import time

from jarvis.core import bugcheck, collection
from jarvis.core.finding import win_finding
from jarvis.core.paths import load_win_script
from jarvis.platform import host
from jarvis.platform.windows import ps_json

from . import tcglog

PS_BOOT = load_win_script("boot_integrity.ps1")
LOG_DIR = os.path.join(host.windows_dir() or "/nonexistent", "Logs", "MeasuredBoot")
WHERE = "TPM measured boot"
BASELINE_KEY = "bootintegrity_baseline_v1"
MAX_LOGS = 64
_NAME = re.compile(r"^(\d{10})-(\d{10})\.log$")
# What each firmware PCR measures, for a finding a person can act on.
PCR_MEANING = {
    "0": "firmware code", "1": "firmware settings",
    "2": "option ROM and add-in card code", "3": "option ROM settings",
    "4": "boot manager code", "5": "boot configuration and disk layout",
    "6": "platform-specific events", "7": "Secure Boot policy",
}
PCR_SEVERITY = {"0": "high", "2": "high", "7": "medium", "4": "medium",
                "1": "medium", "3": "medium", "5": "medium", "6": "low"}
# Boot options that turn off a protection the rest of JARVIS relies on.
DANGEROUS_OPTIONS = ("TESTSIGNING", "NOINTEGRITYCHECKS", "DISABLE_INTEGRITY_CHECKS",
                     "BOOTDEBUG", "DEBUG", "NOEXECUTE=ALWAYSOFF",
                     "HYPERVISORLAUNCHTYPE=OFF", "DISABLEELAMDRIVERS")
# Kernel-Boot event 27 boot types: only a cold boot runs the whole chain.
COLD_BOOT = "0"
FRESH_LOG_SLACK_S = 15 * 60
# Kernel-Power 41 is written at the next boot, WER 1001 seconds later (15 s
# on this host 2026-10-30). Each 1001 absorbs at most one 41: the nearest one
# before it with the same code, inside this window, so a boot loop of
# identical crashes is never folded into one.
SAME_CRASH_S = 5 * 60
BUGCHECK_TITLE = {
    "integrity": "Windows stopped because protected kernel code or data changed",
    "hypervisor": "the hypervisor under Windows crashed",
    "security_check": "a kernel security check stopped Windows",
    "hardware": "a hardware error stopped Windows",
    "other": "Windows crashed with a stop error",
}


def _f(severity, title, detail, category="boot integrity"):
    return win_finding(category, severity, title, detail, where=WHERE)


def read_logs(directory=LOG_DIR):
    """Retained boots, oldest first: {boot, resume, mtime, summary|error}.

    A resume log (resume > 0) covers only the wake path, so only cold-boot logs
    are compared with each other and with the baseline.
    """
    rows = []
    for path in sorted(glob.glob(os.path.join(directory, "*.log")))[-MAX_LOGS:]:
        match = _NAME.match(os.path.basename(path))
        if not match:
            continue
        row = {"boot": int(match.group(1)), "resume": int(match.group(2))}
        try:
            row["mtime"] = os.path.getmtime(path)
            if os.path.getsize(path) > tcglog.MAX_LOG_BYTES:
                raise tcglog.LogError("log is over the size bound")
            with open(path, "rb") as fh:
                row["summary"] = tcglog.summary(fh.read())
        except (OSError, tcglog.LogError) as exc:
            row["error"] = str(exc)[:120]
        rows.append(row)
    return rows


def read_attestation(directory=LOG_DIR):
    """Windows' own pre-attestation verdict for the newest boot, or None."""
    files = sorted(glob.glob(os.path.join(directory, "*.json")))
    if not files:
        return None
    try:
        with open(files[-1], "rb") as fh:
            raw = fh.read(64 * 1024)
        text = raw.decode("utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff")
                          or b"\x00" in raw[:8] else "utf-8-sig")
        data = json.loads(text.lstrip("﻿"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    fields = {}
    for group in ("Required", "Expected", "Informational"):
        for row in data.get(group) or []:
            if isinstance(row, dict) and isinstance(row.get("Field"), str):
                fields[row["Field"]] = row.get("Value", row.get("ValueFromTcgLog"))
    return {"health": data.get("HealthStatus"), "fields": fields}


def _state(summary, firmware):
    return {"pcrs": summary["pcrs"], "option_roms": summary["option_roms"],
            "boot_apps": summary["boot_apps"], "variables": summary["variables"],
            "authorities": summary["authorities"],
            "firmware": (firmware or {}).get("version") or ""}


def drift(baseline, current, label):
    """Findings for every measured difference between two boot states."""
    out = []
    # The firmware version is only known for the running boot; an older
    # retained boot carries None and no version claim is made about it.
    known = bool(baseline.get("firmware")) and bool(current.get("firmware"))
    firmware_changed = known and baseline["firmware"] != current["firmware"]
    new_roms = sorted(set(current["option_roms"]) - set(baseline["option_roms"]))
    if new_roms:
        out.append(_f("high", "new option ROM or add-in card code ran before the OS",
                      f"{label}: {len(new_roms)} code image(s) not in the baseline were "
                      f"measured into PCR 2 (first {new_roms[0][:16]}). This is code from a "
                      "plug-in device or card, outside the system firmware"))
    for name in ("SecureBoot", "PK", "KEK", "db", "dbx"):
        old, new = baseline["variables"].get(name), current["variables"].get(name)
        if old == new:
            continue
        core = name in ("SecureBoot", "PK", "KEK")
        out.append(_f("high" if core else "medium",
                      f"Secure Boot variable {name} changed",
                      f"{label}: measured value {str(old)[:16]} -> {str(new)[:16]}. "
                      + ("This is the root of what firmware will trust to boot"
                         if core else "Windows updates this list, so confirm an update "
                         "was installed before accepting it")))
    new_apps = sorted(set(current["boot_apps"]) - set(baseline["boot_apps"]))
    if new_apps:
        out.append(_f("medium", "a boot application not in the baseline ran",
                      f"{label}: {len(new_apps)} EFI application(s) measured into PCR 4 "
                      f"are new (first {new_apps[0][:16]}). A Windows boot-manager update "
                      "does this; so does a bootkit or a boot from other media"))
    new_auth = sorted(set(current["authorities"]) - set(baseline["authorities"]))
    if new_auth:
        out.append(_f("medium", "a new Secure Boot signing authority was used",
                      f"{label}: {len(new_auth)} authority measurement(s) not in the "
                      "baseline authorised boot code"))
    explained = {"7"} if any("Secure Boot" in f["title"] or "authority" in f["title"]
                             for f in out) else set()
    if new_apps:
        explained.add("4")
    if new_roms:
        explained.add("2")
    for pcr in sorted(PCR_MEANING):
        if baseline["pcrs"].get(pcr) == current["pcrs"].get(pcr) or pcr in explained:
            continue
        severity, note = PCR_SEVERITY[pcr], ""
        if pcr == "0":
            if firmware_changed:
                severity = "medium"
                note = (f"; the firmware version also changed ({baseline.get('firmware')} "
                        f"-> {current.get('firmware')}), which a firmware update explains")
            elif known:
                note = "; the firmware version did not change, so an update does not explain it"
            else:
                note = "; the firmware version at that boot is not known"
        out.append(_f(severity, f"{PCR_MEANING[pcr]} measured differently (PCR {pcr})",
                      f"{label}: {baseline['pcrs'].get(pcr, '')[:16]} -> "
                      f"{current['pcrs'].get(pcr, '')[:16]}{note}"))
    if firmware_changed and not any("PCR 0" in f["title"] for f in out):
        out.append(_f("medium", "firmware version changed",
                      f"{label}: {baseline.get('firmware')} -> {current.get('firmware')} "
                      "with no change in the firmware code measurement"))
    return out


def _log_findings(logs, baseline, firmware):
    out = []
    cold = [row for row in logs if row["resume"] == 0 and "summary" in row]
    first, count = {}, {}
    for row in cold:
        if row["boot"] <= baseline["boot"]:
            continue
        state = _state(row["summary"], firmware if row is cold[-1] else None)
        for finding in drift(baseline["state"], state, f"boot {row['boot']}"):
            first.setdefault(finding["title"], finding)
            count[finding["title"]] = count.get(finding["title"], 0) + 1
    # One finding per difference, anchored at the first boot that showed it.
    for title, finding in first.items():
        if count[title] > 1:
            finding["detail"] += f"; also in {count[title] - 1} later boot(s)"
        out.append(finding)
    numbers = [row["boot"] for row in cold]
    gaps = [(a, b) for a, b in zip(numbers, numbers[1:]) if b - a > 1]
    if gaps:
        out.append(_f("low", "boot counter gap in the retained measured-boot logs",
                      f"{len(gaps)} gap(s), first between boot {gaps[0][0]} and "
                      f"{gaps[0][1]}: a boot happened with no retained Windows log. "
                      "Log pruning does this; so does starting something other than "
                      "this Windows installation"))
    return out, cold


def _event_findings(events, boots_seen):
    out = []
    by_id = {}
    for event in events:
        by_id.setdefault(event["id"], []).append(event)
    flagged = {}
    for event in by_id.get(27, []):
        options = (event["values"] + ["", ""])[1].upper()
        for flag in DANGEROUS_OPTIONS:
            if re.search(r"(^|\s)" + re.escape(flag) + r"(\s|$|=)", options):
                flagged.setdefault(flag, event["time"])
    for flag, when in sorted(flagged.items()):
        out.append(_f("high", "Windows booted with a protection turned off",
                      f"boot option {flag} was in effect (most recent {when[:19]}Z)"))
    waited = [e for e in by_id.get(32, []) if _int(e["values"][:1]) > 0]
    if waited:
        out.append(_f("medium", "the boot manager waited for someone at the keyboard",
                      f"{len(waited)} boot(s) in the retained events, most recent "
                      f"{waited[0]['time'][:19]}Z for {_int(waited[0]['values'][:1])} ms: "
                      "the Windows boot menu was shown or used. Firmware menus "
                      "(setup, boot-device selection) are not recorded here"))
    entries = {_int(e["values"][:1]) for e in by_id.get(18, [])}
    if entries and max(entries) > 1:
        out.append(_f("medium", "more than one boot entry is configured",
                      f"the boot manager reported up to {max(entries)} boot options; "
                      "an added entry can start another loader"))
    cold = [e for e in by_id.get(27, []) if (e["values"] + [""])[0] == COLD_BOOT]
    dirty = len(by_id.get(41, []))
    if dirty:
        out.append(_f("low", "unclean shutdowns before recent boots",
                      f"{dirty} power-loss or hard-reset record(s) against {len(cold)} "
                      f"cold boot(s) in the retained events, most recent "
                      f"{by_id[41][0]['time'][:19]}Z. A forced power-off precedes a boot "
                      "from other media as well as a crash or a drained battery"))
    whea = [e for e in events if e["source"] == "WHEA-Logger"]
    if whea:
        out.append(_f("low", "hardware errors were recorded",
                      f"{len(whea)} hardware error record(s), most recent "
                      f"{whea[0]['time'][:19]}Z"))
    boots_seen["cold"] = len(cold)
    boots_seen["last"] = max((e["time"] for e in by_id.get(12, [])), default="")
    return out


def _epoch(iso):
    try:
        return calendar.timegm(time.strptime(str(iso)[:19], "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return None


def crashes(events):
    """Stop errors in the retained events, newest first: {time, code, params, dump}.

    WER 1001 carries the parameters and dump; a Kernel-Power 41 with a nonzero
    BugcheckCode counts on its own only when no 1001 records the same crash
    (WER can fail to run). Malformed values are dropped, never read as clean.
    """
    out, wer = [], []
    for e in events:
        if e["id"] == 1001 and e["source"] == "WER-SystemErrorReporting":
            parsed = bugcheck.from_wer((e["values"] + [""])[0])
            if parsed:
                dump = os.path.basename(str((e["values"] + ["", ""])[1]).replace("\\", "/"))
                wer.append({"time": e["time"], "code": parsed[0], "params": parsed[1],
                            "dump": dump})
    out.extend(wer)
    power = []
    for e in events:
        if e["id"] != 41 or e["source"] != "Kernel-Power":
            continue
        code = bugcheck.from_kernel_power((e["values"] + [""])[0])
        at = _epoch(e["time"])
        if code is not None and at is not None:
            power.append({"time": e["time"], "at": at, "code": code})
    for w in wer:
        at = _epoch(w["time"])
        near = [p for p in power if at is not None and p["code"] == w["code"]
                and 0 <= at - p["at"] <= SAME_CRASH_S]
        if near:
            power.remove(max(near, key=lambda p: p["at"]))
    out.extend({"time": p["time"], "code": p["code"], "params": [], "dump": ""} for p in power)
    return sorted(out, key=lambda c: c["time"], reverse=True)


def _bugcheck_findings(events):
    by_class = {}
    for crash in crashes(events):
        by_class.setdefault(bugcheck.describe(crash["code"])[1], []).append(crash)
    out = []
    for kind, found in by_class.items():
        severity, meaning = bugcheck.CLASSES[kind]
        if kind in bugcheck.BELOW_KERNEL and len(found) > 1:
            severity = "high"
        last = found[0]
        codes = sorted({bugcheck.label(c["code"]) for c in found})
        params = f" parameters {', '.join(last['params'])};" if last["params"] else ""
        dump = f" dump {last['dump']};" if last["dump"] else " no dump recorded;"
        out.append(_f(severity, BUGCHECK_TITLE[kind],
                      f"{len(found)} stop error(s): {'; '.join(codes)}. {meaning}. Most recent "
                      f"recorded at the restart {last['time'][:19]}Z (the crash itself was "
                      f"earlier);{params}{dump} a stop error is not a compromise verdict: "
                      "only analysis of the dump names what faulted. Memory integrity "
                      "and Credential Guard run on the hypervisor, so their state is "
                      "checked separately"))
    return out


def _int(values):
    try:
        return int(values[0])
    except (IndexError, TypeError, ValueError):
        return 0


def _platform_findings(data):
    out = []
    sb, tpm, guard = data["secureBoot"], data["tpm"], data["deviceGuard"]
    if sb.get("enabled") != 1:
        out.append(_f("high", "Secure Boot is not enabled",
                      "Windows reports Secure Boot off or unreadable, so unsigned "
                      "boot code is not refused by the firmware"))
    if sb.get("dbxError"):
        out.append(_f("medium", "the Secure Boot revocation list failed to update",
                      f"last dbx update error 0x{int(sb['dbxError']) & 0xffffffff:08X} "
                      f"({sb.get('dbxErrorReason') or 'no reason given'}): boot loaders "
                      "revoked for known bypasses may still be trusted by this firmware"))
    if tpm.get("TPM Present") != "True":
        out.append(_f("high", "no TPM is reported",
                      "without a TPM the measured-boot evidence cannot be trusted"))
    if tpm.get("TPM Has Vulnerable Firmware") == "True":
        out.append(_f("high", "the TPM firmware is reported vulnerable",
                      "Windows flags this TPM firmware version as vulnerable"))
    if tpm.get("Bitlocker PCR7 Binding State") not in (None, "Bound"):
        out.append(_f("medium", "disk encryption is not bound to Secure Boot state",
                      f"PCR 7 binding state: {tpm['Bitlocker PCR7 Binding State']}"))
    if tpm.get("Lockout Counter") not in (None, "0"):
        out.append(_f("medium", "the TPM recorded failed authorisation attempts",
                      f"lockout counter {tpm['Lockout Counter']}"))
    if not guard or guard.get("vbs") != 2:
        out.append(_f("medium", "virtualization-based security is not running",
                      "the hypervisor-protected kernel integrity checks are off"))
    elif 2 not in guard.get("running", []):
        out.append(_f("low", "memory integrity (HVCI) is not running",
                      "virtualization-based security runs without code integrity"))
    return out


def _valid(data):
    if not isinstance(data, dict):
        return False
    if not all(isinstance(data.get(k), dict) for k in ("secureBoot", "tpm")):
        return False
    if not isinstance(data.get("errors"), list) or not isinstance(data.get("events"), list):
        return False
    if len(data["events"]) > 2000 or not isinstance(data.get("deviceGuard"), (dict, type(None))):
        return False
    if not isinstance(data.get("firmware"), (dict, type(None))):
        return False
    return all(isinstance(e, dict) and isinstance(e.get("id"), int)
               and isinstance(e.get("time"), str) and isinstance(e.get("source"), str)
               and isinstance(e.get("values"), list) and len(e["values"]) <= 4
               and all(isinstance(v, str) and len(v) <= 200 for v in e["values"])
               for e in data["events"])


def load_baseline(store):
    try:
        value = json.loads(store.get_meta(BASELINE_KEY, "") or "null")
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) and isinstance(value.get("state"), dict) else None


def accept_baseline(store, logs=None, firmware=None, now=None):
    """Pin the newest cold boot as the baseline. Owner action only."""
    logs = read_logs() if logs is None else logs
    cold = [row for row in logs if row["resume"] == 0 and "summary" in row]
    if not cold:
        return None
    if firmware is None:
        data = ps_json(PS_BOOT, timeout=90)
        firmware = data.get("firmware") if _valid(data) else None
    baseline = {"boot": cold[-1]["boot"], "state": _state(cold[-1]["summary"], firmware),
                "accepted": int(time.time() if now is None else now)}
    store.set_meta(BASELINE_KEY, json.dumps(baseline))
    store.commit()
    return baseline


def audit(store, hosts=("wsl", "win"), directory=LOG_DIR):
    if "win" not in hosts:
        collection.failed("preos", "Windows collection disabled")
        return [_f("medium", "pre-OS boot integrity is not monitored",
                   "Windows collection is disabled", "visibility")]
    problems, findings = [], []
    logs = read_logs(directory)
    unreadable = [row for row in logs if "error" in row]
    cold = [row for row in logs if row["resume"] == 0 and "summary" in row]
    data = ps_json(PS_BOOT, timeout=90)
    if not _valid(data):
        problems.append("boot event and firmware probe returned no valid result")
        data = None
    elif data["errors"]:
        problems.append("; ".join(sorted(set(map(str, data["errors"])))[:4]))
    firmware = data.get("firmware") if data else None

    if not cold:
        problems.append("no readable cold-boot measured-boot log")
    if unreadable:
        problems.append(f"{len(unreadable)} measured-boot log(s) could not be parsed")
        findings.append(_f("medium", "a measured-boot log could not be parsed",
                           f"{len(unreadable)} log(s), first boot {unreadable[0]['boot']}: "
                           f"{unreadable[0]['error']}. An unparsed boot is not a clean boot",
                           "visibility"))

    baseline = load_baseline(store)
    if cold and baseline is None and data is not None:
        # First run: pin the oldest retained cold boot so every later retained
        # boot is compared against it now, not from today onward.
        baseline = {"boot": cold[0]["boot"],
                    "state": _state(cold[0]["summary"], firmware),
                    "accepted": int(time.time()), "automatic": True}
        store.set_meta(BASELINE_KEY, json.dumps(baseline))
    seen = {}
    if cold and baseline:
        found, _ = _log_findings(logs, baseline, firmware)
        findings.extend(found)
    if data:
        findings.extend(_platform_findings(data))
        findings.extend(_event_findings(data["events"], seen))
        findings.extend(_bugcheck_findings(data["events"]))
        # Freshness: Windows booted after the newest log was written.
        if cold and seen.get("last"):
            try:
                booted = calendar.timegm(time.strptime(seen["last"][:19], "%Y-%m-%dT%H:%M:%S"))
            except ValueError:
                booted = 0
            newest = max(row.get("mtime", 0) for row in logs)
            if booted and booted - newest > FRESH_LOG_SLACK_S:
                problems.append("the current boot has no measured-boot log")
                findings.append(_f("medium", "the current boot left no measured-boot log",
                                   f"Windows started {seen['last'][:19]}Z but the newest log "
                                   "is older, so this boot was not compared", "visibility"))
    attestation = read_attestation(directory)
    if attestation is None:
        problems.append("Windows attestation verdict unreadable")
    elif (attestation["health"] != "Attestable"
          or attestation["fields"].get("PcrsMatchTcgLog") is not True):
        findings.append(_f("high", "the TPM does not match the measured-boot log",
                           f"Windows health status {attestation['health']!r}, "
                           f"PcrsMatchTcgLog={attestation['fields'].get('PcrsMatchTcgLog')!r}: "
                           "the log cannot be trusted as a record of this boot"))

    if problems:
        collection.failed("preos", "; ".join(problems)[:300])
        findings.append(_f("medium", "pre-OS boot evidence is incomplete",
                           "; ".join(problems)[:300], "visibility"))
    else:
        collection.succeeded("preos")
    if cold and baseline:
        findings.append(_f(
            "ok" if not problems else "low", "pre-OS boot inventory",
            f"{len(cold)} cold boot(s) and {len(logs) - len(cold) - len(unreadable)} "
            f"resume(s) replayed (boots {cold[0]['boot']}-{cold[-1]['boot']}), compared "
            f"with the baseline pinned at boot {baseline['boot']}; firmware "
            f"{(firmware or {}).get('vendor', '?')} {(firmware or {}).get('version', '?')}. "
            "Not seen: firmware that falsifies its own measurements, boots of other "
            "media, firmware setup or boot-device menus, and the POST beep itself"))
    return findings
