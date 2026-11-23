"""Hash-chained WSL boundary checkpoints and drift comparison (pure).

Invariants:
- A checkpoint is only ever appended by an explicit call; comparison never
  rebaselines, so drift cannot be absorbed into a new normal silently.
- A broken chain, or a fact that was known and is now unreadable, is reported
  as such and never as "no drift".
- A different boot id makes a difference OFFLINE_STATE_DRIFT: the change
  happened while nothing was observing. Same boot is runtime STATE_DRIFT.
- The local chain proves internal consistency only, not tamper resistance;
  it needs an independently protected anchor for that.
"""

import hashlib
import json

GENESIS = "0" * 64
MAX_ENTRIES = 256
# Changes here alter the trust boundary itself and are marked critical.
CRITICAL_PREFIXES = ("wslconfig.wsl2.kernel", "wslconfig.wsl2.kernelcommandline",
                     "wslconfig.wsl2.kernelmodules", "wslconfig.wsl2.networkingmode",
                     "wslconfig.wsl2.firewall", "wsl_conf.interop.",
                     "wsl_conf.automount.", "wsl_conf.boot.command",
                     "interop.binfmt", "docker.socket", "kernel.release",
                     "drvfs.mount[", "path.windows_dirs")


def _hash(body):
    blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def critical(name):
    return name.startswith(CRITICAL_PREFIXES)


def usable_facts(snap):
    """Facts from sources that read cleanly, plus the names of unreadable ones."""
    facts, unknown = {}, []
    for name, src in (snap.get("sources") or {}).items():
        if src.get("status") in ("current", "absent"):
            facts.update(src.get("facts") or {})
        else:
            unknown.append(name)
    return facts, sorted(unknown)


def make_entry(snap, prev=None, *, accepted_by="owner"):
    facts, unknown = usable_facts(snap)
    if not snap.get("boot_id"):
        raise ValueError("boot id unknown; refusing to checkpoint")
    body = {"seq": (prev["seq"] + 1) if prev else 1,
            "boot_id": snap["boot_id"], "facts": facts,
            "unknown_sources": unknown, "accepted_by": accepted_by,
            "prev_hash": prev["entry_hash"] if prev else GENESIS}
    return {**body, "entry_hash": _hash(body)}


def verify_chain(entries):
    """(ok, reason). Empty is valid: it means no baseline, handled by compare."""
    prev_hash, seq = GENESIS, 0
    if len(entries) > MAX_ENTRIES:
        return False, "too many entries"
    for entry in entries:
        try:
            body = {k: v for k, v in entry.items() if k != "entry_hash"}
            if entry["seq"] != seq + 1 or entry["prev_hash"] != prev_hash:
                return False, f"chain break at seq {entry.get('seq')}"
            if _hash(body) != entry["entry_hash"]:
                return False, f"entry {entry['seq']} altered"
        except (KeyError, TypeError, AttributeError):
            return False, "malformed entry"
        prev_hash, seq = entry["entry_hash"], entry["seq"]
    return True, "ok"


def compare(entries, snap, *, limit=100):
    ok, reason = verify_chain(entries)
    if not ok:
        return {"status": "checkpoint_invalid", "reason": reason, "findings": []}
    if not entries:
        return {"status": "no_baseline", "findings": [],
                "reason": "no accepted checkpoint; nothing to compare against"}
    base = entries[-1]
    now, unknown_now = usable_facts(snap)
    offline = bool(snap.get("boot_id")) and snap["boot_id"] != base["boot_id"]
    kind = "OFFLINE_STATE_DRIFT" if offline else "STATE_DRIFT"
    findings = []
    for name in sorted(set(base["facts"]) | set(now)):
        before, after = base["facts"].get(name), now.get(name)
        if before == after:
            continue
        if before is None:
            change = "added"
        elif after is None:
            # Missing because its source is unreadable is lost evidence, not removal.
            change = "unobserved" if _source_unreadable(name, snap) else "removed"
        else:
            change = "changed"
        if change == "unobserved":
            kind_for = "EVIDENCE_LOST"
        else:
            kind_for = kind
        findings.append({"kind": kind_for, "fact": name, "change": change,
                         "before": before, "after": after,
                         "critical": critical(name)})
    for name in unknown_now:
        if name in base.get("unknown_sources", []):
            continue
        findings.append({"kind": "EVIDENCE_LOST", "fact": f"source:{name}",
                         "change": "unobserved", "before": None, "after": None,
                         "critical": False})
    drift = any(f["kind"] != "EVIDENCE_LOST" for f in findings)
    lost = any(f["kind"] == "EVIDENCE_LOST" for f in findings)
    return {"status": "drift" if drift else ("evidence_lost" if lost else "matches_checkpoint"),
            "offline": offline, "baseline_seq": base["seq"],
            "baseline_boot_id": base["boot_id"],
            "findings": findings[:limit],
            "findings_truncated": len(findings) > limit}


def _source_unreadable(name, snap):
    """Unreadable sources carry no facts, so map fact prefixes to source names."""
    mapping = {"wsl_conf": "wsl_conf", "wslconfig": "windows_wslconfig",
               "drvfs": "drvfs", "interop": "interop", "path": "path",
               "docker": "docker_socket", "kernel": "kernel"}
    src_name = mapping.get(name.split(".", 1)[0].split("[", 1)[0])
    src = (snap.get("sources") or {}).get(src_name) or {}
    return src.get("status") not in ("current", "absent")
