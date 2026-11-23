"""Evidence custody: an append-only vault and public timestamp anchors.

The authoritative event log lives in a directory this account can rewrite, so
by itself it cannot prove it was not rewritten. This job adds two independent
witnesses and checks the live history against both:

* Vault. Sealed segments, the chain file and anchor records are staged in an
  untrusted inbox; the elevated broker's vault job moves them into
  C:\\ProgramData\\Jarvis\\Vault, which only Administrators and SYSTEM can
  modify, and which only ever grows. Malware running as the user cannot
  change what was vaulted, so a live history that disagrees with the vault
  was rewritten after it was vaulted.
* Anchors. A digest of the current chain heads is timestamped through public
  OpenTimestamps calendars and, once upgraded, committed to Bitcoin. Only the
  32-byte digest leaves the machine. Even an administrator cannot make a
  rewritten history match an anchor that predates the rewrite, as long as
  one copy of the anchor record survives (live, vault, or wherever the owner
  keeps the .ots files).

It also compares the running Sysmon configuration with the reviewed baseline.
Nothing here deletes evidence: the inbox only receives copies, and staged
copies are removed only after the vault holds identical bytes.
"""

import gzip
import hashlib
import json
import os
import shutil
import time
from pathlib import Path

from jarvis.collectors.telemetry import sysmon_policy
from jarvis.core import inflate, pagecache
from jarvis.core.eventlog import (
    DEFAULT_ROOT,
    GENESIS,
    MAX_HEADER_LINE,
    MAX_SEGMENT_PLAIN,
    EventLog,
    LogError,
    header_hash,
)
from jarvis.core.finding import finding
from jarvis.platform import broker, timestamps
from jarvis.platform.mounts import WINDOWS_DRIVE

META = "evidence_v1"
# The inbox sits in the user's own profile, so other local accounts cannot
# read staged history; the broker (the same user, elevated) can.
INBOX = None
VAULT = Path(WINDOWS_DRIVE) / "ProgramData/Jarvis/Vault"
ANCHORS = Path(os.path.expanduser("~/.jarvis/anchors"))
ANCHOR_EVERY = 6 * 3600          # a new anchor at most this often, if the head moved
UPGRADE_AFTER = 2 * 3600         # calendars need a few blocks before a Bitcoin proof exists
UPGRADES_PER_RUN = 4
FULL_VERIFY_EVERY = 86400        # re-hash every vaulted payload daily; new ones every run
# The daily re-hash used to run as one pass over the whole vault (1.8 GB read
# back over the Windows drive: 25 minutes on 2026-11-02, the bulk lane blocked
# and the page cache filled). It now runs as a rolling slice: each run
# re-hashes a share of the already verified segments proportional to the time
# since the previous run, so every vaulted segment is still re-hashed within
# FULL_VERIFY_EVERY, whatever the cadence or a missed run. MAX_RECHECK bounds
# one run after a long absence; the next runs continue from the cursor.
MAX_RECHECK = 400


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _name(segment):
    return f"{int(segment):012d}.jseg"


def _jsonl(path):
    out = []
    try:
        with open(path, "rb") as fh:
            for line in fh:
                if not line.endswith(b"\n"):
                    break
                out.append(json.loads(line))
    except FileNotFoundError:
        pass
    return out


def _copy_atomic(source, target):
    temp = target.with_name(target.name + ".tmp")
    shutil.copyfile(source, temp)
    os.replace(temp, target)


# -- staging -----------------------------------------------------------------

def stage(root, inbox, vault, anchors, pruned):
    """Copy what the vault lacks into the inbox. Returns counts."""
    out = {"staged_segments": 0, "cleaned": 0, "staged_anchors": 0}
    segments = inbox / "eventlog" / "segments"
    segments.mkdir(parents=True, exist_ok=True)
    (inbox / "anchors").mkdir(parents=True, exist_ok=True)
    vaulted = {h.get("segment") for h in _jsonl(vault / "eventlog" / "chain.jsonl")}
    chain = _jsonl(Path(root) / "chain.jsonl")
    for header in chain:
        n = header.get("segment")
        name = _name(n)
        staged = segments / name
        if n in vaulted:
            kept = vault / "eventlog" / "segments" / name
            if staged.exists() and kept.exists() and _sha256_file(staged) == _sha256_file(kept):
                staged.unlink()
                out["cleaned"] += 1
            continue
        live = Path(root) / "segments" / name
        if n in pruned:
            marker = segments / (name + ".pruned")
            if not marker.exists():
                marker.write_text("removed by retention before it was vaulted\n")
        elif live.exists() and not staged.exists():
            _copy_atomic(live, staged)
            out["staged_segments"] += 1
    # The chain is appended only after its segment files: the vault job waits
    # for a staged segment rather than record a header it cannot back.
    source_chain = Path(root) / "chain.jsonl"
    if source_chain.exists():
        _copy_atomic(source_chain, inbox / "eventlog" / "chain.jsonl")
    for record in sorted(anchors.glob("*")) if anchors.exists() else ():
        target = inbox / "anchors" / record.name
        if record.is_file() and not target.exists():
            _copy_atomic(record, target)
            out["staged_anchors"] += 1
    return out


# -- vault verification --------------------------------------------------------

def recheck_slice(verified_through, cursor, elapsed, every=FULL_VERIFY_EVERY, cap=MAX_RECHECK):
    """(segment numbers to re-hash this run, next cursor). Pure.

    Walks 1..verified_through cyclically from `cursor`, taking
    ceil(verified_through * elapsed / every) segments (at least one, at most
    `cap` and the whole range)."""
    total = int(verified_through or 0)
    if total <= 0:
        return [], 1
    want = -(-total * max(0.0, float(elapsed)) // every) if every > 0 else total
    count = int(max(1, min(total, cap, want)))
    start = int(cursor) if 1 <= int(cursor or 0) <= total else 1
    picks = [((start - 1 + i) % total) + 1 for i in range(count)]
    return picks, (picks[-1] % total) + 1


def verify_vault(live_chain, vault, verified_through=0, full=False, pruned=(), recheck=()):
    """Compare the vault with the live chain and hash vaulted payloads.

    Returns {"problems": [...], "divergent": [...], "verified_through": n,
    "vaulted": count}. `divergent` lists segments whose live header differs
    from the vaulted one: the live history was rewritten after vaulting (or
    the vault was altered by an administrator; anchors tell which).
    """
    problems, divergent = [], []
    recheck = frozenset(recheck)
    rechecked = 0
    vchain = _jsonl(vault / "eventlog" / "chain.jsonl")
    live = {h.get("segment"): h for h in live_chain}
    unvaulted = set()
    try:
        with open(vault / "eventlog" / "unvaulted.txt", encoding="utf-8", errors="replace") as fh:
            unvaulted = {line.split()[0] for line in fh if line.strip()}
    except FileNotFoundError:
        pass
    prev = GENESIS
    # Payload hashing advances only over a contiguous verified prefix.
    through = 0 if full else verified_through
    for i, header in enumerate(vchain):
        n = header.get("segment")
        if n != i + 1:
            problems.append(f"vaulted segment {n}: out of order")
        if header.get("previous_hash") != prev or header_hash(header) != header.get("hash"):
            problems.append(f"vaulted segment {n}: header altered or unlinked")
        prev = header.get("hash")
        mine = live.get(n)
        if mine is None or mine != header:
            divergent.append(n)
        name = _name(n)
        path = vault / "eventlog" / "segments" / name
        if name in unvaulted:
            # The inbox is untrusted: a "removed by retention" claim must
            # match the live log's own retention record.
            if n not in pruned:
                problems.append(f"vaulted segment {n}: skipped as pruned, but the "
                                "event log never recorded pruning it")
            through = n if through == n - 1 else through
            continue
        if not path.exists():
            problems.append(f"vaulted segment {n}: payload missing from the vault")
            continue
        if n <= through and n not in recheck:
            continue
        try:
            with open(path, "rb") as raw, gzip.open(raw, "rb") as fh:
                try:
                    stored = json.loads(inflate.readline(fh, MAX_HEADER_LINE))
                    hasher = hashlib.sha256()
                    for block in inflate.chunks(fh, MAX_SEGMENT_PLAIN):
                        hasher.update(block)
                    digest = hasher.hexdigest()
                finally:
                    pagecache.drop(raw)
        except (OSError, ValueError, EOFError) as exc:
            problems.append(f"vaulted segment {n}: unreadable ({type(exc).__name__})")
            continue
        if stored != header or digest != header.get("payload_sha256"):
            problems.append(f"vaulted segment {n}: payload or header does not match its chain entry")
            continue
        through = n if through == n - 1 else through
        rechecked = rechecked + 1 if n in recheck else rechecked
    return {"problems": problems, "divergent": divergent,
            "verified_through": through, "vaulted": len(vchain), "rechecked": rechecked}


# -- anchors ---------------------------------------------------------------------

def manifest(live_head, vault_state, policy_hash, now):
    return {"v": 1, "at": int(now),
            "eventlog": {"segment": live_head.get("segment"), "hash": live_head.get("hash"),
                         "last_seq": live_head.get("last_seq")},
            "vault": {"segment": vault_state.get("head_segment"),
                      "hash": vault_state.get("head_hash")},
            "sysmon_config_sha256": policy_hash}


def _records(*dirs):
    """{digest: manifest} from every copy of the anchor records."""
    out = {}
    for directory in dirs:
        if not directory.exists():
            continue
        for path in directory.glob("*.json"):
            digest = path.name.split(".")[0]
            try:
                body = path.read_bytes()
                record = json.loads(body)
            except (OSError, ValueError):
                out.setdefault(digest, None)
                continue
            if hashlib.sha256(body).hexdigest() != digest:
                out[digest] = None          # renamed or edited: not a valid record
            else:
                out.setdefault(digest, record)
    return out


def check_anchors(records, live_chain):
    """Anchored heads the live chain no longer contains."""
    heads = {(h.get("segment"), h.get("hash")) for h in live_chain}
    broken, invalid = [], []
    for digest, record in records.items():
        if record is None:
            invalid.append(digest)
            continue
        head = record.get("eventlog") or {}
        if head.get("segment") and (head.get("segment"), head.get("hash")) not in heads:
            broken.append({"digest": digest, "segment": head.get("segment"),
                           "at": record.get("at")})
    return broken, invalid


def _proof_state(directory, digest):
    """(best proof path, bitcoin heights) for one anchor digest."""
    best, heights = None, []
    for path in sorted(directory.glob(digest + "*.ots")):
        try:
            _digest, node = timestamps.parse_file(path.read_bytes())
        except (OSError, timestamps.ProofError):
            continue
        found = [(detail, msg) for kind, detail, msg in timestamps.attestations(node)
                 if kind == "bitcoin"]
        if found or best is None:
            best, heights = path, found or heights
    return best, heights


def anchor(anchors, live_head, vault_state, policy_hash, last, now, network=True,
           submit=None):
    """Write a new anchor when due. Returns (digest or None, error)."""
    if not network or not live_head.get("hash"):
        return None, None
    if last and last.get("hash") == live_head.get("hash"):
        return None, None
    if last and now - last.get("at", 0) < ANCHOR_EVERY:
        return None, None
    record = manifest(live_head, vault_state, policy_hash, now)
    body = _canonical(record).encode()
    digest = hashlib.sha256(body).digest()
    try:
        proof, _calendars = (submit or timestamps.submit)(digest)
    except timestamps.ProofError as exc:
        return None, str(exc)
    anchors.mkdir(parents=True, exist_ok=True)
    (anchors / f"{digest.hex()}.json").write_bytes(body)
    (anchors / f"{digest.hex()}.ots").write_bytes(proof)
    return digest.hex(), None


def upgrade_proofs(anchors, records, now, network=True, upgrade=None, verify=None):
    """Fetch Bitcoin proofs for pending anchors. -> (confirmed, pending, bad)."""
    upgrade = upgrade or timestamps.upgrade
    verify = verify or timestamps.verify_bitcoin
    confirmed, pending, bad = [], [], []
    budget = UPGRADES_PER_RUN
    for digest, record in sorted(records.items(), key=lambda kv: (kv[1] or {}).get("at", 0)):
        if record is None:
            continue
        best, heights = _proof_state(anchors, digest)
        if best is None:
            continue
        if not heights and network and budget and now - record.get("at", now) >= UPGRADE_AFTER:
            budget -= 1
            try:
                data, changed = upgrade(best.read_bytes())
            except (OSError, timestamps.ProofError):
                changed = False
            if changed:
                # A new file: records are append-only, and the vault never
                # replaces a file it already holds.
                target = anchors / f"{digest}.btc.ots"
                if not target.exists():
                    target.write_bytes(data)
                best, heights = _proof_state(anchors, digest)
        if not heights:
            pending.append(digest)
            continue
        height, msg = heights[0]
        verdict = verify(height, msg) if network else None
        if verdict is False:
            bad.append({"digest": digest, "height": height})
        else:
            confirmed.append({"digest": digest, "height": height,
                              "checked": verdict is True})
    return confirmed, pending, bad


# -- the job -----------------------------------------------------------------------

def _load(store):
    try:
        state = json.loads(store.get_meta(META) or "null")
    except (TypeError, ValueError):
        state = None
    return state if isinstance(state, dict) else {}


def default_inbox():
    """%LOCALAPPDATA%\\Jarvis\\VaultInbox of the Windows user, or None."""
    users = Path(WINDOWS_DRIVE) / "Users"
    name = os.environ.get("JARVIS_WINDOWS_USER") or os.environ.get("USER", "")
    for candidate in (users / name, *(sorted(users.glob("*")) if users.is_dir() else ())):
        local = candidate / "AppData" / "Local"
        if local.is_dir() and os.access(local, os.W_OK):
            return local / "Jarvis" / "VaultInbox"
    return None


def audit(store, hosts=("win",), root=DEFAULT_ROOT, inbox=INBOX, vault=VAULT,
          anchors=ANCHORS, now=None, network=True, policy=None, vault_job=None):
    now = time.time() if now is None else now
    inbox = inbox or default_inbox()
    previous = _load(store)
    state = {"at": int(now)}
    out = []
    try:
        with EventLog(root) as log:
            live_chain = list(log.chain)
            pruned = log._pruned()
            live_head = log.head() or {}
    except (LogError, OSError) as exc:
        state["error"] = f"event log unreadable: {type(exc).__name__}"
        store.set_meta(META, json.dumps(state, sort_keys=True))
        store.commit()
        return [finding("visibility", "medium", "Evidence custody could not read the event log",
                        state["error"], str(root))]
    if live_chain:
        live_head = dict(live_head, last_seq=live_chain[-1].get("last_seq"))

    windows = ("win" in (hosts or ()) and Path(WINDOWS_DRIVE).is_dir()
               and inbox is not None)
    if windows:
        try:
            state["staging"] = stage(root, inbox, vault, anchors, pruned)
        except OSError as exc:
            state["staging_error"] = type(exc).__name__
            out.append(finding("visibility", "medium", "Evidence could not be staged for the vault",
                               f"{type(exc).__name__} writing {inbox}", str(inbox)))

    # The broker's own report of the vault job.
    if vault_job is None:
        data, why = broker.result("vault", now=now) if windows else (None, "Windows not selected")
    else:
        data, why = vault_job
    vault_state = data if isinstance(data, dict) else {}
    state["vault_job"] = {k: vault_state.get(k) for k in (
        "ok", "vaulted_segments", "head_segment", "new_segments", "diverged",
        "divergence", "pending", "bytes", "full", "error")} if data else {"unavailable": why}
    if windows and data is None:
        out.append(finding(
            "visibility", "low", "Evidence vault job is not running",
            f"{why}. Sealed history is not being copied into the administrator-only "
            "vault; run `jarvis broker install` to stage the vault job.", str(vault)))
    elif data is not None:
        if vault_state.get("error"):
            out.append(finding("visibility", "medium", "Evidence vault job failed",
                               str(vault_state["error"])[:300], str(vault)))
        if vault_state.get("diverged"):
            out.append(finding(
                "tampering", "critical", "Event history no longer extends its vaulted copy",
                f"{vault_state.get('divergence')}. The live chain was rewritten after it "
                "was vaulted, or the staged copy was forged. The vault kept its copy and "
                "stored the conflicting chain under divergence\\. Preserve both.",
                str(vault)))
        if vault_state.get("full"):
            out.append(finding("visibility", "medium", "Evidence vault reached its size budget",
                               "New segments are no longer vaulted; nothing was deleted.",
                               str(vault)))

    # Independent read-only verification of the vault's contents.
    if windows and (vault / "eventlog" / "chain.jsonl").exists():
        done = int(previous.get("verified_through", 0) or 0)
        # A first run (nothing verified yet) hashes everything; afterwards the
        # daily re-hash is spread over the runs (recheck_slice).
        full = done == 0
        elapsed = now - float(previous.get("at") or (now - FULL_VERIFY_EVERY))
        picks, cursor = recheck_slice(done, previous.get("recheck_cursor", 1), elapsed)
        result = verify_vault(live_chain, vault, done, full, pruned=pruned, recheck=picks)
        state["verified_through"] = result["verified_through"]
        state["vaulted"] = result["vaulted"]
        state["recheck_cursor"] = cursor
        state["rechecked"] = len(picks)
        # The moment the rolling re-check last completed a whole cycle.
        wrapped = full or (picks and cursor <= picks[0])
        state["full_verify_at"] = now if wrapped else previous.get("full_verify_at", 0)
        if result["divergent"]:
            out.append(finding(
                "tampering", "critical", "Event history differs from its vaulted copy",
                f"Segments {result['divergent'][:10]} in the live history do not match the "
                "administrator-only vault. Preserve the event log and the vault before "
                "anything else writes to them.", str(vault)))
        if result["problems"]:
            out.append(finding(
                "tampering", "high", "Evidence vault contents do not verify",
                "; ".join(result["problems"][:5]), str(vault)))

    # Running Sysmon configuration vs the reviewed baseline.
    policy = sysmon_policy.audit(now=now) if policy is None else policy
    baseline = sysmon_policy.baseline_sha256()
    state["sysmon"] = {"running": policy.get("config_hash"), "baseline": baseline,
                       "state": sysmon_policy.drift(policy, baseline)}
    if state["sysmon"]["state"] == "drift":
        # Not "visibility": that category marks this job's own coverage
        # incomplete, and the job saw the drift perfectly well.
        out.append(finding(
            "sensor policy", "high", "Sysmon is not running the reviewed baseline",
            f"running config SHA-256 {policy.get('config_hash')}, baseline "
            f"{baseline}. Either the baseline changed and has not been applied "
            "(scripts/repair/apply-jarvis-sysmon-policy.ps1) or something replaced the "
            "active Sysmon rules.", "windows-sysmon/jarvis-windows-baseline.xml"))

    # Anchors: every surviving record must still name a head in the live chain.
    records = _records(anchors, vault / "anchors")
    broken, invalid = check_anchors(records, live_chain)
    if broken:
        out.append(finding(
            "tampering", "critical", "Event history was rewritten after it was anchored",
            f"{len(broken)} timestamped chain head(s) are no longer in the live history "
            f"(first: segment {broken[0]['segment']}). The anchored digests are public "
            "and cannot be altered; preserve the event log, vault and anchors.",
            str(anchors)))
    if invalid:
        out.append(finding("tampering", "high", "Anchor records were altered",
                           f"{len(invalid)} anchor record(s) no longer match their digest.",
                           str(anchors)))
    last = max((r for r in records.values() if r), key=lambda r: r.get("at", 0), default=None)
    last_head = {"hash": (last or {}).get("eventlog", {}).get("hash"),
                 "at": (last or {}).get("at", 0)} if last else None
    created, error = anchor(anchors, live_head, vault_state, policy.get("config_hash"),
                            last_head, now, network=network)
    if created:
        records = _records(anchors, vault / "anchors")
    confirmed, pending, bad = upgrade_proofs(anchors, records, now, network=network)
    state["anchors"] = {"records": len(records), "created": created, "error": error,
                        "confirmed": len(confirmed), "pending": len(pending),
                        "latest_confirmed_height": max((c["height"] for c in confirmed), default=None)}
    if bad:
        out.append(finding(
            "tampering", "critical", "Anchor proof does not match the Bitcoin block it names",
            f"{len(bad)} proof(s), e.g. block {bad[0]['height']}.", str(anchors)))
    if error and network and not records:
        out.append(finding("visibility", "medium", "Evidence could not be timestamped",
                           f"{error}. History has no external anchor yet.", str(anchors)))

    store.set_meta(META, json.dumps(state, sort_keys=True))
    store.commit()
    return out


def summary(store):
    state = _load(store)
    return state or None
