"""Pure, coverage-gated Linux process reconciliation.

A snapshot comparison identifies changed state, not missed short-lived tasks.
Only a complete, continuous, same-boot lifecycle source that predates a task
may contradict an unpaired /proc instance. A missing source means unknown.
"""


def reconcile(current, *, previous=None, lifecycle=None, limit=100):
    if not 1 <= limit <= 1000:
        raise ValueError("limit out of range")
    rows = (current or {}).get("processes") or []
    before = {p["key"]: p for p in (previous or {}).get("processes") or []
              if isinstance(p, dict) and p.get("key")}
    boot = current.get("boot_id")
    same_boot = bool(boot and previous and previous.get("boot_id") == boot)
    lifecycle = lifecycle or {}
    valid_lifecycle = (lifecycle.get("status") == "complete"
                       and lifecycle.get("boot_id") == boot
                       and bool(lifecycle.get("source_id"))
                       and lifecycle.get("receipt_verified") is True
                       and lifecycle.get("attachment_verified") is True
                       and lifecycle.get("cursor_continuous") is True
                       and lifecycle.get("policy_covers_fork") is True
                       and lifecycle.get("loss_count") == 0
                       and type(lifecycle.get("since_start_ticks")) is int
                       and type(lifecycle.get("through_start_ticks")) is int
                       and lifecycle["through_start_ticks"] >= lifecycle["since_start_ticks"]
                       and type(lifecycle.get("settle_ticks", 0)) is int
                       and 0 <= lifecycle.get("settle_ticks", 0) <= 1000000
                       and isinstance(lifecycle.get("covered_pid_namespaces"), list)
                       and len(lifecycle["covered_pid_namespaces"]) <= 256
                       and isinstance(lifecycle.get("created_keys"), list)
                       and len(lifecycle["created_keys"]) <= 100000)
    creations = set(lifecycle["created_keys"]) if valid_lifecycle else set()
    findings = []
    counts = {"represented": len(rows), "matched_lifecycle": 0,
              "unexplained": 0, "unknown_lifecycle": 0,
              "new_in_snapshot": 0, "disappeared_from_snapshot": 0,
              "privilege_changes": 0}
    for row in rows:
        key = row.get("key")
        if not key:
            counts["unknown_lifecycle"] += 1
            continue
        old = before.get(key) if same_boot else None
        if same_boot and old is None:
            counts["new_in_snapshot"] += 1
        if old and (old.get("uid"), old.get("capabilities")) != (
                row.get("uid"), row.get("capabilities")):
            counts["privilege_changes"] += 1
            if len(findings) < limit:
                findings.append({"kind": "privilege_snapshot_change", "key": key,
                                 "basis": "two procfs snapshots; transition actor unknown"})
        if valid_lifecycle and key in creations:
            counts["matched_lifecycle"] += 1
        elif (valid_lifecycle and row.get("start_ticks") is not None
              and row.get("namespaces", {}).get("pid")
              in lifecycle["covered_pid_namespaces"]
              and row["start_ticks"] >= lifecycle["since_start_ticks"]
              and row["start_ticks"] <= lifecycle["through_start_ticks"]
              and lifecycle["through_start_ticks"] - row["start_ticks"]
              >= lifecycle.get("settle_ticks", 0)
              and not current.get("budget_exhausted") and not current.get("errors")):
            counts["unexplained"] += 1
            if len(findings) < limit:
                findings.append({"kind": "lifecycle_visibility_contradiction",
                                 "key": key, "basis": "continuous source lacks creation"})
        else:
            counts["unknown_lifecycle"] += 1
    if same_boot:
        now_keys = {p.get("key") for p in rows}
        counts["disappeared_from_snapshot"] = sum(k not in now_keys for k in before)
    return {"status": "limited" if current.get("status") == "partial" else
            "unavailable", "lifecycle_source": "usable" if valid_lifecycle else
            "unavailable_or_unproven", "counts": counts, "findings": findings,
            "findings_truncated": counts["unexplained"] + counts["privilege_changes"]
            > len(findings), "limitations": list(current.get("source_limits") or [])
            + ([] if valid_lifecycle else ["no continuous lifecycle source receipt"])
            + ([] if same_boot or not previous else ["prior snapshot has another boot"])}
