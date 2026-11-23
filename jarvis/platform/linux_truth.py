"""Bounded /proc process-truth view. A snapshot is not lifecycle coverage.

No command lines, environment values, file names, or socket addresses leave
this module. Every row is keyed by boot plus kernel start ticks, never PID alone.
Read errors, races and scan truncation are evidence about visibility, not a
reason to call a quiet machine clean. This reader never changes host policy.
"""

import os
import time

PROC = "/proc"
NAMESPACES = ("pid", "user", "mnt", "net", "uts", "ipc", "cgroup", "time")
MAX_PROCESSES = 4096
MAX_THREADS = 16384
MAX_FDS = 8192
MAX_SECONDS = 2.0
MAX_READ_BYTES = 16384
MAX_MAP_BYTES = 262144
MAX_MAP_ROWS = 1024


def _read(path):
    with open(path, "rb") as fh:
        return fh.read(MAX_READ_BYTES).decode("utf-8", "replace")


def _stat(raw):
    # comm may contain spaces and ')' characters; the last ')' precedes state.
    end = raw.rfind(") ")
    if end < 0:
        raise ValueError("invalid proc stat")
    fields = raw[end + 2:].split()
    if len(fields) < 20:
        raise ValueError("short proc stat")
    return {"state": fields[0], "ppid": int(fields[1]),
            "cpu_ticks": int(fields[11]) + int(fields[12]),
            "start_ticks": int(fields[19])}


def _status(raw):
    allowed = {"Name", "Tgid", "Pid", "PPid", "Uid", "Gid", "Threads",
               "NSpid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
               "NoNewPrivs"}
    values = {}
    for line in raw.splitlines():
        field, sep, value = line.partition(":")
        if sep and field in allowed:
            values[field] = value.strip()
    return values


def _namespace(base, name):
    try:
        return os.readlink(f"{base}/ns/{name}")
    except OSError:
        return None


def _fds(base, budget, deadline):
    try:
        names = sorted((n for n in os.listdir(base + "/fd") if n.isdigit()), key=int)
    except OSError as exc:
        return [], None, type(exc).__name__, True
    observed = []
    for name in names[:budget]:
        if time.monotonic() >= deadline:
            break
        path = f"{base}/fd/{name}"
        try:
            target = os.readlink(path)
            if target.startswith("socket:["):
                kind = "socket"
            elif target.startswith("pipe:["):
                kind = "pipe"
            elif target.startswith("/memfd:") or target.startswith("memfd:"):
                kind = "memfd"
            elif target.startswith("anon_inode:"):
                kind = "anonymous_inode"
            elif target.endswith(" (deleted)"):
                kind = "deleted_file"
            else:
                kind = "file_or_device"
            try:
                st = os.stat(path)
                identity = {"device": st.st_dev, "inode": st.st_ino}
            except OSError:
                identity = {"device": None, "inode": None}
            observed.append({"fd": int(name), "kind": kind, **identity})
        except OSError:
            continue
    return observed, len(names), None, len(observed) != len(names)


def _process(base, boot, deadline, thread_budget, fd_budget):
    first = _stat(_read(base + "/stat"))
    status = _status(_read(base + "/status"))
    pid = int(os.path.basename(base))
    if int(status.get("Pid", pid)) != pid:
        raise ValueError("status PID mismatch")
    namespaces = {n: _namespace(base, n) for n in NAMESPACES}
    try:
        cgroup = _read(base + "/cgroup").strip().splitlines()[:8]
        # Keep only cgroup paths, bounded. They may contain user-controlled
        # names, so this is local-only evidence and not sent to a model.
        cgroup = [row.split(":", 2)[-1][:256] for row in cgroup]
    except OSError:
        cgroup = None
    try:
        exe = os.readlink(base + "/exe")
        exe_name = os.path.basename(exe.removesuffix(" (deleted)"))[:128]
        exe_deleted = exe.endswith(" (deleted)")
        exe_stat = os.stat(base + "/exe")
        executable = {"name": exe_name, "device": exe_stat.st_dev,
                      "inode": exe_stat.st_ino, "deleted": exe_deleted}
    except OSError:
        executable = None
    try:
        task_names = sorted((n for n in os.listdir(base + "/task") if n.isdigit()),
                            key=int)
        task_error = None
    except OSError as exc:
        task_names, task_error = [], type(exc).__name__
    threads = []
    for name in task_names[:thread_budget]:
        if time.monotonic() >= deadline:
            break
        try:
            stat = _stat(_read(f"{base}/task/{name}/stat"))
        except (OSError, ValueError):
            continue  # raced exit; count below rather than inventing a thread
        threads.append({"tid": int(name), "start_ticks": stat["start_ticks"],
                        "state": stat["state"], "cpu_ticks": stat["cpu_ticks"]})
    fds, fd_count, fd_error, fds_truncated = _fds(base, fd_budget, deadline)
    # Re-read task leader last. If PID was reused during the scan, discard
    # the entire row instead of attaching old threads to a new process.
    last = _stat(_read(base + "/stat"))
    if last["start_ticks"] != first["start_ticks"]:
        raise ValueError("PID reused during scan")
    # The kernel parent is evidence for a kernel thread. An unreadable exe
    # alone is not: /proc permissions can hide it for ordinary user tasks.
    kind = ("kernel_thread_candidate" if executable is None
            and (pid == 2 or first["ppid"] == 2) else
            "unknown_type" if executable is None else "user_process")
    return {"key": f"linux:{boot}:{namespaces['pid'] or '?'}:{pid}:{first['start_ticks']}",
            "pid": pid, "start_ticks": first["start_ticks"],
            "ppid": first["ppid"], "name": status.get("Name", "")[:128],
            "entity_type": kind, "state": last["state"],
            "cpu_ticks": last["cpu_ticks"], "uid": status.get("Uid"),
            "gid": status.get("Gid"), "nspid": status.get("NSpid"),
            "capabilities": {n: status.get(n) for n in
                             ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")},
            "no_new_privs": status.get("NoNewPrivs"),
            "namespaces": namespaces, "cgroups": cgroup,
            "executable": executable, "threads": threads,
            "thread_count_reported": int(status.get("Threads", "0")),
            "thread_count_listed": len(task_names),
            "thread_error": task_error,
            "threads_truncated": len(task_names) > len(threads),
            "fds": fds, "fd_count_listed": fd_count,
            "fd_error": fd_error, "fds_truncated": fds_truncated}


def snapshot(*, proc=PROC, max_processes=MAX_PROCESSES,
             max_threads=MAX_THREADS, max_fds=MAX_FDS,
             max_seconds=MAX_SECONDS):
    """Capture all visible task leaders within explicit resource bounds.

    The result is always `partial`: /proc is a point-in-time user-space view.
    It cannot prove no short-lived tasks, hidden tasks or missing event history.
    """
    if not 1 <= max_processes <= MAX_PROCESSES or not 1 <= max_threads <= MAX_THREADS \
            or not 1 <= max_fds <= MAX_FDS \
            or not 0 < max_seconds <= MAX_SECONDS:
        raise ValueError("process-truth budget out of range")
    started = time.monotonic()
    deadline = started + max_seconds
    errors = []
    try:
        boot = _read(proc + "/sys/kernel/random/boot_id").strip()
        names = sorted((n for n in os.listdir(proc) if n.isdigit()), key=int)
    except OSError as exc:
        return {"status": "unavailable", "source": "procfs",
                "errors": [type(exc).__name__], "processes": [],
                "source_limits": ["procfs enumeration failed"],
                "event_stream": "unavailable"}
    if not boot:
        errors.append("boot identity unavailable")
    processes = []
    races = 0
    threads_seen = 0
    fds_seen = 0
    budget_exhausted = False
    for name in names[:max_processes]:
        if (time.monotonic() >= deadline or threads_seen >= max_threads
                or fds_seen >= max_fds):
            budget_exhausted = True
            break
        try:
            row = _process(f"{proc}/{name}", boot or "unknown-boot",
                           deadline, max_threads - threads_seen,
                           max_fds - fds_seen)
        except FileNotFoundError:
            races += 1
            continue
        except (OSError, ValueError) as exc:
            errors.append(f"pid {name}: {type(exc).__name__}")
            continue
        threads_seen += len(row["threads"])
        fds_seen += len(row["fds"])
        processes.append(row)
    by_pid = {row["pid"]: row for row in processes}
    for row in processes:
        parent = by_pid.get(row["ppid"])
        row["parent_key"] = (parent["key"] if parent and
                             parent["start_ticks"] <= row["start_ticks"] else None)
        row["parent_basis"] = "coherent_snapshot" if row["parent_key"] else "unknown"
    if len(names) > max_processes:
        budget_exhausted = True
    limits = ["procfs is a sampled view; lifecycle events are not connected"]
    if budget_exhausted:
        limits.append("scan budget exhausted")
    if errors:
        limits.append("one or more process details were inaccessible")
    if races:
        limits.append("one or more processes exited during the scan")
    if any(p["threads_truncated"] or p["thread_error"] or
           any(v is None for v in p["namespaces"].values()) for p in processes):
        limits.append("thread or namespace details are incomplete")
    if any(p["fds_truncated"] or p["fd_error"] for p in processes):
        limits.append("open descriptor details are incomplete")
    return {"status": "partial", "source": "procfs", "boot_id": boot or None,
            "observed_at": time.time(), "elapsed_seconds": round(time.monotonic() - started, 3),
            "enumerated_pids": len(names), "represented_processes": len(processes),
            "represented_threads": threads_seen, "represented_fds": fds_seen,
            "raced_exits": races,
            "budget_exhausted": budget_exhausted, "errors": errors[:50],
            "processes": processes, "source_limits": limits,
            "event_stream": "unavailable"}


def executable_mappings(pid, *, proc=PROC, expected_start_ticks=None):
    """Inspect one selected instance's executable maps, without map contents.

    This is a snapshot. It cannot identify RW→RX transitions or prove that a
    region was executed. Callers must pass the observed start tick to avoid
    deep-inspecting a reused PID.
    """
    pid = int(pid)
    if pid < 1 or expected_start_ticks is None:
        raise ValueError("pid and expected start identity required")
    base = f"{proc}/{pid}"
    try:
        before = _stat(_read(base + "/stat"))["start_ticks"]
        if before != int(expected_start_ticks):
            return {"status": "identity_changed", "mappings": []}
        with open(base + "/maps", "rb") as fh:
            raw = fh.read(MAX_MAP_BYTES + 1)
        truncated = len(raw) > MAX_MAP_BYTES
        rows = []
        # Do not parse an incomplete final line after the byte cap.
        lines = raw[:MAX_MAP_BYTES].splitlines()
        if truncated and lines:
            lines = lines[:-1]
        for line in lines:
            fields = line.decode("utf-8", "replace").split(None, 5)
            if len(fields) < 5 or "x" not in fields[1]:
                continue
            start, end = (int(part, 16) for part in fields[0].split("-", 1))
            name = fields[5] if len(fields) > 5 else ""
            kind = ("memfd" if "memfd:" in name else
                    "anonymous" if not name else
                    "file_deleted" if name.endswith(" (deleted)") else
                    "file_backed")
            rows.append({"bytes": max(0, end - start), "permissions": fields[1],
                         "device": fields[3], "inode": fields[4], "kind": kind})
            if len(rows) >= MAX_MAP_ROWS:
                truncated = True
                break
        after = _stat(_read(base + "/stat"))["start_ticks"]
        if after != before:
            return {"status": "identity_changed", "mappings": []}
    except (OSError, ValueError, IndexError) as exc:
        return {"status": "unavailable", "reason": type(exc).__name__,
                "mappings": []}
    return {"status": "partial" if truncated else "sampled",
            "process_key": f"{pid}:{before}", "mappings": rows,
            "truncated": truncated,
            "limitation": "mapping snapshot; memory transitions and execution not observed"}
