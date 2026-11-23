"""eBPF programs from /proc/kallsyms, without bpftool, against a baseline.

bpftool is not installed on most machines (it is not here), and the program
inventory used to come back empty without a word: an eBPF rootkit loaded
after boot was invisible (2026-10-27 coverage audit). Every JIT-compiled
program appears in /proc/kallsyms as `bpf_prog_<tag>_<name> [bpf]`; the tag
is a hash of the program's instructions, so the same program has the same
tag after a reboot. A tag that is not in the learned baseline is new kernel-
resident code.

Legitimate churn is expected: systemd loads per-unit device and firewall
filters (`sd_*`), container runtimes load unnamed cgroup device filters, and
Sysmon for Linux loads its own probes. Those are reported low. A new named
program that is none of these is medium: that is how a fresh tracing hook or
an eBPF rootkit appears. New tags are never folded into the baseline
silently; they stay reported for as long as they are loaded.
"""

import json
import re

from .common import PROC, _finding, _read

KALLSYMS_BPF = re.compile(r"\sbpf_prog_([0-9a-f]{16})(?:_([^\s]*))?\s+\[bpf\]")
BASELINE_META = "ebpf_baseline_v1"
# Sysmon for Linux (SysinternalsEBPF) probe names, measured 2026-10-27.
SYSMON_PROBES = frozenset((
    "rawEBPFprog", "genericRawEnter", "UDPsend", "UDPrecvRawExit", "TCPconnection",
    "TCPacceptRawExit", "ProcTerminated", "ProcCreateRawExit", "ProcAccessedRawExit",
    "FileOpenRawExit", "FileDeleteRawExit", "FileDeleteAtRawExit",
    "FileDeleteAtCwdRawExit", "FileCreateRawExit", "CloseFDRawExit", "BPFLoadRawExit"))
WHERE = f"{PROC}/kallsyms"


def kallsyms_programs(proc=PROC):
    """{tag: name} for every JIT-compiled eBPF program, or None if unobservable.

    Programs are JIT-compiled (and so in kallsyms) only while bpf_jit_enable
    is on; with it off this view is blind, which is reported, not hidden."""
    if _read(f"{proc}/sys/net/core/bpf_jit_enable").strip() == "0":
        return None
    try:
        with open(f"{proc}/kallsyms", encoding="ascii", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    return {m.group(1): m.group(2) or "" for m in KALLSYMS_BPF.finditer(text)}


def _kind(name, sysmon_running):
    if name.startswith("sd_") or name == "systemd":
        return "systemd"
    if not name:
        return "unnamed"
    if name in SYSMON_PROBES and sysmon_running:
        return "sysmon"
    return "other"


def assess(programs, baseline, holders):
    """(findings, baseline to store or None). Pure.

    programs: {tag: name} now, or None when the view is blind.
    baseline: {tag: name} learned earlier, or None on the first run.
    holders: [{"name": ...}] processes holding eBPF handles (fd scan)."""
    if programs is None:
        return [_finding("medium", "eBPF program inventory unavailable",
                         "bpf_jit_enable is off or /proc/kallsyms is unreadable, and "
                         "bpftool is not installed, so loaded eBPF programs cannot be "
                         "listed; an eBPF rootkit would not be seen.", WHERE)], None
    sysmon_running = any((h.get("name") or "").lower().startswith("sysmon") for h in holders)
    if baseline is None:
        kinds = {}
        for name in programs.values():
            kinds[_kind(name, sysmon_running)] = kinds.get(_kind(name, sysmon_running), 0) + 1
        summary = ", ".join(f"{n} {k}" for k, n in sorted(kinds.items()))
        return [_finding("ok", "eBPF program baseline learned",
                         f"{len(programs)} JIT-compiled programs ({summary or 'none'}); "
                         f"programs loaded later are reported against this list.",
                         WHERE)], dict(programs)
    out = []
    new = {tag: name for tag, name in programs.items() if tag not in baseline}
    for tag, name in sorted(new.items(), key=lambda kv: kv[1]):
        kind = _kind(name, sysmon_running)
        label = name or "(unnamed)"
        if kind == "other":
            out.append(_finding(
                "medium", "new eBPF program loaded since baseline",
                f"{label} (tag {tag}) is kernel-resident code that was not loaded when "
                f"the baseline was learned. eBPF can trace, filter and rewrite what other "
                f"tools see; find its owner with `sudo bpftool prog show tag {tag}`.",
                WHERE))
        else:
            why = {"systemd": "a systemd unit device or firewall filter",
                   "unnamed": "unnamed; container runtimes load unnamed cgroup device filters",
                   "sysmon": "a Sysmon for Linux probe, and Sysmon is running"}[kind]
            out.append(_finding("low", "new eBPF program loaded since baseline",
                                f"{label} (tag {tag}) — {why}", WHERE))
    if not new:
        out.append(_finding("ok", "no eBPF programs beyond the baseline",
                            f"{len(programs)} loaded, all known", WHERE))
    return out, None


def findings(holders, db_path=None, proc=PROC):
    """Inventory findings; learns and reads the baseline in the service store."""
    programs = kallsyms_programs(proc)
    baseline, store = None, None
    if db_path:
        try:
            from jarvis.core.store import Store
            store = Store(db_path)
            saved = json.loads(store.get_meta(BASELINE_META) or "null")
            baseline = saved if isinstance(saved, dict) else None
        except Exception:
            store = None
    try:
        if store is None and programs is not None:
            # No store (CLI, tests): report the inventory, never learn a baseline.
            return [_finding("low", "eBPF programs loaded",
                             f"{len(programs)} JIT-compiled programs; run inside the "
                             f"service to compare them with a baseline", WHERE)]
        out, learned = assess(programs, baseline, holders)
        if learned is not None and store is not None:
            store.set_meta(BASELINE_META, json.dumps(learned))
        return out
    finally:
        if store is not None:
            store.close()
