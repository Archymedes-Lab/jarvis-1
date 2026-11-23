"""Run one scheduled audit by name and return its findings in the common shape.

Most collectors already return findings; the ones that do not (the process scan,
feeds, intel) are adapted here, so the scheduler only ever sees one shape.

Each job is a small function registered in RUNNERS under its schedule name.
Jobs that touch the database open their own store: they run inside the
scheduler's worker thread, and a sqlite handle must not cross threads.
"""

import re
import time
from contextlib import contextmanager

from jarvis.collectors import appcode
from jarvis.collectors.host import (
    accelerator,
    audiowatch,
    bootchain,
    bootintegrity,
    canary,
    containers,
    content,
    controlwatch,
    dotnet_posture,
    firmwareaudit,
    fridaydefender,
    geo,
    inputwatch,
    keyreaders,
    opshealth,
    osquery,
    patches,
    pixel,
    posture,
    privacyseal,
    restarts,
    selfguard,
    spyware,
    storage,
    toolchain,
    updates,
    winblocks,
    wslguard,
    wslmanifest,
)
from jarvis.collectors.host import intrusion as intrusion_mod
from jarvis.collectors.identity import bruteforce, impersonation, logins, secrets, sshwatch
from jarvis.collectors.network import firewall, internetwatch, netflow, netwatch, sniffing, webshell
from jarvis.collectors.persistence import asep as asep_mod
from jarvis.collectors.persistence import backdoor, control, implant, linuxguard, pkgverify, startup
from jarvis.collectors.process import evasion as evasion_mod
from jarvis.collectors.process import hidden, memscan, monitor, resourcewatch
from jarvis.collectors.telemetry import (
    auditd,
    evidence,
    history_retention,
    history_verify,
    mirror,
    native,
    psscript,
    reconcile,
    sensorprobe,
    sysmon,
    sysmon_linux,
    sysmon_policy,
    sysmon_pressure,
)
from jarvis.core import collection, historybook, retention
from jarvis.core import mlworker as mlworker_mod
from jarvis.core.eventlog import LogError
from jarvis.core.finding import LOCAL_HOST
from jarvis.core.store import Store
from jarvis.intel import distrovuln, feeds, gaps, hunt, osv, worldwatch
from jarvis.intel import research as intel
from jarvis.lab import audit as arena_audit
from jarvis.platform import host
from jarvis.platform import openvino as openvino_mod
from jarvis.response import alert, llm, memory_advice
from jarvis.response import ledger as ledger_mod
from jarvis.response.reporting.cadence import run as report_due
from jarvis.service import attackmap, connectivity, heartbeat, selfcheck, supervisors, verifyjob
from jarvis.service import coverage as coverage_mod
from jarvis.service.schedule import JOBS

# Composition root: core routing stays platform-independent, while the daemon
# explicitly supplies the measured Windows OpenVINO executor.
mlworker_mod.set_gpu_infer(openvino_mod.infer)


@contextmanager
def _store(db_path):
    store = Store(db_path)
    try:
        yield store
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Jobs that adapt a collector's own result shape
# ---------------------------------------------------------------------------

def _scan(hosts, db_path):
    # The process scan is stateful (it maintains the baseline), so it needs
    # its own store handle inside the worker thread.
    with _store(db_path) as store:
        res = monitor.scan(store, hosts=hosts)
        history_error = None
        try:
            from pathlib import Path
            historybook.record_snapshot(res.get("processes", []), hosts, res["ts"],
                                        root=Path(db_path).absolute().parent / "eventlog")
        except (LogError, OSError, ValueError) as exc:
            history_error = type(exc).__name__
            collection.failed("process-history", "process snapshot history not committed: "
                              + history_error)
        policy = (sysmon_policy.audit() if "win" in hosts else
                  {"event1": "unknown", "detail": "Windows host not selected",
                   "source": "unavailable"})
        # Perception summary for the health endpoint: cheap persisted counts
        # (VERIFIED vs UNRECONCILED vs UNKNOWN) so HTTP never touches the
        # event log. Read-only; finding semantics live in reconcile.processes.
        try:
            import json as _json

            from jarvis.collectors.telemetry import reconcile as _reconcile
            verdicts = _reconcile.classify_snapshot(
                res.get("processes", []), observed_at=res["ts"])
            summary = {"verified": 0, "unreconciled": 0, "unknown": 0}
            for v in verdicts:
                label = v.get("label", "UNKNOWN")
                if label == "VERIFIED":
                    summary["verified"] += 1
                elif label == "UNRECONCILED":
                    summary["unreconciled"] += 1
                else:
                    summary["unknown"] += 1
            store.set_meta("perception_summary_v1", _json.dumps({
                "at": res["ts"], "windows_processes": len(verdicts),
                "sysmon_process_create_policy": sysmon_policy.summary(policy),
                "sysmon_process_create_coverage":
                    _reconcile.coverage_evidence(
                        res["ts"], snapshot=res.get("processes", [])),
                "sysmon_pressure": sysmon_pressure.audit(),
                **summary,
            }))
            store.commit()
        except Exception:
            pass
    out = []
    if history_error:
        out.append({"category": "visibility", "severity": "high", "host": LOCAL_HOST,
                    "title": "Process history recording blocked",
                    "detail": "Existing evidence retained; new sampled snapshot not committed: "
                              + history_error, "where": "canonical event history"})
    for f in res["findings"]:
        remotes = ", ".join(
            f"{r['ip']}:{r['port']}" for r in f["remotes"][:3]
            if r["scope"] == "public")
        out.append({
            "category": "process", "severity": f["severity"],
            "host": f["host"],
            "title": f"{f['name']} [pid {f['pid']}]"
                     + (" — NEW" if f["unknown"] else ""),
            "detail": (f["cmdline"] or "")[:160]
                      + (f"  →  {remotes}" if remotes else ""),
            "where": f["exe"] or f.get("script") or "",
        })
    for p in res["new_public_peers"]:
        out.append({
            "category": "peer", "severity": "medium",
            "host": p["proc"]["host"],
            "title": "new external peer",
            "detail": f"{p['ip']}:{p['port']} ← {p['proc']['name']}",
            "where": p["proc"].get("exe") or "",
        })
    out.extend(reconcile.processes(
        res.get("processes", []), observed_at=res["ts"], policy=policy))
    return out


def _link_findings(db_path):
    """The Link Plane's view from persisted state plus current evidence
    (links.py). The plane itself runs in the scheduler; this lane only reads."""
    from jarvis.service import links
    try:
        store = Store(db_path)
        try:
            raw = store.get_meta(links.META, "") or ""
            plane = links.LinkPlane().load(raw)
            now = time.time()
            evidence = links.gather_evidence(store.get_snapshots(), now, store=store, plane=plane)
            plane.tick(evidence, now, hold=True)
            return plane.findings(now)
        finally:
            store.close()
    except Exception as exc:  # noqa: BLE001 - a reporting fault must not take the watchdogs down
        return [{"category": "collectors", "severity": "low", "host": LOCAL_HOST,
                 "title": "connection status is unavailable this run",
                 "detail": f"the link plane could not be read: {type(exc).__name__}", "where": "links"}]


def _watchdogs(hosts, db_path):
    # Both halves of the supervision loop: the systemd timer that restarts
    # this daemon, and the Windows task that reports it missing when WSL
    # itself is down.
    out = alert.channel_findings()       # critical while nothing can page the owner
    out += _link_findings(db_path)
    if host.has_windows():
        # A machine with no Windows host has no Windows tasks to be watched by.
        out += supervisors.audit_health_monitor()
        out += (supervisors.audit_native_service() if host.native_windows()
                else supervisors.audit_reviver())
        out += supervisors.audit_broker() + connectivity.audit()
    if host.native_windows():
        # No systemd: the native service task above is the out-of-daemon
        # watchdog, and its own task trigger is what restarts it.
        return out
    active, enabled_state = selfcheck.timer_state()
    if not active:
        watchdog_s, restart = selfcheck.systemd_supervision()
        if watchdog_s and restart == "always":
            # The server edition's unit: systemd itself is the out-of-process
            # supervisor (ARGUS-SERVER.md W12, measured in the 2026-10-25 lab run).
            return out + [{
                "category": "daemon", "severity": "ok", "host": LOCAL_HOST,
                "title": "systemd supervises this daemon",
                "detail": f"{selfcheck.UNIT} has a {watchdog_s} s watchdog and Restart=always: "
                          f"a wedged or dead daemon is killed and restarted from outside it",
                "where": selfcheck.UNIT}]
        return out + [{
            "category": "daemon", "severity": "high", "host": LOCAL_HOST,
            "title": "the out-of-daemon watchdog is not installed",
            "detail": "jarvis-selfcheck.timer is absent, so nothing outside "
                      "this process can restart it if it dies — and a dead "
                      "daemon cannot report its own death. Install with "
                      "`./install.sh --seal`.",
            "where": "jarvis-selfcheck.timer"}]
    err = selfcheck.ensure_timer()
    if err:
        return out + [{
            "category": "daemon", "severity": "high", "host": LOCAL_HOST,
            "title": "the out-of-daemon watchdog has stopped",
            "detail": f"jarvis-selfcheck.timer is {active}/{enabled_state} "
                      f"and could not be re-armed: {err}",
            "where": "jarvis-selfcheck.timer"}]
    if active != "active" or enabled_state != "enabled":
        # ensure_timer() fixed it. Say so — a watchdog that keeps needing
        # to be restarted is a finding, not a routine success.
        return out + [{
            "category": "daemon", "severity": "medium", "host": LOCAL_HOST,
            "title": "the out-of-daemon watchdog had stopped and was re-armed",
            "detail": f"jarvis-selfcheck.timer was {active}/{enabled_state}; "
                      f"it is running again. Repeated occurrences mean "
                      f"something is stopping it.",
            "where": "jarvis-selfcheck.timer"}]
    return out + [{
        "category": "daemon", "severity": "ok", "host": LOCAL_HOST,
        "title": "watchdogs supervise each other",
        "detail": f"jarvis-selfcheck.timer {active}/{enabled_state} — it "
                  f"restarts this daemon, this daemon re-arms it",
        "where": "jarvis-selfcheck.timer"}]


def _report(hosts, db_path):
    with _store(db_path) as store:
        return report_due(store, JOBS)


def _ledger(hosts, db_path):
    with _store(db_path) as store:
        # A row is only "stale" relative to whether its own collector has
        # run since; the snapshot table is where that is recorded.
        snaps = store.get_snapshots()
        job_ts = {k: int(v.get("ts") or 0) for k, v in snaps.items()
                  if not v.get("error")}
        # The snapshots also let it attach an overdue row to the original
        # finding instead of restating it as a second one.
        return ledger_mod.audit(store, job_ts=job_ts, snapshots=snaps)


def _input(deep):
    def run(hosts, db_path):
        with _store(db_path) as store:
            # The Windows-side hook does not survive a reboot or a WSL restart
            # and nothing outside this loop respawns it, so supervise() keeps
            # it up — cheaply on the healthy path, with backoff and flap
            # detection when it is not. "input_hook" is the short-interval
            # watchdog; "input" additionally runs the full injected-event audit.
            pids, findings = inputwatch.supervise(store, deep=deep)
            # A monitor that is down is not a successful observation: recording
            # it as one would leave the score, coverage, the dashboard and the
            # daily email all reporting input monitoring as fine.
            outage = next((f for f in findings if alert.is_outage(f)), None)
            if outage:
                collection.failed("input-hook", outage.get("title", "monitor down"))
            if deep:
                findings += inputwatch.audit(store, pids=pids, supervised=True)
            return findings
    return run


def _netwatch(hosts, db_path):
    with _store(db_path) as store:
        netwatch.record(store)
        return netwatch.audit(store)


def _feeds(hosts, db_path):
    with _store(db_path) as store:
        results = feeds.refresh(store)
        results.append(feeds.refresh_attack(store))
        results.append(feeds.refresh_tranco(store))
        out = []
        # One finding per cause, naming the feeds it hit: an offline server
        # is one problem, not seventeen (ARGUS-SERVER.md W12, 2026-10-25).
        # Persisted failures count too: a feed retries once a day, and the
        # hourly runs between must not read "complete" over stale indicators.
        failed = {r["name"]: r["error"] for r in results if r.get("error")}
        failed.update({n: e for n, e in feeds.failing(store).items() if n not in failed})
        by_error = {}
        for name, error in failed.items():
            collection.failed(f"feed:{name}", error)
            if feeds.is_abusech(name):
                if not feeds.abusech_key() and re.search(r"\b(401|403|410)\b", error):
                    error = (f"{error}. abuse.ch requires a free Auth-Key since 2025-06-30: "
                             f"create an account at auth.abuse.ch and set "
                             f"\"{feeds.ABUSECH_KEY_CONF}\" in ~/.jarvis/config.json")
            by_error.setdefault(error, []).append(name)
        for error, names in sorted(by_error.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            title = (f"{names[0]} feed failed" if len(names) == 1
                     else f"{len(names)} threat feeds failed")
            out.append({"category": "feed", "severity": "medium", "host": LOCAL_HOST,
                        "title": title, "detail": f"{error} — {', '.join(sorted(names))}",
                        "where": ""})
        if any(not r.get("error") for r in results):
            collection.succeeded("feeds")
        kept = sum(r.get("kept", 0) for r in results if not r.get("error"))
        if kept:
            out.append({"category": "feed", "severity": "low", "host": LOCAL_HOST,
                        "title": f"{kept} indicators refreshed",
                        "detail": ", ".join(
                            r["name"] for r in results
                            if r.get("kept")), "where": ""})
        feeds.prune(store)
        # Retire-then-remove: prune() marks feed entries retired, and
        # retention deletes the ones that have stayed retired. Without
        # this second step the indicators table only ever grows.
        removed = sum(r["rows"] for r in retention.apply(store))
        if removed:
            out.append({"category": "feed", "severity": "low",
                        "host": LOCAL_HOST,
                        "title": f"{removed} aged rows removed",
                        "detail": "database retention policy; run "
                                  "`jarvis retention` to see what it keeps",
                        "where": ""})
        return out


def _intel(hosts, db_path):
    if not intel.load_key():
        return [{"category": "intel", "severity": "low", "host": LOCAL_HOST,
                 "title": "threat-intel search is not set up",
                 "detail": "optional: `jarvis intel --set-key <exa-key>` adds research "
                           "from security publishers; the free bulk feeds run without it",
                 "where": ""}]
    with _store(db_path) as store:
        try:
            options = intel.daemon_options(store)
            stats = intel.refresh(store, **options)
        except intel.BudgetExceeded as exc:
            # Not a failure: the brake worked. Say so quietly and keep the
            # previous findings on the dashboard.
            return [{"category": "intel", "severity": "low",
                     "host": LOCAL_HOST, "title": "intel refresh paused",
                     "detail": str(exc), "where": ""}]
    out = []
    if stats["errors"]:
        out.append({
            "category": "intel", "severity": "medium", "host": LOCAL_HOST,
            "title": "intel refresh had errors",
            "detail": "; ".join(stats["errors"])[:400], "where": ""})
    out.append({
        "category": "intel", "severity": "low", "host": LOCAL_HOST,
        "title": f"refreshed {', '.join(stats['topics'])}",
        "detail": f"{stats['docs']} documents, {stats['kept']} indicators "
                  f"kept of {stats['seen']} candidates, "
                  f"${stats['cost']:.3f}",
        "where": ""})
    return out


def _hunt(hosts, db_path):
    with _store(db_path) as store:
        return hunt.sort_findings(hunt.hunt(store, hosts=hosts))


def _gaps(hosts, db_path):
    with _store(db_path) as store:
        return gaps.gaps(store)[0]


# ---------------------------------------------------------------------------
# Jobs that call a collector directly
# ---------------------------------------------------------------------------

def _with_store(audit, **kwargs):
    """A job whose collector takes (store, hosts=...)."""
    def run(hosts, db_path):
        with _store(db_path) as store:
            return audit(store, hosts=hosts, **kwargs)
    return run


def _rule_match(*args):
    """The detection rules, for the retention job (bulk lane: history_retention
    itself must not import what reaches Windows; the rules only match text)."""
    from jarvis.collectors.telemetry import techniques
    return techniques.match(*args)


def _store_only(audit):
    """A job whose collector takes only the store."""
    def run(hosts, db_path):
        with _store(db_path) as store:
            return audit(store)
    return run


def _updates_job(store):
    """The updates collector with the response layer's acting parts handed in
    (a collector never imports the response layer)."""
    from jarvis.response import alert, updater

    def notify(store, conf, p, pol, now):
        return updates.notify_owner(store, conf, p, pol, now, deliver=alert.deliver, enabled=alert.enabled)

    return updates.audit(store, conf=alert.load_conf(), start_auto=updater.start_auto,
                         last_auto=updater.last_auto, notify=notify)


def _hosts_only(audit):
    """A job whose collector takes only hosts=..."""
    return lambda hosts, db_path: audit(hosts=hosts)


def _canary(hosts, db_path):
    # Config (callback inbox, anchoring) is read here, in the service layer, and
    # handed to the collector, which must not import `response` itself.
    conf = (alert.load_conf() or {}).get("canary", {}) or {}
    with _store(db_path) as store:
        return canary.audit(store, conf=conf)


def _selfguard(hosts, db_path):
    # The technique matcher's suspended pack rules live in telemetry; the
    # service layer passes them to the host-domain collector.
    from jarvis.collectors.telemetry import techniques
    with _store(db_path) as store:
        return selfguard.audit(store, hosts=hosts, suspended=dict(techniques.PACK_SUSPENDED))


def _sorted(module):
    """A job whose collector takes no arguments and ships its own ordering."""
    return lambda hosts, db_path: module.sort_findings(module.audit())


def _intrusion(db_path):
    with _store(db_path) as store:
        return intrusion_mod.sort_findings(intrusion_mod.audit(store))


def _boot(hosts, db_path):
    findings = startup.sort_findings(startup.audit())
    # Reuse the control audit's full task verification, but only while its
    # result is current: stale or failing evidence verifies nothing.
    from jarvis.response.reporting.score import freshness
    with _store(db_path) as store:
        snap = store.get_snapshots().get("control")
    if freshness(snap, JOBS["control"][0], time.time()) == "current":
        findings = startup.apply_verified_tasks(findings, snap.get("findings"))
        findings = startup.apply_signed_tasks(findings, snap.get("findings"))
    return startup.sort_findings(findings)


def _coverage(hosts, db_path):
    findings = coverage_mod.sort_findings(
        coverage_mod.audit(db_path=db_path, hosts=hosts))
    # Human-in-the-loop self-fix: the self-audit that just ran is the right
    # moment to notice JARVIS itself needs help. maintain() only proposes and
    # mails (rate-limited); it never runs commands or models, and never raises
    # into the scheduler.
    try:
        from jarvis.response import selffix
        selffix.maintain(db_path, schedule=JOBS)
    except Exception:
        pass
    return findings


def _resources(hosts, db_path):
    with _store(db_path) as store:
        findings = list(resourcewatch.audit(store, hosts=hosts))
        findings.extend(accelerator.audit(store, hosts=hosts))
        return findings


RUNNERS = {
    "scan": _scan,
    "bridge": lambda hosts, db_path: coverage_mod.bridge_status(),
    "input_hook": _input(deep=False),
    "watchdogs": _watchdogs,
    "resources": _resources,
    "internet": _with_store(internetwatch.audit),
    "controls": _with_store(controlwatch.audit),
    "audio": _with_store(audiowatch.audit),
    "privacy": _with_store(privacyseal.audit),
    "wsl": _with_store(wslguard.audit),
    "wslmanifest": _with_store(wslmanifest.audit),
    "storage": _with_store(storage.audit),
    "preos": _with_store(bootintegrity.audit),
    "fwaudit": _with_store(firmwareaudit.audit),
    "netflow": _with_store(netflow.audit),
    "logins": _with_store(logins.audit),
    "sshwatch": _with_store(sshwatch.audit),
    "opshealth": _with_store(opshealth.audit),
    "restarts": _with_store(restarts.audit),
    "osquery": lambda hosts, db_path: osquery.audit(),
    "psscript": _with_store(psscript.audit),
    "content": _with_store(content.audit),
    "winblocks": lambda hosts, db_path: winblocks.audit(hosts),
    "linuxguard": _with_store(linuxguard.audit),
    "bootchain": _with_store(bootchain.audit),
    "selfguard": _selfguard,
    "keyreaders": _with_store(keyreaders.audit),
    "friday_defender": _with_store(fridaydefender.audit),
    "pkgverify": lambda hosts, db_path: pkgverify.audit(),
    "heartbeat": _store_only(heartbeat.run),
    "sensorprobe": _store_only(sensorprobe.run),
    "patches": _store_only(patches.audit),
    "updates": _store_only(_updates_job),
    "distrovuln": lambda hosts, db_path: distrovuln.refresh(),
    "appcode": _store_only(appcode.audit),
    "osv": lambda hosts, db_path: osv.refresh(),
    "deep_hidden": lambda hosts, db_path: hidden.audit(hosts=hosts, deep=True)[0],
    "hidden": lambda hosts, db_path: hidden.audit(hosts=hosts, db_path=db_path)[0],
    "firewall": _hosts_only(firewall.audit),
    "control": _hosts_only(control.audit),
    "dotnet": _hosts_only(dotnet_posture.audit),
    "asep": _sorted(asep_mod),
    # Both domains: it must be told which exist, or the Linux half runs on a
    # machine that has no Linux side.
    "spy": lambda hosts, db_path: spyware.sort_findings(spyware.audit(hosts=hosts)),
    "pixel": _hosts_only(pixel.audit),
    "identity": _with_store(impersonation.audit),
    "intrusion": lambda hosts, db_path: _intrusion(db_path),
    "evasion": _sorted(evasion_mod),
    "coverage": _coverage,
    "boot": _boot,
    "hunt": _hunt,
    "gaps": _gaps,
    "intel": _intel,
    "report": _report,
    "feeds": _feeds,
    "implant": _hosts_only(implant.audit),
    "netwatch": _netwatch,
    "posture": _hosts_only(posture.audit),
    "backdoor": _hosts_only(backdoor.audit),
    "toolchain": _with_store(toolchain.audit),
    "ledger": _ledger,
    "input": _input(deep=True),
    "memscan": lambda hosts, db_path: memscan.audit(hosts=hosts,
                                                     advise=memory_advice.advisor()),
    "secrets": lambda hosts, db_path: secrets.audit(),
    "bruteforce": _hosts_only(bruteforce.audit),
    "sniffing": _hosts_only(sniffing.audit),
    "webshell": _hosts_only(webshell.audit),
    "auditd": _hosts_only(auditd.audit),
    # Incremental: each run reads only what happened since the last one,
    # instead of re-reading a day of log every ten minutes.
    "sysmon_linux": _with_store(sysmon_linux.audit, incremental=True),
    "sysmon": _with_store(sysmon.audit, incremental=True),
    "native": _with_store(native.audit),
    "rust_mirror": _with_store(mirror.audit),
    "history_verify": _with_store(history_verify.verify_history),
    "retention": _with_store(history_retention.retention, match=_rule_match),
    "verify": _with_store(verifyjob.audit),
    "evidence": _with_store(evidence.audit),
    "canary": _canary,
    "arena": lambda hosts, db_path: arena_audit.audit(hosts=hosts),
    "geo": _with_store(geo.audit),
    "world": _with_store(worldwatch.audit),
    "containers": _hosts_only(containers.audit),
    "attackmap": _with_store(lambda store, hosts=None: attackmap.measure(store)[0]),
    "model": lambda hosts, db_path: [llm.status_findings(alert.load_conf())],
}


def run_job(name, hosts, db_path):
    """Run one audit and return its findings in the common shape."""
    runner = RUNNERS.get(name)
    if runner is None:
        raise ValueError(name)
    from jarvis.collectors import verify_inventory
    return verify_inventory.apply(name, runner(hosts, db_path))
