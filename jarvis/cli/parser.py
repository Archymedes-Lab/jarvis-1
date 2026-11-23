"""Argument parsing and process entry point."""

import argparse
import sys

from jarvis.core import statedir
from jarvis.core.store import DEFAULT_DB, Store
from jarvis.intel import feeds
from jarvis.intel import research as intel
from jarvis.service import selfcheck

from .commands import ack as ack_cli
from .commands import arena as arena_cli
from .commands import ask as ask_cli
from .commands import attack as attack_cli
from .commands import brief as brief_cli
from .commands import broker as broker_cli
from .commands import canary as canary_cli
from .commands import (
    cmd_alert,
    cmd_approve,
    cmd_asep,
    cmd_audio,
    cmd_auditd,
    cmd_backdoor,
    cmd_baseline,
    cmd_boot,
    cmd_bruteforce,
    cmd_containers,
    cmd_content,
    cmd_control,
    cmd_coverage,
    cmd_dotnet,
    cmd_evasion,
    cmd_events,
    cmd_feeds,
    cmd_firewall,
    cmd_gaps,
    cmd_hidden,
    cmd_hunt,
    cmd_implant,
    cmd_inputwatch,
    cmd_intel,
    cmd_intrusion,
    cmd_investigate,
    cmd_memscan,
    cmd_netwatch,
    cmd_outstanding,
    cmd_peers,
    cmd_posture,
    cmd_preos,
    cmd_procs,
    cmd_scan,
    cmd_secrets,
    cmd_selfcheck,
    cmd_serve,
    cmd_sniffing,
    cmd_spy,
    cmd_status,
    cmd_sysmon,
    cmd_sysmon_linux,
    cmd_toolchain,
    cmd_watch,
    cmd_webshell,
    cmd_wslmanifest,
)
from .commands import defend as defend_cli
from .commands import desktop as desktop_cli
from .commands import evidence as evidence_cli
from .commands import fix as fix_cli
from .commands import geo as geo_cli
from .commands import history as history_cli
from .commands import impersonation as impersonation_cli
from .commands import incidents as incidents_cli
from .commands import inspect as inspect_cli
from .commands import lifecycle as lifecycle_cli
from .commands import linuxguard as linuxguard_cli
from .commands import mesh as mesh_cli
from .commands import model as model_cli
from .commands import native as native_cli
from .commands import notify as notify_cli
from .commands import pixel as pixel_cli
from .commands import privacy as privacy_cli
from .commands import provenance as provenance_cli
from .commands import reason as reason_cli
from .commands import repair as repair_cli
from .commands import retention as retention_cli
from .commands import rules as rules_cli
from .commands import sensor as sensor_cli
from .commands import server as server_cli
from .commands import timeline as timeline_cli
from .commands import update as update_cli
from .commands import veil as veil_cli
from .commands import welcome as welcome_cli


def build_parser():
    p = argparse.ArgumentParser(
        prog="jarvis",
        description="Watch processes, scripts, network peers and control surfaces "
                    "across WSL and Windows.",
    )
    p.add_argument("--db", default=DEFAULT_DB, help="database path")
    p.add_argument("--host", choices=["wsl", "win", "all"], default="all")
    sub = p.add_subparsers(dest="cmd", required=True)
    repair_cli.add_parser(sub)
    ack_cli.add_parser(sub)
    linuxguard_cli.add_parser(sub)
    rules_cli.add_parser(sub)
    ask_cli.add_parser(sub)
    brief_cli.add_parser(sub)
    broker_cli.add_parser(sub)
    attack_cli.add_parser(sub)
    arena_cli.add_parser(sub)
    defend_cli.add_parser(sub)
    fix_cli.add_parser(sub)
    incidents_cli.add_parser(sub)
    inspect_cli.add_parser(sub)
    sensor_cli.add_parser(sub)
    geo_cli.add_parser(sub)
    canary_cli.add_parser(sub)
    server_cli.add_parser(sub)
    notify_cli.add_parser(sub)
    update_cli.add_parser(sub)
    model_cli.add_parser(sub)
    privacy_cli.add_parser(sub)
    timeline_cli.add_parser(sub)
    history_cli.add_parser(sub)
    mesh_cli.add_parser(sub)
    reason_cli.add_parser(sub)
    veil_cli.add_parser(sub)
    desktop_cli.add_parser(sub)
    lifecycle_cli.add_parser(sub)

    b = sub.add_parser("baseline", help="record the current state as known-good")
    b.add_argument("--reset", action="store_true",
                   help="forget the old baseline first instead of adding to it")
    b.set_defaults(fn=cmd_baseline)

    s = sub.add_parser("scan", help="one pass: report drift and suspicious traits")
    s.add_argument("--enrich", action="store_true", help="reverse-DNS public IPs")
    s.add_argument("--json", action="store_true")
    s.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(fn=cmd_scan)

    w = sub.add_parser("watch", help="scan continuously")
    w.add_argument("-i", "--interval", type=int, default=60)
    w.add_argument("--enrich", action="store_true")
    w.add_argument("-v", "--verbose", action="store_true", help="print quiet passes too")
    w.add_argument("--limit", type=int, default=10)
    w.set_defaults(fn=cmd_watch)

    c = sub.add_parser("control",
                       help="audit persistence, remote access and security controls")
    c.add_argument("--category", choices=["persistence", "remote", "defense"])
    c.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    c.add_argument("--json", action="store_true")
    c.add_argument("-v", "--verbose", action="store_true")
    c.set_defaults(fn=cmd_control)

    h = sub.add_parser("hidden",
                       help="cross-view scan for processes hiding from listings")
    h.add_argument("--deep", action="store_true",
                   help="sweep the full pid range instead of the first 65536")
    h.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    h.add_argument("--json", action="store_true")
    h.set_defaults(fn=cmd_hidden)

    sp = sub.add_parser("spy",
                        help="monitoring software, mic/camera use, input control")
    sp.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    sp.add_argument("-v", "--verbose", action="store_true")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=cmd_spy)

    au = sub.add_parser("audio", help="Windows audio endpoints, routes and sessions")
    au.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    au.add_argument("-v", "--verbose", action="store_true")
    au.add_argument("--json", action="store_true")
    au.set_defaults(fn=cmd_audio)

    po = sub.add_parser("preos", help="pre-OS boot integrity: firmware, Secure Boot, TPM measured boot")
    po.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    po.add_argument("-v", "--verbose", action="store_true")
    po.add_argument("--json", action="store_true")
    po.add_argument("--accept-baseline", action="store_true",
                    help="pin the newest cold boot as the new baseline (owner decision)")
    po.set_defaults(fn=cmd_preos)

    co = sub.add_parser("containers", help="local Docker privilege and exposure inventory")
    co.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    co.add_argument("-v", "--verbose", action="store_true")
    co.add_argument("--json", action="store_true")
    co.set_defaults(fn=cmd_containers)

    bo = sub.add_parser("boot",
                        help="what ran at startup, incl. windows that flash and close")
    bo.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    bo.add_argument("-v", "--verbose", action="store_true")
    bo.add_argument("--json", action="store_true")
    bo.add_argument("--trace", action="store_true",
                    help="save private startup/recent process and task evidence")
    bo.add_argument("--watch-seconds", type=int, choices=range(1, 601), metavar="1..600",
                    help="observe visible windows, then save a trace (implies --trace)")
    bo.set_defaults(fn=cmd_boot)

    fw = sub.add_parser("firewall",
                        help="firewall posture, inbound rules and remote connections")
    fw.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    fw.add_argument("-v", "--verbose", action="store_true")
    fw.add_argument("--json", action="store_true")
    fw.set_defaults(fn=cmd_firewall)

    it = sub.add_parser("intrusion",
                        help="pasted commands, infostealer and extension artifacts")
    it.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    it.add_argument("-v", "--verbose", action="store_true")
    it.add_argument("--json", action="store_true")
    it.set_defaults(fn=cmd_intrusion)

    cv = sub.add_parser("coverage",
                        help="self-audit: blind spots, stale collectors, failures")
    cv.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    cv.add_argument("-v", "--verbose", action="store_true")
    cv.add_argument("--json", action="store_true")
    cv.set_defaults(fn=cmd_coverage)

    ev = sub.add_parser("evasion",
                        help="BYOVD, alternate data streams, LNK abuse, dead-drop C2")
    ev.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    ev.add_argument("-v", "--verbose", action="store_true")
    ev.add_argument("--json", action="store_true")
    ev.set_defaults(fn=cmd_evasion)

    ap = sub.add_parser("asep",
                        help="autostart extensibility points beyond Run keys")
    ap.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.set_defaults(fn=cmd_asep)

    sv = sub.add_parser("serve",
                        help="run the 24/7 daemon and local dashboard")
    sv.add_argument("-p", "--port", type=int, default=8787)
    sv.add_argument("--supervised", action="store_true",
                    help="started by the watchdog task or the desktop app: one instance only, "
                         "respect `argus stop`, and do not restart in a loop (service/supervision.py)")
    sv.set_defaults(fn=cmd_serve)

    inv = sub.add_parser("investigate",
                         help="run every audit at once — start here if you suspect something")
    inv.add_argument("--deep", action="store_true")
    inv.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    inv.add_argument("-v", "--verbose", action="store_true")
    inv.set_defaults(fn=cmd_investigate)


    it2 = sub.add_parser("intel",
                         help="refresh the threat-intelligence knowledge base")
    it2.add_argument("--topic", action="append",
                     choices=sorted(intel.CORPUS),
                     help="refresh only this topic (repeatable)")
    it2.add_argument("--all", action="store_true", help="refresh every topic")
    it2.add_argument("--results", type=int, default=6,
                     help="results per query (default 6)")
    it2.add_argument("--days", type=int, default=365,
                     help="only consider writeups published in the last N days")
    it2.add_argument("--set-key", metavar="KEY", help="store the Exa API key")
    it2.add_argument("--revet", action="store_true",
                     help="re-judge stored indicators against the current rules")
    it2.add_argument("--show", action="store_true",
                     help="show what the knowledge base holds")
    it2.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    it2.add_argument("-v", "--verbose", action="store_true")
    it2.add_argument("--json", action="store_true")
    it2.set_defaults(fn=cmd_intel)

    sm = sub.add_parser("sysmon",
                        help="LSASS access, injection and tampering from Sysmon")
    sm.add_argument("--hours", type=int, default=24,
                    help="how far back to read (default 24)")
    sm.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    sm.add_argument("-v", "--verbose", action="store_true")
    sm.add_argument("--json", action="store_true")
    sm.set_defaults(fn=cmd_sysmon)

    sc = sub.add_parser("secrets",
                        help="credentials sitting in plaintext on disk")
    sc.add_argument("--path", action="append",
                    help="scan this directory instead (repeatable)")
    sc.add_argument("--deep", action="store_true",
                    help="scan all of $HOME, including dependency trees")
    sc.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    sc.add_argument("-v", "--verbose", action="store_true")
    sc.add_argument("--json", action="store_true")
    sc.set_defaults(fn=cmd_secrets)

    mem = sub.add_parser("memscan",
                         help="unbacked executable memory, hooked ntdll stubs, "
                              "process mitigations")
    mem.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    mem.add_argument("-v", "--verbose", action="store_true")
    mem.add_argument("--json", action="store_true")
    mem.set_defaults(fn=cmd_memscan)

    dn = sub.add_parser("dotnet", help=".NET runtime hijack and AMSI registration")
    dn.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    dn.add_argument("-v", "--verbose", action="store_true")
    dn.add_argument("--json", action="store_true")
    dn.set_defaults(fn=cmd_dotnet)

    iw = sub.add_parser("inputwatch",
                        help="detect keystrokes and clicks no hardware produced")
    iw.add_argument("--start", action="store_true", help="start the hook helper")
    iw.add_argument("--stop", action="store_true", help="stop the hook helper")
    iw.add_argument("--own", action="store_true",
                    help="make this install the one that runs the machine's input hook")
    iw.add_argument("--hours", type=int, default=24,
                    help="how far back to report (default 24)")
    iw.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    iw.add_argument("-v", "--verbose", action="store_true")
    iw.add_argument("--json", action="store_true")
    iw.set_defaults(fn=cmd_inputwatch)

    wm = sub.add_parser("wslmanifest",
                        help="what WSL runs, by owner, against the approved manifest")
    wm.add_argument("--approve", action="store_true",
                    help="approve everything running now as the expected set")
    wm.add_argument("--partial", action="store_true",
                    help="with --approve: accept a view that cannot read every process")
    wm.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    wm.add_argument("-v", "--verbose", action="store_true")
    wm.add_argument("--json", action="store_true")
    wm.set_defaults(fn=cmd_wslmanifest)

    bd = sub.add_parser("backdoor",
                        help="SSH keys, sudo grants, autostart units, accounts")
    bd.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    bd.add_argument("-v", "--verbose", action="store_true")
    bd.add_argument("--json", action="store_true")
    bd.set_defaults(fn=cmd_backdoor)

    od = sub.add_parser("outstanding",
                        help="alerts already sent that were never resolved, "
                             "and ones that came back")
    od.add_argument("--all", action="store_true",
                    help="also list the resolved ones")
    od.add_argument("--limit", type=int, default=20)
    od.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    od.add_argument("-v", "--verbose", action="store_true")
    od.add_argument("--json", action="store_true")
    od.set_defaults(fn=cmd_outstanding)

    tc = sub.add_parser("toolchain",
                        help="MCP servers, agent hooks, editor extensions, "
                             "git hooks, package sources")
    tc.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    tc.add_argument("-v", "--verbose", action="store_true")
    tc.add_argument("--json", action="store_true")
    tc.set_defaults(fn=cmd_toolchain)

    po = sub.add_parser("posture",
                        help="Windows security settings: what is on and what to set")
    po.add_argument("--elevate", action="store_true",
                    help="re-run through a UAC prompt to read the "
                         "administrator-only checks")
    po.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    po.add_argument("-v", "--verbose", action="store_true")
    po.add_argument("--json", action="store_true")
    po.set_defaults(fn=cmd_posture)

    nw = sub.add_parser("netwatch",
                        help="record network state and report tampering signs")
    nw.add_argument("--hours", type=int, default=24,
                    help="how far back to report (default 24)")
    nw.add_argument("--timeline", action="store_true",
                    help="print the recorded event history instead")
    nw.add_argument("--no-sample", action="store_true",
                    help="report only; do not take a new sample")
    nw.add_argument("--confirm-network", metavar="SSID",
                    help="pin this SSID's recorded access points and gateway as your network")
    nw.add_argument("--forget-network", metavar="SSID",
                    help="remove a network confirmation")
    nw.add_argument("--reason", help="why (required with --confirm-network)")
    nw.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    nw.add_argument("-v", "--verbose", action="store_true")
    nw.add_argument("--json", action="store_true")
    nw.set_defaults(fn=cmd_netwatch)

    im = sub.add_parser("implant",
                        help="interception, boundary bypass, trust subversion")
    im.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    im.add_argument("-v", "--verbose", action="store_true")
    im.add_argument("--json", action="store_true")
    im.set_defaults(fn=cmd_implant)

    fd = sub.add_parser("feeds",
                        help="refresh free bulk indicator feeds (no API key)")
    fd.add_argument("--feed", action="append", choices=sorted(feeds.FEEDS),
                    help="refresh only this feed (repeatable)")
    fd.add_argument("--force", action="store_true",
                    help="refresh even if not yet due")
    fd.add_argument("--attack", action="store_true",
                    help="also refresh the MITRE ATT&CK catalogue")
    fd.add_argument("--status", action="store_true", help="show feed health")
    fd.add_argument("--prune", action="store_true",
                    help="retire feed indicators no longer listed")
    fd.add_argument("--days", type=int, default=90,
                    help="staleness threshold for --prune (default 90)")
    fd.set_defaults(fn=cmd_feeds)

    hu = sub.add_parser("hunt",
                        help="check stored indicators against this machine")
    hu.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    hu.add_argument("-v", "--verbose", action="store_true")
    hu.add_argument("--json", action="store_true")
    hu.set_defaults(fn=cmd_hunt)

    gp = sub.add_parser("gaps",
                        help="techniques in current intel that nothing checks")
    gp.add_argument("--min-docs", type=int, default=1,
                    help="only techniques seen in at least N writeups")
    gp.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    gp.add_argument("-v", "--verbose", action="store_true")
    gp.add_argument("--json", action="store_true")
    gp.set_defaults(fn=cmd_gaps)

    pr = sub.add_parser("procs", help="list baseline fingerprints or every process in a live snapshot")
    pr.add_argument("--approved", type=int, choices=[0, 1])
    pr.add_argument("--live", action="store_true",
                    help="take a fresh process snapshot; show all observed processes")
    pr.add_argument("--json", action="store_true")
    pr.add_argument("--limit", type=int, default=None,
                    help="limit displayed rows (live mode shows all by default)")
    pr.set_defaults(fn=cmd_procs)

    pe = sub.add_parser("peers", help="list observed network peers")
    pe.add_argument("--scope", choices=["public", "private", "loopback"])
    pe.add_argument("--limit", type=int, default=60)
    pe.set_defaults(fn=cmd_peers)

    e = sub.add_parser("events", help="recent alerts")
    e.add_argument("--limit", type=int, default=40)
    e.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    e.add_argument("--since", type=int, metavar="HOURS")
    e.add_argument("-v", "--verbose", action="store_true")
    e.set_defaults(fn=cmd_events)

    a = sub.add_parser("approve", help="mark fingerprints as known-good")
    a.add_argument("fingerprint", nargs="+")
    a.add_argument("--note", default="")
    a.set_defaults(fn=cmd_approve)

    st = sub.add_parser("status", help="show what JARVIS knows so far")
    st.set_defaults(fn=cmd_status)

    bf = sub.add_parser("bruteforce",
                        help="failed-authentication spikes and account lockouts")
    bf.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    bf.add_argument("-v", "--verbose", action="store_true")
    bf.add_argument("--json", action="store_true")
    bf.set_defaults(fn=cmd_bruteforce)

    for _name, _fn, _help in (
        ("content", cmd_content, "bounded read-only community file-content scan"),
        ("sniffing", cmd_sniffing, "packet capture: promiscuous NICs, raw "
         "sockets, capture drivers and tools"),
        ("webshell", cmd_webshell, "server-side scripts that read as command "
         "dispatchers in web roots"),
        ("auditd", cmd_auditd, "is Linux syscall interception installed and "
         "recording?"),
        ("sysmon-linux", cmd_sysmon_linux, "eBPF syscall events from Sysmon "
         "for Linux, with rules"),
    ):
        _p = sub.add_parser(_name, help=_help)
        _p.add_argument("--severity",
                        choices=["critical", "high", "medium", "low"])
        _p.add_argument("-v", "--verbose", action="store_true")
        _p.add_argument("--json", action="store_true")
        _p.set_defaults(fn=_fn)

    al = sub.add_parser("alert",
                        help="email alerts via Resend: status, or --test")
    al.add_argument("--test", action="store_true",
                    help="send a test alert to the configured recipients")
    al.set_defaults(fn=cmd_alert)

    sk = sub.add_parser(
        "selfcheck",
        help="is the daemon actually monitoring? run from a timer outside it")
    sk.add_argument("--restart", action="store_true",
                    help="restart jarvis.service if it is not healthy")
    sk.add_argument("--attempts", type=int, default=selfcheck.ATTEMPTS,
                    metavar="N",
                    help=f"re-check up to N times before declaring it down "
                         f"(default {selfcheck.ATTEMPTS})")
    sk.add_argument("--no-mail", action="store_true",
                    help="do not send an alert, just report")
    sk.add_argument("--quiet", action="store_true",
                    help="exit status only")
    sk.add_argument("--json", action="store_true")
    sk.set_defaults(fn=cmd_selfcheck)

    # Owned by the evidence package so the subcommand and its implementation
    # stay together rather than growing this module further.
    evidence_cli.add_parser(sub)
    pixel_cli.add_parser(sub)
    impersonation_cli.add_parser(sub)
    retention_cli.add_parser(sub)
    provenance_cli.add_parser(sub)
    welcome_cli.add_parser(sub)
    native_cli.add_parser(sub)
    return p


def safe_streams(streams=None):
    """Make printing never fail on the encoding. A redirected stdout on Windows
    (the service's daemon.out.log) is cp1252, and one arrow in a status line
    stopped the whole daemon: redirected output becomes UTF-8, and a console
    keeps its encoding but replaces what it cannot show."""
    names = ("stdout", "stderr")
    for name, stream in zip(names, streams or [getattr(sys, n) for n in names]):
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            tty = stream.isatty()
        except (OSError, ValueError):
            tty = False
        try:
            if tty:
                stream.reconfigure(errors="replace")
            else:
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


def main(argv=None):
    safe_streams()
    args = build_parser().parse_args(argv)
    if args.cmd == 'serve' and getattr(args, 'supervised', False):
        # Before anything opens the store: a duplicate start must cost nothing.
        from jarvis.service import supervision
        refused = supervision.gate(args.port)
        if refused is not None:
            return refused
    if (args.cmd == 'mesh' or getattr(args, 'no_store', False)
            or (args.cmd == 'desktop' and args.action in ('save', 'browser'))):
        # Mesh owns its isolated store, and the server network sensors run as
        # their own account without access to it: never open the protected
        # collector DB for them. `desktop save` only writes the caller's token;
        # `desktop browser` only asks the running daemon for a link.
        return args.fn(args, None)
    refusal = statedir.cli_refusal(args.db, DEFAULT_DB, argv if argv is not None else sys.argv[1:])
    if refusal:
        # The daemon runs as its own account: this account's ~/.jarvis is not
        # the daemon's store, and opening it would show stale or empty state.
        print(refusal, file=sys.stderr)
        return 2
    store = Store(args.db)
    try:
        rc = args.fn(args, store)
    finally:
        store.close()
    # A command's integer result is the exit code (installers and scripts read it);
    # None, a bool or anything else is success, as before.
    return rc if isinstance(rc, int) and not isinstance(rc, bool) else 0
