"""Restart autopsy (collectors/host/restarts.py): invariants I1-I5.

The fixtures are shaped on the real records of 2026-11-03/04: systemd's
catalogue messages for jarvis.service and Linux Sysmon process-create events
as the journal carries them (XML, UtcTime = process start, written to the
journal behind Sysmon's queue).
"""

import json
import time
import unittest
from datetime import datetime, timezone

from jarvis.collectors.host import restarts as R

T = 1793746512.375          # the real stop of 2026-11-04 00:55:12 (EET)
INV = "f308817811ce4ffb93f57c5fd470cfc2"
NEXT = "fbcde6d5d9ae475ca92f354a052e84c6"
WIN_CMD = ("bash -lc systemctl restart jarvis.service 2>/dev/null "
           "|| sudo -n systemctl restart jarvis.service")


class Store:
    def __init__(self, meta=None):
        self.meta = dict(meta or {})

    def get_meta(self, key, default=None):
        return self.meta.get(key, default)

    def set_meta(self, key, value):
        self.meta[key] = value


def unit(ts, message_id, msg, inv=INV, pid="1", **extra):
    return json.dumps({"__REALTIME_TIMESTAMP": str(int(ts * 1e6)), "MESSAGE_ID": message_id,
                       "MESSAGE": msg, "INVOCATION_ID": inv, "_PID": pid, "_BOOT_ID": "b" * 32, **extra})


def restart_job(t=T, inv=INV):
    return [unit(t, R.MSG_STOPPING, "Stopping jarvis.service - JARVIS...", inv, JOB_TYPE="stop"),
            unit(t + 0.16, R.MSG_DEACTIVATED, "jarvis.service: Deactivated successfully.", inv),
            unit(t + 0.17, R.MSG_STOPPED, "Stopped jarvis.service - JARVIS.", inv, JOB_TYPE="restart"),
            unit(t + 0.25, R.MSG_STARTED, "Started jarvis.service - JARVIS.", NEXT, JOB_TYPE="start")]


def utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def proc(ts, pid, image, cmd, ppid="-", user="chris", cwd="/mnt/c/Users/chris/Documents",
         parent_image="-", guid=None, parent_guid=None):
    data = {"UtcTime": utc(ts), "ProcessGuid": guid or f"{{g-{pid}-{image}}}", "ProcessId": str(pid),
            "Image": image, "CommandLine": cmd, "CurrentDirectory": cwd, "User": user,
            "ParentProcessGuid": parent_guid or "-", "ParentProcessId": str(ppid),
            "ParentImage": parent_image, "ParentCommandLine": "-"}
    body = "".join(f'<Data Name="{k}">{v.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")}</Data>'
                   for k, v in data.items())
    return (f'<Event><System><EventID>1</EventID><TimeCreated SystemTime="{utc(ts + 80)}"/></System>'
            f"<EventData>{body}</EventData></Event>")


def windows_restart(t=T):
    """The real 00:55 lineage: bash -lc from wsl.exe (no Linux parent), the
    user-level systemctl that polkit refused, bash exec'ing sudo, sudo's
    unrecorded fork, the root systemctl that did it."""
    return [
        proc(t - 3.18, 26680, "/usr/bin/bash", WIN_CMD, ppid=26677, guid="{bash}"),
        proc(t - 1.76, 26688, "/usr/bin/systemctl", "systemctl restart jarvis.service", ppid=26680,
             parent_image="/usr/bin/bash", parent_guid="{bash}"),
        proc(t - 3.18, 26680, "/usr/bin/sudo", "sudo -n systemctl restart jarvis.service", ppid=26677,
             guid="{sudo}"),
        proc(t - 0.04, 26764, "/usr/bin/systemctl", "systemctl restart jarvis.service", ppid=26762,
             user="root"),
    ]


def tail(t=T):
    """A Sysmon record past the stop, proving the queue has caught up."""
    return [proc(t + 5, 99999, "/usr/bin/true", "true", ppid=1, cwd="/", parent_image="/usr/lib/systemd/systemd")]


# The Sysmon read must carry journald's trusted fields, not only `-t sysmon`
# (SYSLOG_IDENTIFIER, which any account sets): FZ-04's rule.
SYSMON_ARGV = ["journalctl", "_SYSTEMD_UNIT=sysmon.service", "_UID=0", "-t", "sysmon"]


def fake_run(unit_lines, sysmon_events, main_pid="275", journal_ok=True):
    calls = []

    def run(argv, timeout=40):
        calls.append(argv)
        if argv[:2] == ["journalctl", "-u"]:
            return (0, "\n".join(unit_lines)) if journal_ok else (None, "the system journal is not readable")
        if argv[:len(SYSMON_ARGV)] == SYSMON_ARGV:
            return 0, "\n".join(sysmon_events)
        if "sysmon" in argv:
            raise AssertionError(f"Sysmon read without the trusted match: {argv}")
        if argv[0] == "journalctl" and argv[1].startswith("_SYSTEMD_INVOCATION_ID="):
            return 0, json.dumps({"_PID": main_pid}) if main_pid else ""
        raise AssertionError(argv)
    run.calls = calls
    return run


def claims(*items):
    return lambda: (list(items), "")


def judge(unit_lines, sysmon_events, claim_reader=None, store=None, now=T + 600, **kw):
    store = store or Store()
    claim_reader = claim_reader or claims()
    out = R.audit(store, now=now, run=fake_run(unit_lines, sysmon_events, **kw), claims_reader=claim_reader)
    return out, R.ledger(store), store


class Attribution(unittest.TestCase):
    def test_the_real_reviver_restart_is_explained(self):
        out, ledger, _ = judge(restart_job(), windows_restart() + tail(),
                               claims(("reviver", T - 7.4, "active but silent for 110s")))
        self.assertEqual(len(ledger), 1)
        v = ledger[0]
        self.assertEqual((v["verdict"], v["actor"]), ("explained", "reviver"))
        self.assertEqual(v["origin"], "Windows, through wsl.exe (no Linux parent)")
        self.assertEqual(v["issuer_user"], "root")
        self.assertEqual(v["lineage"], ["systemctl", "sudo"])   # the root child joined to its sudo
        self.assertEqual(out, [])

    def test_wake_watchdog_misread_is_contradicted_by_systemd(self):
        state = "if this error was unexpected, please consider searching for existing issues"
        out, ledger, _ = judge(restart_job(), windows_restart() + tail(),
                               claims(("wake-watchdog", T - 1.8, state)))
        self.assertEqual(ledger[0]["verdict"], "unjustified")
        self.assertIn("not a systemctl state", ledger[0]["contradiction"])
        self.assertEqual([(f["severity"], f["category"]) for f in out], [("medium", "tamper")])

    def test_wake_watchdog_claiming_a_real_down_state_is_still_contradicted_on_a_running_unit(self):
        _out, ledger, _ = judge(restart_job(), windows_restart() + tail(),
                                claims(("wake-watchdog", T - 2, "inactive")))
        self.assertEqual(ledger[0]["verdict"], "unjustified")

    def test_reviver_silence_contradicted_by_daemon_children(self):
        kids = [proc(T - 30, 4000 + i, "/usr/bin/python3.12", "python3 -m jarvis.service.collector_worker x",
                     ppid=275, cwd="/", parent_image="/usr/bin/python3.12") for i in range(3)]
        out, ledger, _ = judge(restart_job(), windows_restart() + kids + tail(),
                               claims(("reviver", T - 2, "active but silent for 110s")))
        self.assertEqual(ledger[0]["verdict"], "unjustified")
        self.assertIn("3 collector process", ledger[0]["contradiction"])
        self.assertEqual(out[0]["severity"], "medium")

    def test_deploy_and_selfcheck_are_named_from_the_lineage(self):
        for actor, parent_cmd in (("deploy", "python3 -I /opt/x/scripts/deploy_root_runtime.py --enable"),
                                  ("selfcheck", "/usr/bin/python3 -m jarvis selfcheck --restart --quiet")):
            ev = [proc(T - 5, 500, "/usr/bin/python3.12", parent_cmd, ppid=1, cwd="/",
                       parent_image="/usr/sbin/cron", guid="{p}"),
                  proc(T - 1, 501, "/usr/bin/systemctl", "systemctl restart jarvis.service", ppid=500,
                       cwd="/", parent_image="/usr/bin/python3.12", parent_guid="{p}")]
            _out, ledger, _ = judge(restart_job(), ev + tail())
            self.assertEqual((ledger[0]["verdict"], ledger[0]["actor"]), ("explained", actor))

    def test_crash_and_systemd_watchdog_are_reported_without_sysmon(self):
        crash = [unit(T, R.MSG_EXITED, "Main process exited, code=dumped, status=6/ABRT",
                      EXIT_CODE="dumped", EXIT_STATUS="6")]
        out, ledger, _ = judge(crash, [])
        self.assertEqual((ledger[0]["kind"], ledger[0]["verdict"]), ("crash", "crashed"))
        self.assertEqual(out[0]["severity"], "medium")
        hang = [unit(T, "", "jarvis.service: Watchdog timeout (limit 15min)!"),
                unit(T + 1, R.MSG_FAILED, "jarvis.service: Failed with result 'watchdog'.")]
        _out, ledger, _ = judge(hang, [])
        self.assertEqual((ledger[0]["kind"], ledger[0]["actor"]), ("watchdog", "systemd watchdog"))

    def test_kill_term_is_a_signal_that_needs_a_sender(self):
        killed = [unit(T, R.MSG_EXITED, "Main process exited, code=killed, status=15/TERM",
                       EXIT_CODE="killed", EXIT_STATUS="15")]
        _out, ledger, _ = judge(killed, tail())
        self.assertEqual((ledger[0]["kind"], ledger[0]["verdict"]), ("signal", "unexplained"))
        sender = [proc(T - 1, 700, "/usr/bin/kill", "kill -TERM 275", ppid=1, cwd="/", parent_image="/x")]
        _out, ledger, _ = judge(killed, sender + tail())
        self.assertEqual(ledger[0]["issuer"], "kill -TERM 275")
        self.assertEqual(ledger[0]["verdict"], "unexplained")   # a known kill, but no known actor


class NoSelfExoneration(unittest.TestCase):
    """I3: a claim alone never explains a stop."""

    def test_claim_without_the_signature_lineage_is_unexplained(self):
        ev = [proc(T - 1, 800, "/usr/bin/systemctl", "systemctl restart jarvis.service", ppid=1,
                   cwd="/tmp", parent_image="/usr/bin/python3.12")]
        out, ledger, _ = judge(restart_job(), ev + tail(),
                               claims(("reviver", T - 1, "active but silent for 110s")))
        self.assertEqual(ledger[0]["verdict"], "unexplained")
        self.assertEqual(out[0]["severity"], "high")
        self.assertEqual(out[0]["category"], "tamper")

    def test_signature_lineage_without_a_claim_is_unexplained(self):
        out, ledger, _ = judge(restart_job(), windows_restart() + tail(), claims())
        self.assertEqual(ledger[0]["verdict"], "unexplained")
        self.assertIn("none of their logs", ledger[0]["evidence"])
        self.assertEqual(out[0]["severity"], "high")

    def test_a_claim_far_from_the_stop_does_not_count(self):
        _out, ledger, _ = judge(restart_job(), windows_restart() + tail(),
                                claims(("reviver", T - R.CLAIM_WINDOW_S - 5, "active but silent for 110s")))
        self.assertEqual(ledger[0]["verdict"], "unexplained")

    def test_one_claim_explains_one_stop(self):
        t2 = T + 200
        lines = restart_job() + restart_job(t2, NEXT)
        out, ledger, _ = judge(lines, windows_restart() + windows_restart(t2) + tail(t2),
                               claims(("reviver", T - 2, "active but silent for 110s")), now=t2 + 600)
        self.assertEqual(sorted(v["verdict"] for v in ledger), ["explained", "unexplained"])

    def test_no_restart_command_at_all_is_unexplained(self):
        out, ledger, _ = judge(restart_job(), tail())
        self.assertEqual(ledger[0]["verdict"], "unexplained")
        self.assertEqual(out[0]["severity"], "high")


class EvidenceIsNeverBenign(unittest.TestCase):
    """I2: missing or late evidence is unknown, then unexplained."""

    def test_sysmon_behind_the_stop_is_retried_then_unexplained(self):
        store = Store()
        lines = restart_job()
        for i in range(R.MAX_TRIES - 1):
            out, ledger, _ = judge(lines, windows_restart(), store=store, now=T + 600 + i)
            self.assertEqual(ledger, [], f"judged on try {i + 1} with Sysmon behind the stop")
            self.assertEqual(out, [])
        out, ledger, _ = judge(lines, windows_restart(), store=store, now=T + 700)
        self.assertEqual(ledger[0]["verdict"], "unexplained")
        self.assertIn(f"{R.MAX_TRIES} runs", ledger[0]["evidence"])
        self.assertEqual(out[0]["severity"], "high")

    def test_sysmon_catching_up_during_the_retries_is_judged_on_the_evidence(self):
        store = Store()
        judge(restart_job(), windows_restart(), store=store)
        _out, ledger, _ = judge(restart_job(), windows_restart() + tail(), store=store,
                                claim_reader=claims(("reviver", T - 2, "active but silent for 110s")))
        self.assertEqual(ledger[0]["verdict"], "explained")

    def test_unreadable_claim_log_is_retried_not_treated_as_no_claim(self):
        store = Store()
        broken = lambda: ([], "reviver log unreadable: OSError")   # noqa: E731
        _out, ledger, _ = judge(restart_job(), windows_restart() + tail(), broken, store=store)
        self.assertEqual(ledger, [])
        _out, ledger, _ = judge(restart_job(), windows_restart() + tail(),
                                claims(("reviver", T - 2, "active but silent for 110s")), store=store)
        self.assertEqual(ledger[0]["verdict"], "explained")

    def test_unreadable_journal_is_a_visibility_finding(self):
        out, ledger, _ = judge(restart_job(), [], journal_ok=False)
        self.assertEqual(ledger, [])
        self.assertEqual([(f["category"], f["severity"]) for f in out], [("visibility", "medium")])

    def test_corrupt_stored_state_restarts_and_says_so(self):
        store = Store({R.STATE_META: "{not json"})
        out, ledger, _ = judge(restart_job(), windows_restart() + tail(), store=store,
                               claim_reader=claims(("reviver", T - 2, "active but silent for 110s")))
        self.assertEqual(ledger[0]["verdict"], "explained")
        self.assertTrue(any("could not be read" in f["detail"] for f in out if f["category"] == "visibility"))

    def test_a_stop_still_settling_is_left_for_the_next_run(self):
        out, ledger, store = judge(restart_job(), windows_restart() + tail(), now=T + R.SETTLE_S - 1)
        self.assertEqual(ledger, [])
        self.assertLessEqual(json.loads(store.meta[R.STATE_META])["cursor"], T)

    def test_the_issuer_record_arriving_after_the_stop_is_read(self):
        # Sysmon wrote the issuer ~80 s late; the read must reach past the stop.
        run = fake_run(restart_job(), windows_restart() + tail())
        R.audit(Store(), now=T + 600, run=run, claims_reader=claims())
        sysmon = [a for a in run.calls if a[:len(SYSMON_ARGV)] == SYSMON_ARGV][0]
        until = int(sysmon[sysmon.index("--until") + 1].lstrip("@"))
        self.assertGreaterEqual(until, T + R.INGEST_LAG_S)


class EveryStopOnce(unittest.TestCase):
    """I1 and I4."""

    def test_every_stop_gets_exactly_one_verdict_across_runs(self):
        store = Store()
        stops = [T + i * 400 for i in range(7)]
        lines = [x for i, t in enumerate(stops) for x in restart_job(t, f"{i:032x}")]
        ev = [e for t in stops for e in windows_restart(t)] + tail(stops[-1])
        for k in range(5):
            judge(lines, ev, store=store, now=stops[-1] + 600 + k)
        ledger = R.ledger(store)
        self.assertEqual(sorted(v["invocation"] for v in ledger), sorted(f"{i:032x}" for i in range(7)))
        self.assertEqual(len({v["invocation"] for v in ledger}), len(ledger))

    def test_a_run_judges_at_most_the_bound(self):
        stops = [T + i * 400 for i in range(R.MAX_STOPS_PER_RUN + 3)]
        lines = [x for i, t in enumerate(stops) for x in restart_job(t, f"{i:032x}")]
        ev = [e for t in stops for e in windows_restart(t)] + tail(stops[-1])
        _out, ledger, _ = judge(lines, ev, now=stops[-1] + 600)
        self.assertEqual(len(ledger), R.MAX_STOPS_PER_RUN)

    def test_old_verdicts_expire_and_stay_bounded(self):
        old = {"cursor": T, "pending": {}, "verdicts": [
            {"t": T - R.KEEP_S - 10, "invocation": "x" * 12, "kind": "requested", "verdict": "unexplained"}]}
        _out, ledger, _ = judge([], [], store=Store({R.STATE_META: json.dumps(old)}))
        self.assertEqual(ledger, [])

    def test_running_unit_has_no_verdict(self):
        started = [unit(T, R.MSG_STARTED, "Started jarvis.service", JOB_TYPE="start")]
        out, ledger, _ = judge(started, tail())
        self.assertEqual((out, ledger), ([], []))


class Privacy(unittest.TestCase):
    """I5: only the restart command itself is kept; the lineage is image names."""

    def test_lineage_keeps_image_names_and_drops_other_command_lines(self):
        secret_parent = proc(T - 4, 900, "/usr/bin/bash", "bash -c 'export TOKEN=hunter2; do-things'",
                             ppid=1, cwd="/home/chris", parent_image="/usr/bin/login", guid="{s}")
        child = proc(T - 1, 901, "/usr/bin/systemctl", "systemctl stop jarvis.service", ppid=900,
                     cwd="/home/chris", parent_image="/usr/bin/bash", parent_guid="{s}")
        out, ledger, store = judge(restart_job(), [secret_parent, child] + tail())
        self.assertEqual(ledger[0]["issuer"], "systemctl stop jarvis.service")
        self.assertEqual(ledger[0]["lineage"], ["systemctl", "bash"])
        self.assertNotIn("hunter2", json.dumps(store.meta) + json.dumps(out))

    def test_stored_text_is_bounded(self):
        long_cmd = "systemctl restart jarvis.service " + "x" * 5000
        ev = [proc(T - 1, 902, "/usr/bin/systemctl", long_cmd, ppid=1, cwd="/", parent_image="/x")]
        _out, ledger, _ = judge(restart_job(), ev + tail())
        self.assertLessEqual(len(ledger[0]["issuer"]), R.MAX_CMD)


class ClaimLogs(unittest.TestCase):
    def test_both_logs_parse_and_utf16_noise_is_dropped(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "WSLKeepalive"))
            os.makedirs(os.path.join(root, "Jarvis", "Reviver"))
            noise = "i f   t h i s".encode("utf-16-le")
            with open(os.path.join(root, "WSLKeepalive", "jarvis-wake.log"), "wb") as fh:
                fh.write(b"2026-11-03 16:25:05 jarvis.service is '" + noise + b"' -- restarting\r\n"
                         b"2026-11-03 16:25:11 jarvis.service is 'active' again\r\n")
            with open(os.path.join(root, "Jarvis", "Reviver", "revive.log"), "w") as fh:
                fh.write("2026-11-04 00:55:05 restarting jarvis.service: active but silent for 110s\n"
                         "2026-11-04 00:57:01 JARVIS healthy again (last action: restarting jarvis.service: x)\n")
            got, problem = R.read_claims(root)
        self.assertEqual(problem, "")
        self.assertEqual(sorted(a for a, _t, _r in got), ["reviver", "wake-watchdog"])
        expected = time.mktime(time.strptime("2026-11-04 00:55:05", "%Y-%m-%d %H:%M:%S"))
        self.assertIn(("reviver", expected, "active but silent for 110s"), got)

    def test_no_windows_side_reads_nothing(self):
        self.assertEqual(R.read_claims(""), ([], ""))


if __name__ == "__main__":
    unittest.main()
