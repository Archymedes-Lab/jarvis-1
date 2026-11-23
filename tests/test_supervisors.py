"""The Windows monitor's own silence is the most dangerous silence available.

A scheduled task stuck in 'Running' refuses every later trigger under
MultipleInstances=IgnoreNew, and Task Scheduler still reports the task present
and Ready. That happened in practice: the monitor stopped checking for eleven
minutes while every outward sign said it was installed and fine.
"""

import json
import os
import tempfile
import time
import unittest

from jarvis.service import supervisors


class HealthMonitorAuditTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "state.json")
        self.now = 1_800_000_000

    def _write(self, **state):
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(state, fh)

    def _titles(self, findings):
        return {f["title"]: f["severity"] for f in findings}

    def test_a_stalled_monitor_is_high_not_merely_noted(self):
        self._write(checkedAt=self.now - 900, healthy=True)

        out = self._titles(supervisors.audit_health_monitor(self.path, self.now))

        self.assertEqual(
            out["the independent Windows monitor has stopped checking"], "high")

    def test_a_recent_check_is_reported_as_ok(self):
        self._write(checkedAt=self.now - 30, healthy=True,
                    reason="scheduler progress verified")

        out = self._titles(supervisors.audit_health_monitor(self.path, self.now))

        self.assertEqual(
            out["the independent Windows monitor is checking on JARVIS"], "ok")

    def test_a_slow_run_inside_the_window_is_not_an_alarm(self):
        self._write(checkedAt=self.now - supervisors.STALE_AFTER + 5, healthy=True)

        out = self._titles(supervisors.audit_health_monitor(self.path, self.now))

        self.assertNotIn(
            "the independent Windows monitor has stopped checking", out)

    def test_a_missing_state_file_says_it_never_ran(self):
        out = self._titles(supervisors.audit_health_monitor(self.path, self.now))

        self.assertIn("the independent Windows monitor has never run", out)

    def test_unparseable_state_is_reported_rather_than_ignored(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{not json")

        out = self._titles(supervisors.audit_health_monitor(self.path, self.now))

        self.assertIn(
            "the independent Windows monitor's state is unreadable", out)

    def test_a_state_file_with_no_timestamp_is_not_treated_as_fresh(self):
        self._write(healthy=True)

        out = self._titles(supervisors.audit_health_monitor(self.path, self.now))

        self.assertIn(
            "the independent Windows monitor has not recorded a check", out)

    def test_a_failing_email_path_is_surfaced(self):
        self._write(checkedAt=self.now - 10, healthy=True,
                    mailError="Outage email failed; queued for retry")

        out = self._titles(supervisors.audit_health_monitor(self.path, self.now))

        self.assertEqual(out["the Windows monitor's email path is failing"],
                         "medium")

    def test_a_deliberate_mail_pause_is_low_not_a_failing_path(self):
        self._write(checkedAt=self.now - 10, healthy=True,
                    mailError="Outage email failed (ItemNotFoundException); queued for retry")
        folder = os.path.dirname(self.path)
        open(os.path.join(folder, "mail.json.paused-20260929T131238Z.bak"), "w").close()

        out = self._titles(supervisors.audit_health_monitor(self.path, self.now))

        self.assertNotIn("the Windows monitor's email path is failing", out)
        self.assertEqual(out["outage email has been paused for %d days"
                             % supervisors.pause_age_days("20260929T131238Z", self.now)],
                         "medium")
        self.assertEqual(supervisors.mail_paused_since(folder), "20260929T131238Z")
        fresh = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(self.now - 2 * 86400))
        os.remove(os.path.join(folder, "mail.json.paused-20260929T131238Z.bak"))
        open(os.path.join(folder, "mail.json.paused-%s.bak" % fresh), "w").close()
        out = self._titles(supervisors.audit_health_monitor(self.path, self.now))
        self.assertEqual(out["outage email is paused"], "low")
        open(os.path.join(folder, "mail.json"), "w").close()
        self.assertEqual(supervisors.mail_paused_since(folder), "")

    def test_a_monitor_reporting_us_unhealthy_is_relayed(self):
        self._write(checkedAt=self.now - 10, healthy=False,
                    reason="JARVIS is running but reports its scheduler has stalled")

        findings = supervisors.audit_health_monitor(self.path, self.now)
        hit = [f for f in findings if "reports JARVIS unhealthy" in f["title"]]

        self.assertEqual(len(hit), 1)
        self.assertIn("scheduler has stalled", hit[0]["detail"])

    def test_utf8_bom_written_by_powershell_is_parsed(self):
        with open(self.path, "w", encoding="utf-8-sig") as fh:
            json.dump({"checkedAt": self.now - 5, "healthy": True}, fh)

        out = self._titles(supervisors.audit_health_monitor(self.path, self.now))

        self.assertIn("the independent Windows monitor is checking on JARVIS",
                      out)


class WatchdogWiringTests(unittest.TestCase):
    def test_the_watchdogs_job_reports_both_halves_of_the_loop(self):
        from jarvis.service import jobs

        self.assertIs(jobs.supervisors, supervisors)


class InspectCommandTests(unittest.TestCase):
    """The report tells you which command to run. That command has to be able
    to answer the question the finding raised.

    JARVIS mailed 'the independent Windows monitor has stopped checking' with
    'Inspect: jarvis selfcheck', and selfcheck said nothing about the Windows
    monitor at all. The command existed, so the parser check passed; it just
    could not show you the thing that was broken.
    """

    def test_the_watchdogs_job_points_at_selfcheck(self):
        from jarvis.response.reporting.commands import command_for

        self.assertEqual(command_for("watchdogs"), "jarvis selfcheck")

    def test_selfcheck_reports_the_windows_monitor(self):
        import io
        from contextlib import redirect_stdout

        from jarvis.cli.commands import service

        buf = io.StringIO()
        with redirect_stdout(buf):
            service._print_windows_monitor(False)

        self.assertIn("windows monitor", buf.getvalue())


if __name__ == "__main__":
    unittest.main()


class ReviverAuditTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "state.json")
        self.now = 1_800_000_000

    def _audit(self, **state):
        if state:
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)
        return {f["title"]: f["severity"] for f in supervisors.audit_reviver(self.path, self.now)}

    def test_missing_reviver_is_reported(self):
        self.assertEqual(self._audit(), {"the instant reviver is not installed": "medium"})

    def test_a_silent_loop_is_high(self):
        out = self._audit(checkedAt=self.now - 120, healthy=True)
        self.assertEqual(out, {"the instant reviver has stopped": "high"})

    def test_spent_budget_and_pause_are_not_hidden_behind_ok(self):
        self.assertEqual(self._audit(checkedAt=self.now - 3, gaveUp=True, lastAction="x"),
                         {"the instant reviver has used its restart budget": "high"})
        self.assertEqual(self._audit(checkedAt=self.now - 3, paused=True),
                         {"the instant reviver is paused for maintenance": "medium"})

    def test_a_fresh_loop_is_ok(self):
        self.assertEqual(self._audit(checkedAt=self.now - 4, healthy=True),
                         {"the instant reviver is watching JARVIS": "ok"})


class TornReadTests(unittest.TestCase):
    def test_a_torn_write_is_retried_before_it_counts_as_unreadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('{"checkedAt": 1')                    # half written

            def finish(_delay):
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump({"checkedAt": 1800000000}, fh)

            self.assertEqual(supervisors.read_state(path, sleep=finish), {"checkedAt": 1800000000})
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{broken")
            slept = []
            self.assertIsNone(supervisors.read_state(path, sleep=slept.append))
            self.assertEqual(len(slept), 2)                      # bounded: two short retries
            self.assertIsNone(supervisors.read_state(os.path.join(tmp, "absent.json"),
                                                     sleep=slept.append))
            self.assertEqual(len(slept), 2)                      # a missing file is not retried
