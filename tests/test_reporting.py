import unittest

from jarvis.response.reporting import commands, diff


class CommandMapTests(unittest.TestCase):
    """A report that names a command which does not run is worse than one
    that names none: the reader tries it, it fails, and the report loses
    credibility for the findings that were correct."""

    def _subcommands(self):
        from jarvis.cli.parser import build_parser
        parser = build_parser()
        for action in parser._actions:
            if hasattr(action, "choices") and isinstance(action.choices, dict):
                return set(action.choices)
        return set()

    def test_every_mapped_command_exists_in_the_parser(self):
        known = self._subcommands()
        missing = sorted(
            {cmd.split()[0] for cmd in commands.JOB_COMMANDS.values()} - known)

        self.assertEqual(missing, [], "commands not in the CLI: %s" % missing)

    def test_every_overview_command_exists_in_the_parser(self):
        known = self._subcommands()
        missing = [c for c, _ in commands.OVERVIEW
                   if c.split()[1] not in known]

        self.assertEqual(missing, [])

    def test_every_scheduled_job_has_a_command(self):
        from jarvis.service.schedule import JOBS
        missing = sorted(set(JOBS) - set(commands.JOB_COMMANDS))

        self.assertEqual(missing, [], "jobs with no command: %s" % missing)

    def test_commands_are_ordered_worst_severity_first(self):
        out = commands.commands_for_findings([
            {"job": "secrets", "severity": "low"},
            {"job": "identity", "severity": "critical"},
            {"job": "pixel", "severity": "medium"}])

        self.assertEqual([c for c, _ in out],
                         ["jarvis impersonation", "jarvis pixel",
                          "jarvis secrets"])

    def test_a_job_reporting_twice_yields_its_worst_severity_once(self):
        out = commands.commands_for_findings([
            {"job": "spy", "severity": "low"},
            {"job": "spy", "severity": "high"}])

        self.assertEqual(out, [("jarvis spy", "high")])

    def test_an_unknown_job_is_skipped_rather_than_guessed_at(self):
        self.assertEqual(commands.command_for("no-such-job"), "")
        self.assertEqual(
            commands.commands_for_findings([{"job": "nope", "severity": "high"}]),
            [])


class ProgressiveDiffTests(unittest.TestCase):
    def test_a_new_finding_is_reported_as_new(self):
        m = diff.compare({}, {"a|Thing|x": "high"})

        self.assertEqual(m["appeared"], [("a|Thing|x", "high")])

    def test_a_finding_that_got_worse_is_separated_from_a_new_one(self):
        m = diff.compare({"a|Thing|x": "medium"}, {"a|Thing|x": "critical"})

        self.assertEqual(m["worsened"], [("a|Thing|x", "medium", "critical")])
        self.assertEqual(m["appeared"], [])

    def test_a_finding_that_improved_is_not_reported_as_worse(self):
        m = diff.compare({"a|T|x": "critical"}, {"a|T|x": "low"})

        self.assertEqual(m["improved"], [("a|T|x", "critical", "low")])

    def test_a_finding_that_stopped_being_reported_is_resolved(self):
        m = diff.compare({"a|T|x": "high"}, {})

        self.assertEqual(m["resolved"], [("a|T|x", "high")])

    def test_an_unchanged_finding_is_counted_not_relisted(self):
        m = diff.compare({"a|T|x": "high"}, {"a|T|x": "high"})
        text = diff.describe(m)

        self.assertEqual(m["unchanged"], [("a|T|x", "high")])
        self.assertIn("not re-listed", text)
        self.assertNotIn("T", text.split("UNCHANGED")[0])

    def test_ok_findings_never_enter_the_comparison(self):
        state = diff.snapshot([{"category": "c", "title": "fine", "where": "",
                                "severity": "ok"}])

        self.assertEqual(state, {})

    def test_the_trend_line_names_direction_per_severity(self):
        line = diff.trend_line({"critical": 0, "high": 5},
                               {"critical": 1, "high": 3})

        self.assertIn("critical 0 to 1 (up)", line)
        self.assertIn("high 5 to 3 (down)", line)

    def test_no_previous_report_yields_no_trend_claim(self):
        self.assertEqual(diff.trend_line({}, {"high": 3}), "")

    def test_identical_counts_are_stated_rather_than_left_blank(self):
        self.assertEqual(diff.trend_line({"high": 2}, {"high": 2}),
                         "no change in severity counts")

    def test_describe_is_empty_when_truly_nothing_moved(self):
        self.assertEqual(diff.describe(diff.compare({}, {})), "")


if __name__ == "__main__":
    unittest.main()
