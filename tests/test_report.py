"""Investigation reports: every report says what was checked, found and not done, and never overstates."""

import unittest

from jarvis.response import report


def base(**kw):
    args = dict(title="Check of X", checked=["the stored result"], found=["it failed"], meaning=["a permission problem"],
                certainty="Based only on the stored result.", recommendation=["Re-run it."])
    args.update(kw)
    return report.build(**args)


SECRET = "sk-" + "Mn3Bv4Cx" * 4


class ReportInvariantTests(unittest.TestCase):
    def test_what_i_have_not_done_is_never_empty_and_defaults_to_no_change(self):
        r = base()
        self.assertEqual(r["not_done"][0], report.NO_CHANGE)
        self.assertTrue(r["read_only"])
        self.assertIn("Read-only", r["mode_label"])
        self.assertFalse(r["changed"])

    def test_a_read_only_report_cannot_claim_a_change(self):
        with self.assertRaises(ValueError):
            base(read_only=True, changed=["deleted a file"])

    def test_a_report_that_changed_something_names_what_changed(self):
        r = base(read_only=False, changed=["a patch was applied through the terminal"])
        self.assertTrue(r["changed"])
        self.assertTrue(r["not_done"][0].startswith("Changed: a patch was applied"))
        self.assertNotIn(report.NO_CHANGE, r["not_done"])

    def test_nothing_found_is_scoped_to_what_was_checked_and_names_what_was_not(self):
        r = base(found=[], unchecked=["memory", "the network"])
        self.assertIn("Nothing was observed in the areas listed under", r["found"][0])
        self.assertIn("says nothing about the areas that were not checked", " ".join(r["found"]))
        self.assertIn("Not checked: memory; the network", r["not_done"])

    def test_an_investigation_with_no_checked_areas_cannot_be_complete(self):
        with self.assertRaises(ValueError):
            base(checked=[])
        incomplete = base(checked=[], status=report.INCOMPLETE, found=[])
        self.assertEqual(incomplete["checked"], ["Nothing was completed."])
        self.assertNotIn("Nothing was observed in the areas", " ".join(incomplete["found"]))

    def test_an_incomplete_or_failed_report_says_so_and_lowers_its_certainty(self):
        for status, word in ((report.INCOMPLETE, "did not finish"), (report.FAILED, "failed")):
            r = base(status=status)
            self.assertIn(word, r["found"][0])
            self.assertTrue(r["certainty"].startswith("Low: the investigation did not complete"))
            self.assertEqual(r["status"], status)

    def test_certainty_is_never_invented(self):
        self.assertIn("Not scored", base(certainty="")["certainty"])
        self.assertNotRegex(base(certainty="")["certainty"], r"\d+\s*%")

    def test_unknown_statuses_are_rejected(self):
        with self.assertRaises(ValueError):
            base(status="mostly-fine")

    def test_text_from_tools_is_masked_and_bounded(self):
        r = base(found=[f"saw token={SECRET} in the output", "x" * 1000], technical=f"raw output {SECRET} " + "y" * 9000)
        self.assertNotIn(SECRET, " ".join(r["found"]) + r["technical"])
        self.assertLessEqual(max(len(x) for x in r["found"]), 240)
        self.assertLessEqual(len(r["technical"]), 4000)

    def test_text_form_keeps_the_fixed_order(self):
        text = report.as_text(base())
        positions = [text.index(h) for _k, h in report.SECTIONS if h in text]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("What I have not done:", text)
        self.assertIn("Read-only: nothing was changed; complete", text.splitlines()[0])


class FixReportTests(unittest.TestCase):
    ENTRY = {"id": "fx-0123abcd", "title": "Fix the check", "status": "proposed", "problem": "scan is failing",
             "generation_state": "", "patch_chars": 0}

    def test_a_proposal_is_a_read_only_report_that_states_nothing_is_applied(self):
        r = report.fix_report(self.ENTRY)
        self.assertTrue(r["read_only"])
        self.assertIn("No patch is applied from the dashboard.", r["not_done"])
        self.assertIn("Your approval here is a record of intent; it is not execution.", r["not_done"])
        self.assertIn("Draft only", r["certainty"])
        self.assertIn("Approving starts a draft only", " ".join(r["recommendation"]))

    def test_a_failed_draft_is_reported_as_failed_not_as_a_partial_success(self):
        r = report.fix_report({**self.ENTRY, "status": "draft_failed", "generation_error": "model unreachable"})
        self.assertEqual(r["status"], report.FAILED)
        self.assertIn("This investigation failed", r["found"][0])
        self.assertTrue(r["certainty"].startswith("Low"))
        self.assertIn("generation error: model unreachable", r["technical"])

    def test_an_applied_proposal_names_that_the_change_came_from_the_terminal(self):
        r = report.fix_report({**self.ENTRY, "status": "applied"})
        self.assertFalse(r["read_only"])
        self.assertTrue(r["changed"])
        self.assertTrue(r["not_done"][0].startswith("Changed: a patch was applied through the terminal"))

    def test_an_advisory_review_is_described_as_unable_to_approve(self):
        r = report.fix_report({**self.ENTRY, "jev": {"proposal": {"answers": {}}}})
        self.assertIn("cannot approve or apply anything", r["certainty"])
        self.assertIn("No advisory review is recorded", report.fix_report(self.ENTRY)["certainty"])

    def test_every_status_has_a_next_step_and_never_calls_a_draft_a_fix(self):
        for status in report._FIX_NEXT:
            r = report.fix_report({**self.ENTRY, "status": status})
            self.assertTrue(r["recommendation"][0])
            self.assertNotRegex(" ".join(r["found"] + r["recommendation"] + r["meaning"]).lower(), r"\bfixed\b|\bresolved\b")

    def test_a_proposal_with_no_recorded_problem_is_incomplete_not_complete(self):
        r = report.fix_report({"id": "fx-0123abcd", "status": "proposed"})
        self.assertEqual(r["status"], report.INCOMPLETE)


if __name__ == "__main__":
    unittest.main()
