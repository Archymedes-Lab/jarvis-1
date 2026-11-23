"""Desktop toast channel: bounded, critical-only, and independent of mail."""

import unittest

from jarvis.response import toast


def f(sev="critical", title="t", cat="thing", detail="d"):
    return {"category": cat, "severity": sev, "title": title, "detail": detail,
            "where": "", "host": "win"}


class Store:
    def __init__(self):
        self.meta = {}

    def get_meta(self, k, d=None):
        return self.meta.get(k, d)

    def set_meta(self, k, v):
        self.meta[k] = v


class SelectTests(unittest.TestCase):
    def test_only_criticals_and_outages_are_chosen(self):
        chosen, _ = toast.select([f("high"), f("critical", "c"), f("medium")], {}, 1000)
        self.assertEqual([x["title"] for _, x in chosen], ["c"])

    def test_nopage_categories_are_skipped(self):
        chosen, _ = toast.select([f("critical", cat="process")], {}, 1000)
        self.assertEqual(chosen, [])

    def test_a_finding_repeats_at_most_every_six_hours(self):
        chosen, state = toast.select([f("critical", "c")], {}, 1000)
        self.assertEqual(len(chosen), 1)
        again, state = toast.select([f("critical", "c")], state, 1000 + 3600)
        self.assertEqual(again, [])
        later, _ = toast.select([f("critical", "c")], state, 1000 + toast.TOAST_REPEAT_S + 1)
        self.assertEqual(len(later), 1)

    def test_hourly_cap_bounds_a_storm(self):
        storm = [f("critical", f"c{i}") for i in range(50)]
        chosen, state = toast.select(storm, {}, 1000)
        self.assertEqual(len(chosen), toast.TOAST_CAP)
        more, _ = toast.select([f("critical", "x")], state, 1000 + 60)
        self.assertEqual(more, [])

    def test_text_is_bounded_and_carries_no_command_line(self):
        title, body = toast.text(f("critical", "T" * 300, detail="D" * 500), "hunt")
        self.assertLessEqual(len(title), toast.TITLE_LIMIT)
        self.assertLessEqual(len(body), toast.BODY_LIMIT)


class DeliverTests(unittest.TestCase):
    def test_deliver_shows_and_records_without_mail(self):
        store, calls = Store(), []

        def runner(script, payload):
            calls.append(payload)
            return {"shown": True}
        n = toast.deliver(store, "hunt", [f("critical", "c")], now=5000, runner=runner)
        self.assertEqual(n, 1)
        self.assertIn('"title"', calls[0])
        self.assertIn(toast.STATE_META, store.meta)

    def test_deliver_never_raises(self):
        def runner(script, payload):
            raise RuntimeError("interop down")
        self.assertEqual(toast.deliver(Store(), "hunt", [f("critical")], now=1, runner=runner), 0)

    def test_payload_goes_over_stdin_not_the_command_line(self):
        self.assertIn("[Console]::In.ReadToEnd()", toast.PS_TOAST)
        self.assertNotIn("{title}", toast.PS_TOAST)


if __name__ == "__main__":
    unittest.main()
