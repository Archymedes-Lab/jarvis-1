"""Observation epochs: wall clocks are never compared across a discontinuity."""

import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from jarvis.core import epochs
from jarvis.core.epochs import Ledger, Sample

SCRATCH = os.path.join(os.path.expanduser("~"), ".cache", "jarvis-tests")


def s(wall, mono, boottime=None, boot="b1", release="r1"):
    return Sample(boot, wall, mono, mono if boottime is None else boottime, release)


class TransitionTests(unittest.TestCase):
    def test_continuous_clock_keeps_the_epoch(self):
        self.assertIsNone(epochs.transition(s(1000, 10), s(1300.4, 310.4)))

    def test_every_discontinuity_opens_an_epoch(self):
        prev = s(1000, 10)
        cases = {
            "first": (None, s(1, 1)),
            "boot": (prev, s(2000, 5, boot="b2")),
            "resume": (prev, s(1400, 20, boottime=400)),     # kernel-known suspend
            "clock-step": (prev, s(5000, 20)),                 # frozen VM, wall jumped
            "release": (prev, s(1010, 20, release="r2")),
        }
        for reason, (a, b) in cases.items():
            with self.subTest(reason=reason):
                self.assertEqual(epochs.transition(a, b), reason)

    def test_backwards_wall_step_is_a_clock_step(self):
        self.assertEqual(epochs.transition(s(1000, 10), s(900, 20)), "clock-step")

    def test_measured_wsl_clock_discipline_is_continuous(self):
        # Measured 2026-09-24: over 300 monotonic seconds the wall clock
        # advanced ~270.5 s (hv timesync steps of -2.95 s every ~30 s).
        self.assertIsNone(epochs.transition(s(1000, 10), s(1000 + 300 - 29.5, 310)))
        # One -2.95 s correction landing between two views 0.35 s apart is
        # beyond the budget: inconclusive there is the safe error.
        self.assertEqual(epochs.transition(s(1000, 10), s(1000.35 - 2.95, 10.35)),
                         "clock-step")

    def test_resume_after_frozen_vm_is_forward_and_opens_an_epoch(self):
        # Standby froze the VM for 10 minutes inside a 5-minute sample interval.
        self.assertEqual(epochs.transition(s(1000, 10), s(1000 + 300 + 600, 310)),
                         "clock-step")
        # Even a short freeze of 10 s is caught: forward slack is 1% + 2 s.
        self.assertEqual(epochs.transition(s(1000, 10), s(1000 + 300 + 10, 310)),
                         "clock-step")

    def test_backward_step_beyond_the_discipline_budget_opens_an_epoch(self):
        # Clock set back by 2 minutes within 5 minutes: more than 15%.
        self.assertEqual(epochs.transition(s(1000, 10), s(1000 + 300 - 120, 310)),
                         "clock-step")

    def test_release_is_named_before_clock_movement(self):
        self.assertEqual(epochs.transition(s(1000, 10), s(9000, 20, release="r2")),
                         "release")

    def test_monotonic_regression_is_never_same_epoch(self):
        self.assertEqual(epochs.transition(s(1000, 100), s(1001, 50)), "boot")

    def test_unreadable_boot_id_is_a_discontinuity(self):
        self.assertEqual(epochs.transition(s(1000, 10, boot=""), s(1001, 11, boot="")),
                         "boot")

    def test_ntp_slew_within_threshold_is_continuous(self):
        # 300 s at 500 ppm is 0.15 s of drift, far below STEP_S.
        self.assertIsNone(epochs.transition(s(1000, 10), s(1300.15, 310)))


class LedgerTests(unittest.TestCase):
    def test_observe_opens_only_on_transition(self):
        ledger = Ledger()
        self.assertEqual(ledger.observe(s(1000, 10)).reason, "first")
        self.assertIsNone(ledger.observe(s(1060, 70)))
        opened = ledger.observe(s(9000, 80))
        self.assertEqual((opened.seq, opened.reason), (2, "clock-step"))

    def test_ledger_is_bounded(self):
        ledger = Ledger()
        for i in range(epochs.KEEP + 20):
            ledger.observe(s(1000 + i * 100, i, boot=f"b{i}"))
        self.assertEqual(len(ledger.epochs), epochs.KEEP)
        self.assertEqual(ledger.current.seq, epochs.KEEP + 20)

    def test_round_trip_and_corruption(self):
        ledger = Ledger()
        ledger.observe(s(1000, 10))
        ledger.observe(s(9000, 20))
        again = Ledger.from_json(ledger.to_json())
        self.assertEqual(again.epochs, ledger.epochs)
        self.assertEqual(again.last, ledger.last)
        for bad in ("{", '{"epochs": [{"seq": "x"}]}', '{"epochs": 5}', "[]"):
            with self.subTest(bad=bad):
                self.assertEqual(Ledger.from_json(bad).epochs, [])

    def test_non_monotonic_sequence_is_rejected(self):
        ledger = Ledger()
        ledger.observe(s(1000, 10))
        ledger.observe(s(9000, 20))
        text = ledger.to_json().replace('"seq": 2', '"seq": 1')
        self.assertEqual(Ledger.from_json(text).epochs, [])


class OrderingTests(unittest.TestCase):
    def test_same_epoch_orders_by_monotonic_not_wall(self):
        a = {"epoch": 3, "wall": 5000.0, "mono": 10.0}
        b = {"epoch": 3, "wall": 4000.0, "mono": 11.0}   # wall disagrees
        self.assertEqual(epochs.ordered(a, b), -1)
        self.assertEqual(epochs.wall_delta(a, b), 1.0)

    def test_cross_epoch_has_order_but_no_delta(self):
        # "event before its process existed": a resume stepped the wall clock.
        proc_start = {"epoch": 3, "wall": 5000.0, "mono": 10.0}
        event = {"epoch": 4, "wall": 4990.0, "mono": 2.0}
        self.assertEqual(epochs.ordered(proc_start, event), -1)
        self.assertIsNone(epochs.wall_delta(proc_start, event))

    def test_missing_epoch_is_unordered(self):
        self.assertIsNone(epochs.ordered({"wall": 1}, {"epoch": 1, "mono": 1}))
        self.assertIsNone(epochs.ordered({"epoch": 1}, {"epoch": 1, "mono": 1}))


class SampleTests(unittest.TestCase):
    def test_live_sample_is_self_consistent(self):
        a = epochs.sample()
        b = epochs.sample()
        self.assertTrue(a.boot_id)
        self.assertTrue(epochs.coherent(a, b))

    def test_missing_boot_id_file_reads_empty(self):
        self.assertEqual(epochs.sample(boot_id_path="/nonexistent/boot_id").boot_id, "")


class RecordTests(unittest.TestCase):
    def test_record_without_store_path_writes_nothing(self):
        with mock.patch("jarvis.core.store.Store") as store:
            self.assertIsNone(epochs.record(None))
            store.assert_not_called()

    def test_record_persists_and_detects_a_step(self):
        os.makedirs(SCRATCH, mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as tmp:
            db = os.path.join(tmp, "store.db")
            first = epochs.record(db, s(1000, 10))
            self.assertEqual(first.reason, "first")
            self.assertIsNone(epochs.record(db, s(1100, 110)))
            self.assertEqual(epochs.record(db, s(9000, 120)).reason, "clock-step")
            with sqlite3.connect(db) as conn:
                row = conn.execute("SELECT v FROM meta WHERE k=?", (epochs.META,)).fetchone()
            self.assertEqual([e.seq for e in Ledger.from_json(row[0]).epochs], [1, 2])

    def test_unreadable_store_starts_an_empty_ledger(self):
        self.assertEqual(epochs.load("/nonexistent/dir/store.db").epochs, [])


if __name__ == "__main__":
    unittest.main()
