"""A thread that exits mid-check must not become a hidden process."""

import unittest
from unittest import mock

from jarvis.collectors.process.hidden import run


class GhostRaceTests(unittest.TestCase):
    def confirm(self, alive_after):
        with mock.patch.object(run, "is_thread", return_value=False), \
             mock.patch.object(run, "_still_alive", return_value=alive_after):
            return run.confirmed_ghosts([11396], fresh_read={1, 2}, fresh_sig={1, 2, 11396})

    def test_a_thread_that_vanished_is_not_reported(self):
        self.assertEqual(self.confirm(alive_after=False), [])

    def test_a_pid_that_stays_alive_is_still_reported(self):
        self.assertEqual(self.confirm(alive_after=True), [11396])

    def test_a_listed_pid_or_a_thread_is_never_a_ghost(self):
        with mock.patch.object(run, "is_thread", return_value=True), \
             mock.patch.object(run, "_still_alive", return_value=True):
            self.assertEqual(run.confirmed_ghosts([7], {1}, {1, 7}), [])
        self.assertEqual(run.confirmed_ghosts([1], {1}, {1}), [])
