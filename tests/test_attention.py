import unittest

from jarvis.core.attention import activity_episodes, event_attention, event_milestones


def observation(seq, at, application="editor", activity="development", **extra):
    return {"source_seq": seq, "observed_at": at, "application": application,
            "activity": activity, "active": True, **extra}


class AttentionTests(unittest.TestCase):
    def test_critical_event_is_a_pointer_and_never_action_authority(self):
        event = {"seq": 12, "category": "protection", "action": "disabled",
                 "raw": "private content", "process": {"cmdline": "secret"}}
        self.assertEqual(event_attention(event), {
            "seq": 12, "category": "protection", "action": "disabled",
            "priority": "immediate", "authority": "observe_only"})

    def test_events_keep_discrete_wakes_and_report_missing_sequence(self):
        result = event_milestones([
            {"seq": 10, "category": "process", "action": "start"},
            {"seq": 12, "category": "file", "action": "executable_detected"},
            {"seq": 13, "category": "malware", "action": "detected"}])
        self.assertEqual([m["seq"] for m in result["milestones"]], [12, 13])
        self.assertEqual(result["gaps"], [{"after_seq": 10, "before_seq": 12}])
        self.assertFalse(result["truncated"])

    def test_replay_limit_and_retry_do_not_claim_complete_history(self):
        rows = ({"seq": n, "category": "sensor", "action": "error"}
                for n in range(1, 5))
        first = event_milestones(rows, limit=2)
        self.assertTrue(first["truncated"])
        self.assertEqual(first["consumed"], 2)
        self.assertEqual([m["seq"] for m in first["milestones"]], [1, 2])
        self.assertEqual([m["seq"] for m in event_milestones([
            {"seq": 3, "category": "sensor", "action": "error"},
            {"seq": 4, "category": "sensor", "action": "error"}])["milestones"]], [3, 4])

    def test_out_of_order_event_fails(self):
        with self.assertRaises(ValueError):
            event_milestones([{"seq": 3}, {"seq": 3}])

    def test_episode_compression_is_private_and_replayable(self):
        rows = [observation(1, "2026-09-25T09:00:00Z", window_title="private"),
                observation(2, "2026-09-25T09:04:00Z", raw_image="pixels"),
                observation(3, "2026-09-25T09:08:00Z", "browser", "browsing")]
        result = activity_episodes(rows)
        self.assertEqual([e["observations"] for e in result["episodes"]], [2, 1])
        self.assertEqual(result["episodes"][0]["first_seq"], 1)
        self.assertEqual(result["episodes"][0]["last_seq"], 2)
        self.assertNotIn("private", str(result))
        self.assertNotIn("pixels", str(result))

    def test_gap_and_idle_break_episode(self):
        rows = [observation(1, "2026-09-25T09:00:00Z"),
                observation(3, "2026-09-25T09:01:00Z"),
                observation(4, "2026-09-25T09:20:00Z"),
                observation(5, "2026-09-25T09:21:00Z", active=False)]
        result = activity_episodes(rows)
        self.assertEqual(len(result["episodes"]), 4)
        self.assertEqual(result["gaps"], [{"after_seq": 1, "before_seq": 3}])

    def test_invalid_or_sensitive_labels_fail(self):
        with self.assertRaises(ValueError):
            activity_episodes([observation(1, "2026-09-25T09:00:00Z",
                                              application="MyBank account 123")])
        with self.assertRaises(ValueError):
            activity_episodes([observation(1, "2026-09-25T09:00:00")])

    def test_observation_limit_marks_incomplete(self):
        rows = [observation(n, f"2026-09-25T09:0{n}:00Z") for n in range(1, 4)]
        result = activity_episodes(rows, limit=2)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["consumed"], 2)

    def test_episode_output_cap_is_explicit(self):
        rows = [observation(n, f"2026-09-25T09:00:{n % 60:02d}+00:00",
                            activity="development" if n % 2 else "browsing")
                for n in range(1, 502)]
        # Use monotonic minutes so ordering, rather than wall-clock wrapping,
        # exercises the output cap.
        from datetime import datetime, timedelta, timezone
        start = datetime(2026, 9, 25, 9, tzinfo=timezone.utc)
        for n, row in enumerate(rows):
            row["observed_at"] = (start + timedelta(minutes=n)).isoformat()
        result = activity_episodes(rows)
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["episodes"]), 500)
        self.assertEqual(result["consumed"], 500)


if __name__ == "__main__":
    unittest.main()
