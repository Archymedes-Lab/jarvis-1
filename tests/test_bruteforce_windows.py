"""Windows failed-logon classification: guesses stay high, policy refusals
(for example Edge single sign-on refused by account restriction) do not
masquerade as a guessing attack."""
import unittest
from unittest import mock

from jarvis.collectors.identity import bruteforce as bf


def run(rows, total=None, lockouts=0):
    top = [{"key": k, "n": n} for k, n in rows]
    data = {"auditing": 1, "total": sum(n for _, n in rows) if total is None else total,
            "top": top, "lockouts": lockouts}
    with mock.patch.object(bf.collect_windows, "available", return_value=True), \
         mock.patch.object(bf, "ps_json", return_value=data):
        return [(f["severity"], f["title"]) for f in bf._windows()]


class WindowsBruteforceTests(unittest.TestCase):
    def test_wrong_password_spike_is_still_high(self):
        out = run([("chris|-|0xc000006d|0xc000006a|svchost.exe", 25)])
        self.assertIn(("high", "25 failed Windows logons for chris from local in 24h"), out)

    def test_unknown_user_spike_from_one_address_is_high(self):
        out = run([("admin|203.0.113.9|0xc000006d|0xc0000064|", 30)])
        self.assertTrue(any(s == "high" and "203.0.113.9" in t for s, t in out))

    def test_edge_account_restriction_is_a_low_policy_refusal(self):
        out = run([("chris|-|0xc000006e|0xc000006e|msedge.exe", 14),
                   ("chris|-|0xc000006e|0xc000006e|msedgewebview2.exe", 6)])
        self.assertNotIn("high", [s for s, _ in out])
        self.assertIn(("low", "20 Windows sign-in attempts refused by policy "
                              "(account restriction)"), out)

    def test_unlisted_status_counts_as_guessing(self):
        out = run([("chris|-|0xc00000ff|0x0|unknown.exe", 22)])
        self.assertIn("high", [s for s, _ in out])

    def test_refusals_do_not_dilute_a_real_spike_on_the_same_user(self):
        out = run([("chris|-|0xc000006e|0xc000006e|msedge.exe", 30),
                   ("chris|-|0xc000006d|0xc000006a|lsass.exe", 20)])
        self.assertIn(("high", "20 failed Windows logons for chris from local in 24h"), out)

    def test_diffuse_guessing_still_reaches_the_total_medium_beside_a_refusal(self):
        rows = [(f"user{i}|10.0.0.{i}|0xc000006d|0xc000006a|", 5) for i in range(9)]
        rows.append(("chris|-|0xc000006e|0xc000006e|msedge.exe", 3))
        out = run(rows)
        self.assertIn(("medium", "45 failed Windows logons in 24h"), out)

    def test_a_username_cannot_choose_the_source_address(self):
        # TargetUserName is whatever the guesser typed; every field after it is
        # set by Windows. A "|" in the name must not shift its text into the ip.
        out = run([("x|8.8.8.8|203.0.113.9|0xc000006d|0xc0000064|", 30)])
        self.assertIn(("high", "30 failed Windows logons for x|8.8.8.8 from 203.0.113.9 in 24h"), out)

    def test_lockouts_still_report(self):
        out = run([], total=0, lockouts=2)
        self.assertIn(("high", "2 account lockout(s) in the last 7 days"), out)


if __name__ == "__main__":
    unittest.main()
