"""Wave 1 property fuzzing (archymedes-gtm docs/FUZZING-2026-11.md, surfaces #3 and #5).

Dev-only: needs Hypothesis, which never ships in a release (ARGUS stays standard library).
    uv run --with hypothesis --with pytest python -m pytest tests/fuzz -q
FUZZ_EXAMPLES raises the case count for nightly runs (default 300 per property).

PRECONDITIONS: none beyond what the real callers pass: free text, JSON written by any process
that can write the licence file, findings dicts from collectors.
ORACLES: named per test. Every failure found is kept as an @example regression.
"""

import json
import os
import re
import tempfile
import time
import unittest

try:
    from hypothesis import HealthCheck, assume, example, given, settings
    from hypothesis import strategies as st
except ImportError:  # pragma: no cover - the product test run has no Hypothesis
    raise unittest.SkipTest("hypothesis not installed (dev-only fuzzing)") from None

from jarvis.licensing import licence
from jarvis.response import privacy, review

N = int(os.environ.get("FUZZ_EXAMPLES", "300"))
FAST = settings(max_examples=N, deadline=None, suppress_health_check=[HealthCheck.too_slow])

SECRET_WORDS = ("password", "passwd", "secret", "token", "api_key", "apikey", "recovery_code")
secret_value = st.text(alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789", min_size=10, max_size=40)
noise = st.text(max_size=80)


KEY_RE = re.compile(r"^ARGUS-(SRV|DSK)(-[0-9A-HJKMNP-TV-Z]{5}){5}$")


class LicenceKeys(unittest.TestCase):
    @FAST
    @given(st.text(max_size=200))
    @example("argus-srv-01234-56789-abcde-fghjk-mnpq3")
    @example("ARGUS-SRV-01234-56789-ABCDE-FGHJK-MNPQ3\n")
    @example("ARGUS-SRV-01234-56789-ABCDE-FGHJK-MNPQ3\x00")
    @example("argus://activate?key=ARGUS-SRV-01234-56789-ABCDE-FGHJK-MNPQ3")
    def test_normalise_accepts_only_argus_keys(self, text):
        # ORACLE: returns a canonical key whose check character holds, or raises LicenceError; nothing else.
        try:
            k = licence.normalise(text)
        except licence.LicenceError:
            return
        self.assertRegex(k, KEY_RE)
        self.assertEqual(licence.normalise(k), k)

    json_value = st.recursive(st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True) | st.text(max_size=40),
                              lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=12), c, max_size=4), max_leaves=12)

    @FAST
    @given(st.dictionaries(st.sampled_from(["key", "certificate", "status", "activation_id", "last_seen",
                                            "last_seen_mac", "fp_source", "x"]), json_value, max_size=8),
           st.floats(min_value=0, max_value=4e9))
    def test_status_never_raises_and_never_grants_without_a_signed_certificate(self, record, now):
        # ORACLE: status() never raises on any file content, and no hand-written record is licensed:
        # only a certificate signed by a key in trust.py can be.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, licence.FILENAME)
            with open(path, "w") as fh:
                json.dump(record, fh, allow_nan=True)
            st_ = licence.status(path, now=now, trusted={"t1": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})
        self.assertFalse(st_["licensed"])


class ReviewRedaction(unittest.TestCase):
    @FAST
    @given(st.sampled_from(SECRET_WORDS), secret_value, noise, noise, st.sampled_from(["=", ": ", "="]))
    def test_planted_secret_never_reaches_the_report(self, word, secret, before, after, sep):
        # ORACLE: a credential written as `<word><sep><value>` in a finding's title or detail is never
        # in the rendered finding (surface #3: the paid report must not leak secrets).
        assume(secret not in before and secret not in after)  # noise that equals the secret is not a leak
        f = review._finding({"severity": "high", "title": f"{before} {word}{sep}{secret} {after}",
                             "detail": f"{after} {word}{sep}{secret} {before}"})
        self.assertNotIn(secret, f["title"])
        self.assertNotIn(secret, f.get("detail", ""))

    @FAST
    @given(st.dictionaries(st.sampled_from(["severity", "title", "detail", "kind", "category"]), st.one_of(st.none(), st.text(max_size=400), st.integers()), max_size=5))
    def test_finding_is_total_and_bounded(self, raw):
        # ORACLE: any collector dict becomes a bounded row; severity is always one of the four.
        f = review._finding(raw)
        self.assertIn(f["severity"], review.SEVERITIES)
        self.assertLessEqual(len(f["title"]), review.MAX_TITLE)
        self.assertLessEqual(len(f.get("detail", "")), max(review.MAX_DETAIL, len(review.WITHHELD)))


class RedactorResources(unittest.TestCase):
    """Surface #3/#10 class: an attacker-written log line must not stall the redactor (ReDoS)."""

    def _timed(self, text):
        t = time.perf_counter()
        privacy.redact(text)
        return time.perf_counter() - t

    def test_long_word_runs_stay_linear(self):
        # ORACLE: redacting 20 kB of adversarial text takes well under a second.
        for text in ("a" * 20_000, "password" * 2_500, "-" * 20_000, "x-" * 10_000, "https://" + "a" * 20_000):
            with self.subTest(head=text[:12]):
                self.assertLess(self._timed(text), 1.0)

    @FAST
    @given(st.text(alphabet="aps-_=:sword tkenx", min_size=200, max_size=4000))
    def test_random_word_soup_stays_fast(self, text):
        self.assertLess(self._timed(text), 0.5)


if __name__ == "__main__":
    unittest.main()
