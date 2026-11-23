"""The sample review shown to prospects stays honest and current (scripts/reviews/sample_review.py).

- It is labelled as invented before anything else.
- It is the real renderer's output: the committed file equals a fresh render, so a change to
  the renderer or the register cannot leave a stale sample in front of a buyer.
- The fixture's fake secret value never reaches the text (the withholding rule still applies).
- It shows the non-observed states, not only a clean week.
"""

import io
import os
import runpy
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'scripts', 'reviews', 'sample_review.py')
COMMITTED = os.path.join(ROOT, 'docs', 'commercial', 'SAMPLE-SERVER-REVIEW.txt')


def render():
    buf = io.StringIO()
    with redirect_stdout(buf):
        runpy.run_path(SCRIPT, run_name='__main__')
    return buf.getvalue()


class SampleReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = render()

    def test_first_line_says_it_is_invented(self):
        self.assertTrue(self.text.startswith('SAMPLE REPORT.'))
        self.assertIn('none of them was observed on any machine', self.text.splitlines()[0])

    def test_committed_sample_is_the_current_render(self):
        with open(COMMITTED, encoding='utf-8') as fh:
            committed = fh.read()
        self.assertEqual(committed, self.text,
                         'regenerate: python3 scripts/reviews/sample_review.py > '
                         'docs/commercial/SAMPLE-SERVER-REVIEW.txt')

    def test_fixture_secret_value_is_withheld(self):
        self.assertNotIn('not-a-real-value', self.text)
        self.assertIn('detail withheld from this report', self.text)

    def test_shows_unobserved_states_and_the_not_an_audit_line(self):
        self.assertIn('1 partial, 1 stale, 1 not observed', self.text)
        self.assertIn('It is not a security audit', self.text)

    def test_deterministic(self):
        self.assertEqual(render(), self.text)


if __name__ == '__main__':
    unittest.main()
