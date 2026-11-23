"""The observed server review never claims more than was observed (jarvis/response/review.py).

Each test names the invariant it guards (see the module docstring). The store is a
real one created by `Store`, then filled the way the scheduler fills it.
"""

import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
import uuid
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from jarvis.cli import parser as cli
from jarvis.core import audience
from jarvis.core.store import Store
from jarvis.response import review

NOW = 1_800_000_000.0
DAY = 86400


def _jobs():
    return [job for _c, _l, job in review.server_jobs()]


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, 'jarvis.db')
        Store(self.db).close()

    def tearDown(self):
        self.tmp.cleanup()

    def snapshot(self, job, findings, ts=NOW - DAY, error=''):
        import sqlite3
        with sqlite3.connect(self.db) as c:
            c.execute('INSERT OR REPLACE INTO snapshots(kind,ts,duration,error,payload) '
                      'VALUES(?,?,?,?,?)', (job, int(ts), 1.0, error, json.dumps(findings)))

    def run_receipt(self, job, coverage='complete', at=NOW - DAY, error=''):
        import sqlite3
        with sqlite3.connect(self.db) as c:
            c.execute('INSERT INTO defender_runs(run_id,job,observed_at,coverage,error,digest,'
                      'finding_count) VALUES(?,?,?,?,?,?,?)',
                      (uuid.uuid4().hex, job, at, coverage, error, 'd', 0))

    def build(self, **kw):
        return review.build(self.db, now=NOW, host='test-host', **kw)

    def section(self, rv, job):
        return next(s for s in rv['sections'] if s['job'] == job)


class Success(Fixture):
    def test_observed_job_reports_its_findings_sorted_and_counted(self):
        self.run_receipt('sshwatch')
        self.snapshot('sshwatch', [{'severity': 'low', 'title': 'b'},
                                   {'severity': 'critical', 'title': 'a'}])
        rv = self.build()
        sec = self.section(rv, 'sshwatch')
        self.assertEqual(sec['state'], 'observed')
        self.assertEqual([f['severity'] for f in sec['findings']], ['critical', 'low'])
        self.assertEqual(rv['severity_counts_in_window']['critical'], 1)
        text = review.render(rv)
        self.assertIn('critical', text)
        self.assertIn('not a security audit', text)
        self.assertIn('Neither is a verdict', text)

    def test_observed_job_with_no_findings_says_so_with_the_date(self):
        self.run_receipt('opshealth')
        self.snapshot('opshealth', [])
        text = review.render(self.build())
        self.assertIn('No findings in the stored result of', text)


class Continuity(Fixture):
    def test_every_server_job_has_a_section_even_in_an_empty_store(self):
        rv = self.build()
        self.assertEqual(sorted(s['job'] for s in rv['sections']), sorted(_jobs()))
        self.assertTrue(all(s['state'] == 'not_observed' for s in rv['sections']))
        self.assertEqual(rv['states']['not_observed'], len(_jobs()))
        self.assertIn('Nothing can be said about this area', review.render(rv))

    def test_a_failed_run_is_partial_and_shows_its_error(self):
        self.run_receipt('logins', coverage='unavailable', error='journal unreadable')
        self.snapshot('logins', [], error='journal unreadable')
        sec = self.section(self.build(), 'logins')
        self.assertEqual(sec['state'], 'partial')
        self.assertEqual(sec['runs']['unavailable'], 1)
        self.assertIn('journal unreadable', sec['error'])

    def test_findings_older_than_the_window_are_stale_and_not_counted(self):
        self.snapshot('sshwatch', [{'severity': 'high', 'title': 'old'}], ts=NOW - 30 * DAY)
        rv = self.build(days=7)
        sec = self.section(rv, 'sshwatch')
        self.assertEqual(sec['state'], 'stale')
        self.assertEqual(rv['severity_counts_in_window']['high'], 0)
        self.assertIn('before this window', review.render(rv))

    def test_receipts_in_window_with_an_older_snapshot_are_stale(self):
        self.run_receipt('opshealth', at=NOW - DAY)
        self.snapshot('opshealth', [{'severity': 'high', 'title': 'x'}], ts=NOW - 20 * DAY)
        self.assertEqual(self.section(self.build(days=7), 'opshealth')['state'], 'stale')

    def test_receipts_before_the_window_do_not_count_as_observed(self):
        self.run_receipt('sshwatch', at=NOW - 10 * DAY)
        self.assertEqual(self.section(self.build(days=7), 'sshwatch')['state'], 'not_observed')

    def test_receipts_without_a_stored_result_never_print_a_date(self):
        self.run_receipt('bootchain')
        text = review.render(self.build())
        self.assertIn('No stored result for this area', text)
        self.assertNotIn('stored result of never', text)

    def test_unreadable_stored_findings_are_reported_not_hidden(self):
        import sqlite3
        self.run_receipt('pkgverify')
        with sqlite3.connect(self.db) as c:
            c.execute("INSERT INTO snapshots(kind,ts,duration,error,payload) VALUES"
                      "('pkgverify',?,1,'','{not json')", (int(NOW - DAY),))
        sec = self.section(self.build(), 'pkgverify')
        self.assertIn('unreadable', sec['error'])


class ReadOnly(Fixture):
    def test_a_missing_store_is_refused_and_never_created(self):
        missing = os.path.join(self.tmp.name, 'nope', 'jarvis.db')
        with self.assertRaises(review.ReviewError):
            review.build(missing, now=NOW)
        self.assertFalse(os.path.exists(missing))

    def test_a_store_without_tables_is_refused(self):
        empty = os.path.join(self.tmp.name, 'empty.db')
        open(empty, 'wb').close()
        with self.assertRaises(review.ReviewError):
            review.build(empty, now=NOW)

    def test_building_does_not_change_the_store(self):
        self.run_receipt('sshwatch')
        self.snapshot('sshwatch', [{'severity': 'low', 'title': 'x'}])
        before = hashlib.sha256(open(self.db, 'rb').read()).hexdigest()
        listing = sorted(os.listdir(self.tmp.name))
        self.build()
        self.assertEqual(hashlib.sha256(open(self.db, 'rb').read()).hexdigest(), before)
        self.assertEqual(sorted(os.listdir(self.tmp.name)), listing)

    def test_the_connection_cannot_write(self):
        import sqlite3
        conn = review.open_readonly(self.db)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("DELETE FROM snapshots")
        finally:
            conn.close()

    def test_no_network_is_touched(self):
        with mock.patch('socket.socket.connect', side_effect=AssertionError('network')), \
                mock.patch('urllib.request.urlopen', side_effect=AssertionError('network')):
            review.render(self.build())


class Privacy(Fixture):
    def test_secret_values_in_detail_are_redacted(self):
        self.run_receipt('opshealth')
        self.snapshot('opshealth', [{'severity': 'high', 'title': 'unit failed',
                                     'detail': 'ExecStart ran with password=hunter2 and '
                                               'Bearer abc.def.ghi'}])
        rv = self.build()
        text = review.render(rv)
        self.assertNotIn('hunter2', text)
        self.assertNotIn('abc.def.ghi', text)
        self.assertNotIn('ExecStart', text, 'a detail the redactor touches is withheld whole')
        self.assertEqual(self.section(rv, 'opshealth')['findings'][0]['detail'], review.WITHHELD)

    def test_a_clean_detail_is_kept(self):
        self.run_receipt('opshealth')
        self.snapshot('opshealth', [{'severity': 'high', 'title': 'unit failed',
                                     'detail': 'nginx.service exited with status 1'}])
        f = self.section(self.build(), 'opshealth')['findings'][0]
        self.assertEqual(f['detail'], 'nginx.service exited with status 1')

    def test_findings_about_secrets_keep_their_title_only(self):
        self.run_receipt('appcode')
        self.snapshot('appcode', [{'severity': 'critical', 'title': 'Credential in repository',
                                   'detail': 'config.py line 3: sk_live_' + 'x' * 24}])
        sec = self.section(self.build(), 'appcode')
        self.assertIn('withheld', sec['findings'][0]['detail'])
        self.assertNotIn('sk_live_', json.dumps(sec))

    def test_urls_lose_their_paths(self):
        self.run_receipt('opshealth')
        self.snapshot('opshealth', [{'severity': 'low', 'title': 'hook',
                                     'detail': 'posts to https://example.org/hook/SECRETPATH'}])
        self.assertNotIn('SECRETPATH', review.render(self.build()))


class Bounds(Fixture):
    def test_findings_per_section_are_capped_and_the_rest_counted(self):
        self.run_receipt('sshwatch')
        self.snapshot('sshwatch', [{'severity': 'low', 'title': f't{i:03}'} for i in range(100)])
        sec = self.section(self.build(), 'sshwatch')
        self.assertEqual(len(sec['findings']), review.MAX_FINDINGS)
        self.assertEqual(sec['truncated'], 100 - review.MAX_FINDINGS)
        self.assertEqual(sec['finding_count'], 100)

    def test_long_text_is_clipped(self):
        self.run_receipt('sshwatch')
        self.snapshot('sshwatch', [{'severity': 'low', 'title': 'a' * 999, 'detail': 'b' * 999}])
        f = self.section(self.build(), 'sshwatch')['findings'][0]
        self.assertLessEqual(len(f['title']), review.MAX_TITLE)
        self.assertLessEqual(len(f['detail']), review.MAX_DETAIL)

    def test_the_window_is_bounded(self):
        for bad in (0, 32, -1, True, 7.5, '7'):
            with self.assertRaises(review.ReviewError, msg=repr(bad)):
                self.build(days=bad)

    def test_render_is_bounded_in_lines(self):
        for job in _jobs():
            self.run_receipt(job)
            self.snapshot(job, [{'severity': 'low', 'title': f'{job}{i}', 'detail': 'd'}
                                for i in range(60)])
        self.assertLessEqual(len(review.render(self.build()).splitlines()), review.MAX_LINES)

    def test_unknown_severity_is_reported_as_low_not_dropped(self):
        self.run_receipt('sshwatch')
        self.snapshot('sshwatch', [{'severity': 'weird', 'title': 'x'}])
        self.assertEqual(self.section(self.build(), 'sshwatch')['findings'][0]['severity'], 'low')


class Claims(Fixture):
    def test_coverage_comes_from_the_register_statement(self):
        rv = self.build()
        self.assertEqual(rv['coverage'], audience.first_run('server')['looks_at'])
        words = set(audience.STATUS_WORDS.values()) | {audience.UNKNOWN_WORD}
        self.assertTrue(all(s['register'] in words for s in rv['sections']))

    def test_render_refuses_handwritten_overclaim(self):
        with mock.patch.object(review, 'NOT_AN_AUDIT', 'This server is fully protected.'):
            with self.assertRaises(ValueError):
                review.render(self.build())

    def test_render_refuses_a_promise_verb(self):
        with mock.patch.dict(review.STATE_WORDS, {'observed': 'observed; this prevents attacks'}):
            with self.assertRaises(ValueError):
                review.render(self.build())

    def test_handwritten_text_is_clean(self):
        for t in [review.NOT_AN_AUDIT] + list(review.STATE_WORDS.values()):
            self.assertEqual(audience._overclaims(t) + audience._promises(t), [], t)

    def test_blind_spots_and_removal_are_always_stated(self):
        text = review.render(self.build())
        self.assertIn('What this review could not see', text)
        self.assertIn('To remove ARGUS-1', text)
        self.assertIn('has not been validated', text)


class PrivateFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_file_is_owner_only(self):
        p = os.path.join(self.tmp.name, 'r.txt')
        review.write_private(p, 'x')
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)

    def test_existing_file_is_not_overwritten(self):
        p = os.path.join(self.tmp.name, 'r.txt')
        open(p, 'w').write('keep')
        with self.assertRaises(FileExistsError):
            review.write_private(p, 'x')
        self.assertEqual(open(p).read(), 'keep')

    def test_symlink_is_not_followed(self):
        target = os.path.join(self.tmp.name, 'target')
        link = os.path.join(self.tmp.name, 'link')
        os.symlink(target, link)
        with self.assertRaises(OSError):
            review.write_private(link, 'x')
        self.assertFalse(os.path.exists(target))


class Cli(Fixture):
    def _run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), \
                mock.patch('jarvis.core.statedir.load_marker', return_value=None):
            code = cli.main(['--db', self.db, 'review', *argv])
        return code, out.getvalue(), err.getvalue()

    def test_cli_prints_the_report(self):
        code, out, _ = self._run('--days', '7')
        self.assertEqual(code, 0)
        self.assertIn('observed server review', out)

    def test_cli_json_is_the_bounded_dict(self):
        code, out, _ = self._run('--json')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)['kind'], 'argus.server_review/v1')

    def test_cli_refuses_a_missing_store(self):
        out, err = io.StringIO(), io.StringIO()
        missing = os.path.join(self.tmp.name, 'none.db')
        with redirect_stdout(out), redirect_stderr(err), \
                mock.patch('jarvis.core.statedir.load_marker', return_value=None):
            code = cli.main(['--db', missing, 'review'])
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(missing))

    def test_cli_writes_a_new_owner_only_file_and_refuses_to_overwrite(self):
        p = os.path.join(self.tmp.name, 'review.txt')
        self.assertEqual(self._run('--out', p)[0], 0)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        self.assertEqual(self._run('--out', p)[0], 2)

    def test_cli_refuses_the_wrong_store_in_service_account_mode(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), \
                mock.patch('jarvis.core.statedir.cli_refusal', return_value='wrong store'):
            code = cli.main(['--db', self.db, 'review'])
        self.assertEqual(code, 2)
        self.assertIn('wrong store', err.getvalue())

    def test_cli_has_no_state_changing_option(self):
        p = cli.build_parser()
        rv = next(a for a in p._subparsers._group_actions if a.choices and 'review' in a.choices)
        opts = {o for a in rv.choices['review']._actions for o in a.option_strings}
        self.assertEqual(opts, {'-h', '--help', '--days', '--json', '--out'})


if __name__ == '__main__':
    unittest.main()


class OwnerDecisions20261103(Fixture):
    """The three sample-review fixes decided on 2026-11-03 (Scout decisions renderer_*)."""

    def test_a_setting_that_names_a_password_keeps_its_detail(self):
        self.run_receipt('sshwatch')
        self.snapshot('sshwatch', [{'severity': 'medium', 'title': 'PasswordAuthentication is enabled',
                                    'detail': 'sshd_config allows password logins for every user'}])
        f = self.section(self.build(), 'sshwatch')['findings'][0]
        self.assertEqual(f['detail'], 'sshd_config allows password logins for every user')

    def test_a_secret_value_is_still_withheld(self):
        for title, kind in (('API key found in config file', ''), ('token exposed in logs', ''),
                            ('Possible leak', 'secrets')):
            with self.subTest(title=title):
                self.assertEqual(review._finding({'title': title, 'kind': kind, 'detail': 'x=1'})['detail'],
                                 review.WITHHELD)

    def test_the_redactor_still_withholds_a_setting_detail_that_quotes_a_value(self):
        f = review._finding({'title': 'PasswordAuthentication is enabled', 'detail': 'password=hunter2'})
        self.assertEqual(f['detail'], review.WITHHELD)

    def test_capability_status_is_stated_once_and_only_where_it_differs(self):
        for job in _jobs():
            self.run_receipt(job)
            self.snapshot(job, [])
        rv = self.build()
        text = review.render(rv)
        common = review.common_status(rv)
        self.assertEqual(text.count(f'Capability status: {common}'), 1)
        differing = sum(1 for s in rv['sections'] if s['register'] != common)
        self.assertEqual(text.count('   Capability status:'), differing)

    def test_a_stale_area_says_when_its_result_is_from_not_never(self):
        self.snapshot('opshealth', [], ts=NOW - 20 * DAY)
        rv = self.build()
        sec = self.section(rv, 'opshealth')
        self.assertEqual(sec['state'], 'stale')
        text = review.render(rv)
        line = next(l for l in text.splitlines() if 'Last run:' in l and
                    text.splitlines()[text.splitlines().index(l) - 1].endswith('[opshealth]'))
        self.assertIn('no run in this window (stored result from', line)
        self.assertNotIn('Last run: never', line)

    def test_an_area_with_nothing_stored_says_none_recorded(self):
        text = review.render(self.build())
        self.assertNotIn('Last run: never', text)
        self.assertIn('Last run: none recorded', text)
