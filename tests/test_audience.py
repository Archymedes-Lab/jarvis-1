"""Audience first-run text stays inside the coverage register (jarvis/core/audience.py)."""

import io
import json
import os
import socket
import unittest
from contextlib import redirect_stdout
from unittest import mock

from jarvis.cli import parser as cli
from jarvis.core import assurance, audience

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _all_text(statement):
    """Every string a user could see, from the JSON form as well as the terminal form."""
    out = []

    def walk(v):
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)
    walk(statement)
    return out + audience.render(statement).splitlines()


class RegisterBound(unittest.TestCase):
    def test_every_profile_capability_is_in_the_register(self):
        for name, spec in audience.PROFILES.items():
            for cap, _label in spec['capabilities']:
                self.assertIn(cap, assurance.CAPABILITIES, f'{name}: {cap}')

    def test_status_words_follow_the_register(self):
        for name in audience.PROFILES:
            st = audience.first_run(name)
            self.assertEqual(st['not_provided'], [], name)
            for row in st['looks_at']:
                status = assurance.CAPABILITIES[row['capability']][0]
                self.assertEqual(row['register_status'], status)
                self.assertEqual(row['status'], audience.STATUS_WORDS[status])

    def test_live_count_is_counted_not_written(self):
        st = audience.first_run('server')
        total = len(assurance.CAPABILITIES)
        live = sum(v[0] in audience.LIVE_STATUSES for v in assurance.CAPABILITIES.values())
        self.assertEqual(st['register'], {'total': total, 'live_tested': live,
                                          'policy_version': assurance.POLICY_VERSION})
        self.assertIn(str(total), st['register_line'])
        if live == 0:
            self.assertIn('None of the', st['register_line'])

    def test_a_promoted_status_is_counted_but_never_given_a_stronger_word(self):
        reg = dict(assurance.CAPABILITIES)
        status, basis, gap = reg['server_ssh_watch']
        reg['server_ssh_watch'] = ('live', basis, gap)
        st = audience.first_run('server', register=reg)
        self.assertEqual(st['register']['live_tested'], 1)
        self.assertTrue(st['register_line'].startswith('1 of '))
        # No reviewed word exists for 'live', so it is listed as not provided.
        self.assertNotIn('server_ssh_watch', [r['capability'] for r in st['looks_at']])
        row = [r for r in st['not_provided'] if r['capability'] == 'server_ssh_watch'][0]
        self.assertEqual(row['status'], audience.UNKNOWN_WORD)

    def test_a_capability_missing_from_the_register_is_not_provided(self):
        reg = {k: v for k, v in assurance.CAPABILITIES.items() if k != 'off_box_heartbeat'}
        st = audience.first_run('server', register=reg)
        self.assertNotIn('off_box_heartbeat', [r['capability'] for r in st['looks_at']])
        row = [r for r in st['not_provided'] if r['capability'] == 'off_box_heartbeat'][0]
        self.assertEqual(row['limit'], 'not in the coverage register')
        self.assertIn('Not provided in this release:', audience.render(st))

    def test_output_follows_a_changed_register_without_caching(self):
        reg = dict(assurance.CAPABILITIES)
        _s, basis, _g = reg['server_login_audit']
        reg['server_login_audit'] = ('partial', basis, 'Only sshd is read; more detail')
        row = [r for r in audience.first_run('server', register=reg)['looks_at']
               if r['capability'] == 'server_login_audit'][0]
        self.assertEqual(row['status'], audience.STATUS_WORDS['partial'])
        self.assertEqual(row['limit'], 'Only sshd is read')


class NoOverclaim(unittest.TestCase):
    def test_no_profile_overclaims(self):
        for name in audience.PROFILES:
            for text in _all_text(audience.first_run(name)):
                self.assertEqual(audience._overclaims(text), [], f'{name}: {text}')

    def test_render_refuses_an_overclaiming_line(self):
        st = audience.first_run('server')
        st['facts'] = st['facts'] + ['Complete protection for your server.']
        with self.assertRaises(ValueError):
            audience.render(st)

    def test_handwritten_text_promises_no_outcome(self):
        for name in audience.PROFILES:
            st = audience.first_run(name)
            for text in [st['title'], st['audience']] + st['facts'] + [
                    r['label'] for r in st['looks_at']]:
                self.assertEqual(audience._promises(text), [], f'{name}: {text}')
        st = audience.first_run('desktop')
        st['looks_at'][0] = dict(st['looks_at'][0], label='Protects your secrets')
        with self.assertRaises(ValueError):
            audience.render(st)

    def test_limits_show_the_first_clause_and_no_source_paths(self):
        for name in audience.PROFILES:
            for row in audience.first_run(name)['looks_at']:
                self.assertNotIn(';', row['limit'])
                self.assertNotIn('.py', row['limit'])
                self.assertLessEqual(len(row['limit']), audience.MAX_LIMIT)
                self.assertLessEqual(len(row['label']), audience.MAX_LABEL)

    def test_empty_and_long_limits_are_bounded(self):
        self.assertEqual(audience._first_clause(''), 'limits not recorded')
        self.assertEqual(audience._first_clause(None), 'limits not recorded')
        long = audience._first_clause('x' * 1000)
        self.assertEqual(len(long), audience.MAX_LIMIT)

    def test_scores_and_removal_are_stated_honestly(self):
        for name in audience.PROFILES:
            st = audience.first_run(name)
            text = audience.render(st)
            self.assertIn('Neither is a verdict', text)
            self.assertIn('not proof of safety', text)
            self.assertIn('To remove:', text)
            self.assertIn('not been validated', st['removal'])
            self.assertLessEqual(len(text.splitlines()), audience.MAX_LINES)

    def test_render_is_bounded_in_lines(self):
        st = audience.first_run('server')
        st['facts'] = ['fact'] * 500
        lines = audience.render(st).splitlines()
        self.assertEqual(len(lines), audience.MAX_LINES)
        self.assertEqual(lines[-1], '(truncated)')


class Profiles(unittest.TestCase):
    def test_unknown_profiles_are_refused(self):
        for name in ('team', '', 'Server', 'enterprise'):
            with self.assertRaises(audience.UnknownProfile):
                audience.first_run(name)

    def test_cli_refuses_an_unknown_profile(self):
        with self.assertRaises(SystemExit) as cm, redirect_stdout(io.StringIO()), \
                mock.patch('sys.stderr', io.StringIO()):
            cli.main(['welcome', 'team'])
        self.assertEqual(cm.exception.code, 2)

    def test_cli_is_read_only_storeless_and_offline(self):
        def no_network(*_a, **_k):
            raise AssertionError('welcome touched the network')

        def no_store(*_a, **_k):
            raise AssertionError('welcome opened the store')

        out = io.StringIO()
        with mock.patch.object(cli, 'Store', no_store), \
                mock.patch.object(socket, 'socket', no_network), \
                mock.patch.object(cli.statedir, 'cli_refusal', no_store), \
                redirect_stdout(out):
            code = cli.main(['welcome', 'server', '--json'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue()), audience.first_run('server'))

    def test_cli_takes_no_option_that_changes_state(self):
        sub = [a for a in cli.build_parser()._actions if a.dest == 'cmd'][0]
        welcome = sub.choices['welcome']
        options = {o for a in welcome._actions for o in a.option_strings}
        self.assertEqual(options, {'-h', '--help', '--json'})

    def test_shipped_hints_name_a_real_command(self):
        for rel in ('release/server/install.sh', 'release/server/README.txt'):
            with open(os.path.join(ROOT, rel), encoding='utf-8') as fh:
                self.assertIn('argus welcome server', fh.read(), rel)
        args = cli.build_parser().parse_args(['welcome', 'server'])
        self.assertEqual(args.profile, 'server')

    def test_every_next_step_is_a_command_that_parses(self):
        # A first-run hint the user cannot run is a dead end (gstack devex: every hint
        # runnable). Found 2026-11-02: `jarvis server sshwatch` did not parse.
        p = cli.build_parser()
        for name, spec in audience.PROFILES.items():
            for step in spec['next_steps']:
                words = step.split('  ')[0].split()
                with redirect_stdout(io.StringIO()), mock.patch('sys.stderr', io.StringIO()):
                    try:
                        p.parse_args(words[1:])
                    except SystemExit:
                        self.fail(f'{name}: hint does not parse: {step!r}')

    def test_server_hints_use_the_installed_program_name(self):
        for step in audience.PROFILES['server']['next_steps']:
            self.assertTrue(step.startswith('argus '), step)


if __name__ == '__main__':
    unittest.main()
