"""Independent success, benign, privacy and failure controls for measured gaps."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.collectors.host import content
from jarvis.collectors.persistence import startup_state as startup
from jarvis.core import safe_files, script_patterns
from jarvis.core.finding import content_origin, file_finding
from jarvis.core.store import Store


class ShellPositions(unittest.TestCase):
    def test_direct_and_interpreter_invocations(self):
        for text, expected in (
            ('(/tmp/diagnostic-runner &) 2>/dev/null', '/tmp/diagnostic-runner'),
            ('env LANG=C /var/tmp/install-helper --token secret', '/var/tmp/install-helper'),
            ('/bin/sh /dev/shm/.restore --key secret', '/dev/shm/.restore'),
            ('source /tmp/session-init', '/tmp/session-init'),
            ('if true; then /tmp/agent; fi', '/tmp/agent'),
            ('for x in /tmp/*; do /var/tmp/restart; done', '/var/tmp/restart'),
        ):
            self.assertEqual(startup.invocation(text), expected, text)

    def test_mentions_comments_quoted_examples_and_arguments_do_not_count(self):
        for text in (
            'echo /tmp/file', 'printf "%s" /var/tmp/cache', '# /tmp/agent',
            'test -e /dev/shm/marker', 'cp /tmp/download /usr/local/bin/app',
            'echo if /tmp/name', 'echo for /tmp/name',
            'for path in /tmp/*; do echo "$path"; done',
            '/bin/sh -c "/usr/bin/printf /tmp/example"',
            '/bin/bash -lc "/tmp/runner --password Hunter2"',
            '/tmp/../usr/bin/true',
        ):
            self.assertIsNone(startup.invocation(text), text)

    def test_cron_layouts_are_interpreted_before_command_positions(self):
        for row, system, expected in (
            ('@reboot /dev/shm/.recover --token secret', False, '/dev/shm/.recover'),
            ('@hourly root /tmp/task', True, '/tmp/task'),
            ('1 2 * * * root /var/tmp/reconcile', True, '/var/tmp/reconcile'),
            ('1 2 * * * /var/tmp/reconcile', False, '/var/tmp/reconcile'),
        ):
            self.assertEqual(startup.invocation(startup.cron_command(row, system)), expected)
        for row in ('PATH=/tmp:/usr/bin', '# @reboot /tmp/agent', 'ordinary text'):
            self.assertIsNone(startup.cron_command(row))


class PHPFlow(unittest.TestCase):
    def test_actual_direct_request_arguments(self):
        # The fixture fragments avoid shipping one executable web-shell file.
        for sink in ('system', 'shell_exec', 'exec', 'eval', 'passthru'):
            text = '<?php ' + sink + '($_' + 'POST["run"]); ?>'
            self.assertTrue(script_patterns.php_request_exec(text), sink)
        self.assertTrue(script_patterns.php_request_exec('<?php \\system($_' + 'GET["run"]); ?>'))

    def test_cooccurrence_and_noncode_are_not_direct_flow(self):
        marker = 'system($_' + 'POST["run"]);'
        cases = [
            '<?php echo $_GET["name"]; system("uptime"); ?>',
            '<?php // ' + marker + '\necho "ok"; ?>',
            '<?php /* ' + marker + ' */ echo "ok"; ?>',
            '<?php $example = \'' + marker + '\'; echo $example; ?>',
            '<html><code>' + marker + '</code></html>',
            '<?php $obj->' + marker + ' ?>',
            '<?php Demo::' + marker + ' ?>',
            '<?php Demo\\' + marker + ' ?>',
            '<?php $example = <<<TXT\n' + marker + '\nTXT; ?>',
        ]
        for text in cases:
            self.assertFalse(script_patterns.php_request_exec(text), text)

    def test_many_non_global_candidates_do_not_turn_into_positive_evidence(self):
        text = '<?php ' + ('$x->system($_' + 'GET["x"]);\n') * 2000 + ' ?>'
        self.assertFalse(script_patterns.php_request_exec(text))


class Scratch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / 'home'
        self.home.mkdir()

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        return path

    def audit(self, **over):
        args = dict(profile_files=(), profile_dirs=(), boot_files=(), cron_files=(), cron_dirs=())
        args.update(over)
        return startup.audit([('fixture', str(self.home), 1000)], **args)


class StartupEvidence(Scratch):
    def test_profile_cron_and_boot_sources_without_arguments(self):
        profile = self.write('profile.sh', '(/tmp/random-name --password Hunter2 &)\n')
        cron = self.write('cron/root', '@reboot /dev/shm/.random-name --password Hunter2\n')
        boot = self.write('rc.local', '#!/bin/sh\n/var/tmp/boot-helper --password Hunter2 &\n')
        boot.chmod(0o755)
        out = self.audit(profile_files=(str(profile),), cron_dirs=((str(cron.parent), False),), boot_files=(str(boot),))
        self.assertEqual({f['where'] for f in out}, {str(profile), str(cron), str(boot)})
        for f in out:
            self.assertEqual(f['severity'], 'medium')
            self.assertIn('SHA-256', f['detail'])
            self.assertTrue(content_origin(f))
        self.assertNotIn('Hunter2', json.dumps(out))

    def test_history_sink_is_metadata_only_and_normal_links_stay_quiet(self):
        history = self.home / '.bash_history'
        history.symlink_to('/dev/null')
        with mock.patch.object(safe_files, 'read_start', side_effect=AssertionError('history bytes read')):
            out = self.audit()
        self.assertEqual(len(out), 1)
        self.assertIn('No history contents were read', out[0]['detail'])
        history.unlink()
        history.symlink_to(self.write('shared/history', 'private-content'))
        self.assertEqual(self.audit(), [])

    def test_benign_profiles_cron_and_nonexecutable_boot_do_not_alert(self):
        profile = self.write('profile.sh', 'export LANG=C\necho /tmp/session\n')
        cron = self.write('cron/root', '0 2 * * * /usr/bin/find /tmp -type f\n')
        boot = self.write('rc.local', '/tmp/unexecuted-example\n')
        self.assertEqual(self.audit(profile_files=(str(profile),), cron_dirs=((str(cron.parent), False),), boot_files=(str(boot),)), [])

    def test_ancestor_links_unreadable_unstable_and_oversized_evidence_stay_unknown(self):
        profile = self.write('source/profile.sh', '/tmp/task\n')
        alias = self.root / 'alias'
        alias.symlink_to(profile.parent, target_is_directory=True)
        out = self.audit(profile_files=(str(alias / profile.name),))
        self.assertTrue(any(f['category'] == 'visibility' for f in out))
        with mock.patch.object(safe_files, 'read_start', return_value=None):
            self.assertTrue(any(f['category'] == 'visibility' for f in self.audit(profile_files=(str(profile),))))
        with mock.patch.object(startup, 'MAX_FILE_BYTES', 3):
            self.assertTrue(any(f['category'] == 'visibility' for f in self.audit(profile_files=(str(profile),))))
        self.assertTrue(any(f['category'] == 'persistence' for f in self.audit(profile_files=(str(profile),))))

    def test_discovery_budget_and_interrupted_pass_are_visible_then_recover(self):
        directory = self.root / 'profiles'
        directory.mkdir()
        for n in range(10):
            (directory / f'{n}.sh').write_text('/tmp/task\n')
        with mock.patch.object(startup, 'MAX_ENTRIES', 3):
            self.assertTrue(any(f['category'] == 'visibility' for f in self.audit(profile_dirs=(str(directory),))))
        self.assertEqual(len(self.audit(profile_dirs=(str(directory),))), 10)
        ticks = iter([0.0] + [startup.MAX_SECONDS + 1] * 100)
        out = self.audit(profile_dirs=(str(directory),), clock=lambda: next(ticks))
        self.assertEqual([f['category'] for f in out], ['visibility'])

    def test_persisted_file_evidence_cannot_gain_response_authority(self):
        f = file_finding('persistence', 'critical', 'Fixture', 'metadata only', 'fixture')
        store = Store(str(self.root / 't.db'))
        self.addCleanup(store.close)
        store.save_snapshot('backdoor', [f])
        saved = store.get_snapshots()['backdoor']['findings'][0]
        saved.pop('origin', None)
        self.assertTrue(content_origin(saved))
        self.assertEqual(saved['severity'], 'critical')     # marked advisory, never made cheaper
        self.assertTrue(content_origin({'category': 'webshell', 'title': 'old stored finding'}))


class DormantContent(Scratch):
    def test_dormant_php_is_scanned_cached_and_refreshed_without_a_server(self):
        path = self.write('drop/public/handler.php', '<?php system($_' + 'POST["run"]); ?>')
        store = Store(str(self.root / 't.db'))
        self.addCleanup(store.close)
        with mock.patch.object(content, 'roots', return_value=[str(path.parent)]):
            out = content.audit(store)
            self.assertEqual(len(out), 1)
            self.assertIn('PHP request data', out[0]['title'])
            self.assertTrue(content_origin(out[0]))
            with mock.patch.object(content, 'read_start', side_effect=AssertionError('cache missed')):
                self.assertEqual(content.audit(store)[0]['where'], str(path))
            path.write_text('<?php echo "a normal page"; ?>')
            self.assertEqual(content.audit(store), [])
