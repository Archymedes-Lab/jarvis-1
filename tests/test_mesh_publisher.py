"""Isolated continuous-publication regressions; no protected data or service writes."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.core import event
from jarvis.core.eventlog import EventLog
from jarvis.platform.peerledger import protocol as p
from jarvis.platform.peerledger import publisher, store, transport


@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional mesh crypto unavailable')
class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root, self.remote = self.base / 'origin', self.base / 'remote'
        store.init(self.root); store.init(self.remote)
        self.owner, self.witness = store.identity(self.root), store.identity(self.remote)
        self.stream, self.key = p.public(self.owner['signing']), p.public(self.witness['signing'])
        self.configured = [('https://fixture.invalid/v1/mesh', self.key)]
        self.log = EventLog(self.base / 'source', writer=True)
        self.addCleanup(self.log.close)
        self.peer = store.Ledger(self.remote)
        self.addCleanup(self.peer.db.close)

    def append(self):
        n = self.log.last_seq + 1
        ev = event.make(host='wsl', sensor='fixture', channel='fixture', generation='test',
                        record=n, source='fixture', source_event=1, time='2026-10-02T00:00:00Z',
                        category='process', action='start', process={'guid': str(n), 'image': '/private/SECRET'},
                        raw={'secret': 'PASSWORD'})
        self.log.append([ev], {'sensor':'fixture', 'channel':'fixture', 'generation':'test', 'sequence':n})

    def send(self, url, key, req):
        return transport.handle(req, self.peer, self.witness['signing'], {self.stream})

    def cycle(self, **kw):
        return publisher.cycle(self.root, self.log.root, self.configured, self.send, **kw)

    def test_baseline_declares_prefix_and_future_events_advance(self):
        self.append()
        state = self.cycle()
        self.assertTrue(state['ok'])
        self.assertEqual(state['baseline']['unreplicated_through'], 1)
        first = p.decrypt(self.peer.get(self.stream, 1), self.owner)
        self.assertEqual(first['unreplicated_prefix'], [1, 1])
        self.assertEqual(first['rows'], [])
        self.append()
        second = self.cycle()
        self.assertTrue(second['ok'])
        self.assertEqual(second['source_cursor'], 2)
        self.assertEqual(second['source_backlog'], 0)
        latest = p.decrypt(self.peer.head(self.stream), self.owner)
        self.assertEqual(latest['rows'][0]['seq'], 2)
        self.assertNotIn('SECRET', json.dumps(latest))
        self.assertNotIn('PASSWORD', json.dumps(latest))

    def test_empty_source_can_baseline_and_later_publish(self):
        self.assertTrue(self.cycle()['ok'])
        self.append()
        state = self.cycle()
        self.assertTrue(state['ok'])
        self.assertEqual(state['source_cursor'], 1)

    def test_second_process_lock_refused_and_released_on_exit(self):
        with publisher.PublisherLock(self.root):
            with self.assertRaises(p.MeshError):
                publisher.PublisherLock(self.root)
        with publisher.PublisherLock(self.root):
            pass

    def test_offline_cycle_keeps_evidence_and_reports_failure(self):
        self.append()
        def offline(*args):
            raise p.MeshError('offline after bounded attempts')
        state = publisher.cycle(self.root, self.log.root, self.configured, offline)
        self.assertFalse(state['ok'])
        saved = json.loads((self.root / 'publisher-state.json').read_bytes())
        self.assertFalse(saved['ok'])
        self.assertEqual(self.log.last_seq, 1)
        with store.Ledger(self.root) as ledger:
            block = ledger.head(self.stream)
        self.assertIsNotNone(block)
        resumed = self.cycle()
        self.assertTrue(resumed['ok'])
        self.assertEqual(self.peer.head(self.stream), block)

    def test_peer_rollback_reports_failure_even_when_source_idle(self):
        self.assertTrue(self.cycle()['ok'])
        with self.peer.db:
            self.peer.db.execute('DELETE FROM blocks')
        self.assertFalse(self.cycle()['ok'])

    def test_source_rollback_never_reports_fresh_custody(self):
        self.append()
        self.assertTrue(self.cycle()['ok'])
        with EventLog(self.base / 'empty', writer=True) as empty:
            state = publisher.cycle(self.root, empty.root, self.configured, self.send)
        self.assertFalse(state['ok'])

    def test_capacity_failure_does_not_change_source_cursor(self):
        self.append()
        state = self.cycle(budget=8192)
        self.assertFalse(state['ok'])
        self.assertEqual(self.log.last_seq, 1)

    def test_heartbeat_invents_no_source_event(self):
        self.assertTrue(self.cycle()['ok'])
        state = self.cycle(heartbeat_due=True)
        self.assertTrue(state['ok'])
        latest = p.decrypt(self.peer.head(self.stream), self.owner)
        self.assertTrue(latest['heartbeat'])
        self.assertEqual(latest['rows'], [])
        self.assertEqual(latest['through'], 0)
        self.assertEqual(self.log.last_seq, 0)

    def test_cycle_batch_count_is_bounded(self):
        self.assertTrue(self.cycle()['ok'])
        self.append()
        with mock.patch('jarvis.platform.peerledger.publisher.workflow.publish',
                        return_value={'ok':True,'height':1,'receipt_copies':1}) as publish:
            self.cycle()
        self.assertEqual(publish.call_count, publisher.MAX_BATCHES)

    def test_supervised_loop_stops_and_bounds_wait_on_errors(self):
        iterations = [False, False, True]
        waits = []
        with mock.patch('jarvis.platform.peerledger.publisher.cycle',
                        return_value={'ok':False,'batches':0}) as cycle:
            publisher.run(self.root, self.log.root, self.configured, self.send,
                          stop=lambda: iterations.pop(0), wait=waits.append)
        self.assertEqual(cycle.call_count, 2)
        self.assertTrue(all(w >= 30 for w in waits))

    def test_atomic_state_owner_only_and_symlink_refused(self):
        publisher.atomic_state(self.root, {'ok':False})
        self.assertEqual((self.root/'publisher-state.json').stat().st_mode & 0o077, 0)
        (self.root/'publisher-state.new').symlink_to(self.root/'identity.json')
        with self.assertRaises(p.MeshError):
            publisher.atomic_state(self.root, {'ok':True})
        self.assertEqual(store.identity(self.root), self.owner)

    def test_existing_baseline_cannot_be_reset(self):
        self.assertTrue(self.cycle()['ok'])
        with store.Ledger(self.root) as ledger:
            with self.assertRaises(p.MeshError):
                publisher.baseline(self.log, ledger, self.owner)

    def test_watchdog_notification_uses_bounded_local_socket(self):
        with mock.patch.dict('os.environ', {'NOTIFY_SOCKET':'/tmp/fixture-notify'}), \
                mock.patch('socket.socket') as constructor:
            publisher.notify('WATCHDOG=1')
        sock = constructor.return_value.__enter__.return_value
        sock.settimeout.assert_called_once_with(0.1)
        sock.sendto.assert_called_once_with(b'WATCHDOG=1','/tmp/fixture-notify')
