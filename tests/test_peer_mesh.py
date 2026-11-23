"""Isolated adversarial mesh checks; never reads protected user evidence."""
import importlib.util
import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from jarvis.core import event
from jarvis.core.eventlog import EventLog
from jarvis.platform.peerledger import protocol as p
from jarvis.platform.peerledger import store, transport, workflow


@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional mesh crypto not installed')
class MeshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        store.init(self.base / 'origin')
        store.init(self.base / 'peer')
        self.owner = store.identity(self.base / 'origin')
        self.witness = store.identity(self.base / 'peer')
        self.stream = p.public(self.owner['signing'])
        self.key = p.public(self.witness['signing'])
        self.configured = [('https://peer.invalid/v1/mesh', self.key)]
        self.origin = store.Ledger(self.base / 'origin')
        self.receiver = store.Ledger(self.base / 'peer')
        self.addCleanup(self.origin.db.close)
        self.addCleanup(self.receiver.db.close)
        self.log = EventLog(self.base / 'source', writer=True)
        self.addCleanup(self.log.close)

    def row(self, record=1, category='process', action='start'):
        return event.make(host='wsl', boot='boot', sensor='fixture', channel='fixture',
                          generation='test', record=record, source='fixture', source_event=1,
                          time='2026-10-01T01:02:39+00:00', category=category, action=action,
                          process={'pid': 77, 'guid': 'private-guid', 'image': '/private/user/SECRET',
                                   'name': 'SECRET', 'cmdline': 'PASSWORD'},
                          parent={'guid': 'parent-guid'}, raw={'password': 'PASSWORD'},
                          attrs={'document': 'PRIVATE DOCUMENT', 'ip': '192.0.2.99'})

    def append_source(self, row=None):
        self.log.append([row or self.row()], {'sensor': 'fixture', 'channel': 'fixture',
                                             'generation': 'test', 'sequence': self.log.last_seq + 1})

    def send(self, url, key, req):
        return transport.handle(req, self.receiver, self.witness['signing'], {self.stream})

    def block(self, height=1, previous=p.ZERO):
        return p.make_block({'rows': []}, self.owner, height, previous)

    def test_projection_allowlist_removes_private_content_and_unknown_fields(self):
        row = self.row()
        row['seq'] = 1
        projection = p.project(row, self.owner)
        encoded = json.dumps(projection)
        for forbidden in ('SECRET', 'PASSWORD', 'PRIVATE DOCUMENT', '192.0.2.99', 'private-guid', 'boot'):
            self.assertNotIn(forbidden, encoded)
        self.assertEqual(projection['minute'], 29846942)
        self.assertEqual(set(projection), {'seq', 'minute', 'action', 'sampled', 'process',
                                           'parent', 'image', 'identity_complete'})
        other = dict(self.owner, archive=os.urandom(32).hex())
        self.assertNotEqual(projection['image'], p.project(row, other)['image'])

    def test_bare_pid_does_not_invent_identity_and_missing_timezone_unknown(self):
        row = self.row()
        row.update(seq=1, time='2026-10-01T01:02:00')
        row['process'] = {'pid': 77}
        projected = p.project(row, self.owner)
        self.assertIsNone(projected['process'])
        self.assertFalse(projected['identity_complete'])
        self.assertIsNone(projected['minute'])

    def test_nonprocess_records_and_untrusted_actions_not_shared(self):
        row = self.row(category='file', action='create')
        row['seq'] = 1
        self.assertIsNone(p.project(row, self.owner))
        row.update(category='process', action='send-all-secrets')
        self.assertIsNone(p.project(row, self.owner))

    def test_encryption_authentication_and_signatures(self):
        block = self.block()
        self.assertEqual(p.decrypt(block, self.owner), {'rows': []})
        changed = dict(block, previous='1' * 64)
        with self.assertRaises(p.MeshError):
            p.validate_block(changed)
        # Even an origin-signed alteration fails GCM header authentication.
        changed = p.sign({k: v for k, v in changed.items() if k != 'signature'}, self.owner['signing'])
        with self.assertRaises(p.MeshError):
            p.decrypt(changed, self.owner)
        with self.assertRaises(p.MeshError):
            p.decrypt(block, dict(self.owner, archive=os.urandom(32).hex()))

    def test_duplicate_gap_fork_and_restart(self):
        block = self.block()
        self.assertTrue(self.receiver.append(block))
        self.assertFalse(self.receiver.append(block))
        with self.assertRaises(p.MeshError):
            self.receiver.append(self.block())
        with self.assertRaises(p.MeshError):
            self.receiver.append(self.block(3, p.digest(block)))
        self.receiver.db.close()
        self.receiver = store.Ledger(self.base / 'peer')
        self.addCleanup(self.receiver.db.close)
        self.assertEqual(self.receiver.verify(self.stream)['digest'], p.digest(block))

    def test_unenrolled_producer_invalid_schema_and_request_signature(self):
        req = p.request(self.owner, 'put', 1, self.block())
        for allowed, changed in [(set(), req), ({self.stream}, dict(req, nonce='00' * 16)),
                                 ({self.stream}, dict(req, extra='PRIVATE'))]:
            with self.assertRaises(p.MeshError):
                transport.handle(changed, self.receiver, self.witness['signing'], allowed)
        self.assertIsNone(self.receiver.head(self.stream))

    def test_stale_replayed_or_wrong_peer_response_rejected(self):
        req = p.request(self.owner, 'head')
        stale = p.response(req, None, self.witness['signing'], now=time.time() - 121)
        with self.assertRaises(p.MeshError):
            p.validate_response(stale, req, self.key)
        reply = self.send('', '', req)
        for request, key in [(p.request(self.owner, 'head'), self.key), (req, self.stream)]:
            with self.assertRaises(p.MeshError):
                p.validate_response(reply, request, key)

    def test_receipt_follows_durable_commit_and_survives_restart(self):
        block = self.block()
        req = p.request(self.owner, 'put', 1, block)
        resp = self.send('', '', req)
        p.validate_response(resp, req, self.key)
        with store.Ledger(self.base / 'peer') as reader:
            self.assertEqual(reader.get(self.stream, 1), block)

    def test_receipts_reference_ciphertext_without_duplicating_it(self):
        block = p.make_block({'rows': ['fixture' * 5000]}, self.owner, 1, p.ZERO)
        self.origin.append(block)
        req = p.request(self.owner, 'put', 1, block)
        resp = self.send('', '', req)
        self.origin.receipt(block, req, resp)
        stored = self.origin.db.execute('SELECT length(data) FROM receipts').fetchone()[0]
        self.assertLess(stored, 2000)
        saved = self.origin.receipts(self.stream, 1)[0]
        self.assertEqual(saved['request'], req)
        p.validate_response(saved['response'], saved['request'], self.key)

    def test_capacity_exhaustion_preserves_head_and_no_receipt(self):
        block = self.block()
        self.receiver.budget = len(p.wire(block)) - 1
        req = p.request(self.owner, 'put', 1, block)
        with self.assertRaises(p.MeshError):
            self.send('', '', req)
        self.assertIsNone(self.receiver.head(self.stream))
        self.assertEqual(self.receiver.db.execute('SELECT count(*) FROM blocks').fetchone()[0], 0)

    def test_busy_writer_retry_is_bounded(self):
        with store.Ledger(self.base / 'peer') as other:
            other.db.execute('BEGIN IMMEDIATE')
            started = time.monotonic()
            with self.assertRaises(sqlite3.OperationalError):
                self.receiver.append(self.block())
            self.assertLess(time.monotonic() - started, 1)
            other.db.rollback()
        self.assertIsNone(self.receiver.head(self.stream))

    def test_interrupted_transaction_never_publishes_a_head(self):
        block = self.block()
        self.receiver.db.execute('BEGIN IMMEDIATE')
        self.receiver.db.execute('INSERT INTO blocks VALUES(?,?,?,?)',
                                 (self.stream, 1, p.digest(block), p.wire(block)))
        self.receiver.db.close()  # Simulates interruption before commit.
        self.receiver = store.Ledger(self.base / 'peer')
        self.addCleanup(self.receiver.db.close)
        self.assertIsNone(self.receiver.head(self.stream))

    def test_publish_retries_same_ciphertext_after_lost_response(self):
        self.append_source()
        def lost(url, key, req):
            result = self.send(url, key, req)
            if req['op'] == 'put':
                raise p.MeshError('lost response')
            return result
        first = workflow.publish(self.log, self.origin, self.owner, self.configured, send=lost)
        self.assertFalse(first['ok'])
        block = self.origin.head(self.stream)
        self.assertEqual(self.receiver.head(self.stream), block)
        self.append_source(self.row(2))
        second = workflow.publish(self.log, self.origin, self.owner, self.configured, send=self.send)
        self.assertTrue(second['ok'])
        self.assertEqual(self.origin.head(self.stream), block)
        third = workflow.publish(self.log, self.origin, self.owner, self.configured, send=self.send)
        self.assertEqual(third['height'], 2)
        self.assertEqual(p.decrypt(self.origin.head(self.stream), self.owner)['after'], 1)

    def test_source_cursor_not_advanced_on_capacity_failure_and_no_source_mutation(self):
        self.append_source()
        before = self.log.head()
        self.origin.budget = 1
        with self.assertRaises(p.MeshError):
            workflow.prepare(self.log, self.origin, self.owner)
        self.assertIsNone(self.origin.head(self.stream))
        self.assertEqual(self.log.head(), before)
        self.assertEqual(self.log.last_seq, 1)

    def test_nonprocess_scanned_range_is_explicit(self):
        self.append_source(self.row(category='file', action='create'))
        block = workflow.prepare(self.log, self.origin, self.owner)
        payload = p.decrypt(block, self.owner)
        self.assertEqual(payload['rows'], [])
        self.assertEqual(payload['skipped'], 1)
        self.assertEqual(payload['through'], 1)

    def test_source_rollback_or_missing_cursor_refused(self):
        self.append_source()
        workflow.prepare(self.log, self.origin, self.owner)
        with EventLog(self.base / 'empty', writer=True) as empty:
            with self.assertRaises(p.MeshError):
                workflow.prepare(empty, self.origin, self.owner)

    def test_selected_sealed_bytes_verify_before_export(self):
        import gzip
        self.append_source()
        self.log.seal(force=True)
        path = self.log._segment_path(1)
        data = gzip.decompress(path.read_bytes())
        # Modify valid JSON without touching the canonical header's hash.
        changed = data.replace(b'PASSWORD', b'ALTERED!')
        self.assertNotEqual(changed, data)
        path.write_bytes(gzip.compress(changed))
        with self.assertRaises(p.MeshError):
            workflow.prepare(self.log, self.origin, self.owner)
        self.assertIsNone(self.origin.head(self.stream))

    def test_source_verification_bounds_refuse_without_cursor_advancement(self):
        from jarvis.platform.peerledger import source
        self.append_source()
        self.log.seal(force=True)
        with mock.patch.object(source, 'MAX_VERIFY_BYTES', 1):
            with self.assertRaises(p.MeshError):
                workflow.prepare(self.log, self.origin, self.owner)
        self.assertIsNone(self.origin.head(self.stream))

    def test_scoped_source_validation_avoids_rechecking_unrelated_payload(self):
        self.append_source()
        self.log.seal(force=True)
        first = workflow.prepare(self.log, self.origin, self.owner)
        self.append_source(self.row(2))
        self.log.seal(force=True)
        second = workflow.prepare(self.log, self.origin, self.owner)
        self.assertEqual(second['height'], 2)
        self.assertEqual(second['previous'], p.digest(first))
        self.append_source(self.row(3))
        self.log.seal(force=True)
        with mock.patch('jarvis.platform.peerledger.source.gzip.open', wraps=__import__('gzip').open) as opened:
            third = workflow.prepare(self.log, self.origin, self.owner)
        self.assertEqual(third['height'], 3)
        self.assertNotIn(self.log._segment_path(1), [call.args[0] for call in opened.call_args_list])

    def test_source_cursor_commitment_rejects_active_record_rewrite(self):
        self.append_source()
        workflow.prepare(self.log, self.origin, self.owner)
        data = self.log.active.read_bytes()
        self.log.active.write_bytes(data.replace(b'PASSWORD', b'ALTERED!'))
        with self.assertRaises(p.MeshError):
            workflow.prepare(self.log, self.origin, self.owner)

    def test_modified_local_block_or_deleted_middle_is_detected(self):
        one = self.block()
        two = self.block(2, p.digest(one))
        self.receiver.append(one)
        self.receiver.append(two)
        with self.receiver.db:
            self.receiver.db.execute('DELETE FROM blocks WHERE height=1')
        with self.assertRaises(p.MeshError):
            self.receiver.verify(self.stream)

    def test_fresh_check_detects_witness_deletion_and_rollback(self):
        self.append_source()
        workflow.publish(self.log, self.origin, self.owner, self.configured, send=self.send)
        self.assertTrue(workflow.check(self.origin, self.owner, self.configured, send=self.send)['ok'])
        with self.receiver.db:
            self.receiver.db.execute('DELETE FROM blocks')
        self.assertFalse(workflow.check(self.origin, self.owner, self.configured, send=self.send)['ok'])
        self.append_source(self.row(2))
        result = workflow.publish(self.log, self.origin, self.owner, self.configured, send=self.send)
        self.assertTrue(any('rolled back' in failure['error'] for failure in result['failures']))

    def test_export_and_recovery_use_independent_pinned_checkpoint(self):
        self.append_source()
        workflow.publish(self.log, self.origin, self.owner, self.configured, send=self.send)
        checkpoint = self.base / 'checkpoint.json'
        workflow.checkpoint(self.origin, self.owner, checkpoint)
        recovered = workflow.recover(self.owner, self.base / 'restored', checkpoint,
                                     self.configured, send=self.send)
        self.assertTrue(recovered['complete'])
        with store.Ledger(self.base / 'restored') as ledger:
            self.assertEqual(ledger.head(self.stream), self.origin.head(self.stream))
            self.assertEqual(p.decrypt(ledger.head(self.stream), self.owner)['rows'][0]['action'], 'start')
        with self.assertRaises(FileExistsError):
            workflow.checkpoint(self.origin, self.owner, checkpoint)
        with self.assertRaises(p.MeshError):
            workflow.recover(self.owner, self.base / 'bad', checkpoint,
                             [('https://peer.invalid', self.stream)], send=self.send)

    def test_recovery_refuses_missing_blocks_and_never_reports_complete(self):
        self.append_source()
        workflow.publish(self.log, self.origin, self.owner, self.configured, send=self.send)
        path = self.base / 'checkpoint.json'
        workflow.checkpoint(self.origin, self.owner, path)
        with self.receiver.db:
            self.receiver.db.execute('DELETE FROM blocks')
        with self.assertRaises(p.MeshError):
            workflow.recover(self.owner, self.base / 'incomplete', path, self.configured, send=self.send)
        with store.Ledger(self.base / 'incomplete') as ledger:
            self.assertIsNone(ledger.head(self.stream))

    def test_no_duplicate_witness_quorum_or_unsafe_transport(self):
        good = 'https://peer.invalid,' + self.key
        with self.assertRaises(p.MeshError):
            workflow.peers([good, good])
        for url in ('http://peer.invalid', 'https://user@peer.invalid',
                    'https://peer.invalid/path', 'https://peer.invalid?token=secret'):
            with self.assertRaises(p.MeshError):
                transport.peer(url + ',' + self.key)
        req = p.request(self.owner, 'head')
        with self.assertRaises(p.MeshError):
            transport.NoRedirect().redirect_request(req, None, 302, '', {}, 'https://other.invalid')

    def test_network_retry_exhaustion_is_bounded(self):
        opener = mock.Mock()
        opener.open.side_effect = OSError('offline')
        with mock.patch('urllib.request.build_opener', return_value=opener), mock.patch('time.sleep'):
            with self.assertRaises(p.MeshError):
                transport.exchange('https://peer.invalid', self.key, p.request(self.owner, 'head'))
        self.assertEqual(opener.open.call_count, 2)
        # The deployed provider rejects Python's default browser signature;
        # a truthful application agent passes without relaxing edge policy.
        sent = opener.open.call_args.args[0]
        self.assertEqual(sent.get_header('User-agent'), 'JarvisEvidenceMesh/1.0')

    def test_unsafe_identity_files_and_symlinks_refused(self):
        path = self.base / 'origin' / 'identity.json'
        path.chmod(0o644)
        with self.assertRaises(p.MeshError):
            store.identity(self.base / 'origin')
        path.chmod(0o600)
        link = self.base / 'link'
        link.symlink_to(self.base / 'origin')
        with self.assertRaises(p.MeshError):
            store.identity(link)

    def test_cli_registration_and_no_default_network_action(self):
        from jarvis.cli.parser import build_parser
        args = build_parser().parse_args(['mesh', 'status', '--root', str(self.base / 'origin')])
        self.assertEqual(args.peer, [])
        self.assertEqual(args.action, 'status')
        from jarvis.cli.parser import main
        with mock.patch('jarvis.cli.parser.Store') as protected, mock.patch('builtins.print'):
            self.assertEqual(main(['mesh', 'status', '--root', str(self.base / 'missing')]), 2)
        protected.assert_not_called()

    def test_real_https_publish_challenge_checkpoint_and_recover(self):
        import datetime
        import ipaddress
        import ssl
        import threading

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        tls_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'isolated-mesh')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(tls_private.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([
                    x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                .sign(tls_private, hashes.SHA256()))
        cert_path, key_path = self.base / 'tls.pem', self.base / 'tls-key.pem'
        store.new_file(cert_path, cert.public_bytes(serialization.Encoding.PEM))
        store.new_file(key_path, tls_private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        server = transport.server(self.base / 'peer', [self.stream], cert_path, key_path, port=0)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        try:
            context = ssl.create_default_context(cafile=str(cert_path))
            url = 'https://127.0.0.1:' + str(server.server_port)
            configured = workflow.peers([url + ',' + self.key])
            def send(endpoint, witness, req):
                return transport.exchange(endpoint, witness, req, context=context)
            self.append_source()
            result = workflow.publish(self.log, self.origin, self.owner, configured, send=send)
            self.assertTrue(result['ok'])
            self.assertTrue(workflow.check(self.origin, self.owner, configured, send=send)['ok'])
            checkpoint = self.base / 'https-checkpoint.json'
            workflow.checkpoint(self.origin, self.owner, checkpoint)
            restored = workflow.recover(self.owner, self.base / 'https-restored', checkpoint,
                                        configured, send=send)
            self.assertTrue(restored['complete'])
            # Default trust rejects this isolated self-signed fixture.
            with self.assertRaises(p.MeshError):
                transport.exchange(url, self.key, p.request(self.owner, 'head'))
            with self.assertRaises(p.MeshError):
                transport.exchange(url, self.stream, p.request(self.owner, 'head'), context=context)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_interrupted_recovery_resumes_without_overwrite(self):
        first = p.make_block({'rows': [1]}, self.owner, 1, p.ZERO)
        second = p.make_block({'rows': [2]}, self.owner, 2, p.digest(first))
        for block in (first, second):
            self.origin.append(block)
            req = p.request(self.owner, 'put', block['height'], block)
            resp = self.send('', '', req)
            self.origin.receipt(block, req, resp)
        path = self.base / 'resume-checkpoint.json'
        workflow.checkpoint(self.origin, self.owner, path)
        def interrupted(url, key, req):
            if req.get('height') == 2:
                raise p.MeshError('connection lost')
            return self.send(url, key, req)
        with self.assertRaises(p.MeshError):
            workflow.recover(self.owner, self.base / 'resume', path, self.configured, send=interrupted)
        with store.Ledger(self.base / 'resume') as ledger:
            self.assertEqual(ledger.verify(self.stream)['height'], 1)
        result = workflow.recover(self.owner, self.base / 'resume', path, self.configured, send=self.send)
        self.assertTrue(result['complete'])

    def test_unavailable_optional_crypto_fails_explicitly(self):
        import builtins
        real_import = builtins.__import__
        def unavailable(name, *args, **kwargs):
            if name.startswith('cryptography'):
                raise ImportError('isolated missing dependency')
            return real_import(name, *args, **kwargs)
        with mock.patch('builtins.__import__', side_effect=unavailable):
            with self.assertRaisesRegex(p.MeshError, 'optional cryptography'):
                p.public(self.owner['signing'])


if __name__ == '__main__':
    unittest.main()
