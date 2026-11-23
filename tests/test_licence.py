"""Argus licences (jarvis/licensing/licence.py): signed, device-bound leases checked offline.

The Archymedes licence service is replaced by FakeService, which signs real Ed25519 certificates with
a test key, so these tests exercise the same verification the shipped client does and show exactly
what leaves the machine. docs/LICENSING-ARCHITECTURE.md §10 lists what must be refused.
"""

import base64
import io
import json
import os
import stat
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from jarvis.cli import parser as cli
from jarvis.core.store import Store
from jarvis.licensing import device, ed25519, keys, licence, trust
from jarvis.response import review

SEED = bytes(range(32))
PUB = device.b64url(ed25519.public_key(SEED))
TRUSTED = {'t1': PUB}
NOW = 1_800_000_000
DAY = 86400
MID = 'aa' * 16


def make_key(plan='SRV', data='0123456789ABCDEFGHJKMNPQ'):
    body = data + keys.check_char(plan + data)
    return f'ARGUS-{plan}-' + '-'.join(body[i:i + 5] for i in range(0, 25, 5))


KEY = make_key()


def jws(claims, kid='t1', seed=SEED, typ='argus-licence+jwt'):
    h = device.b64url(json.dumps({'alg': 'EdDSA', 'kid': kid, 'typ': typ}).encode())
    p = device.b64url(json.dumps({**claims, 'kid': kid}).encode())
    return f'{h}.{p}.{device.b64url(ed25519.sign(seed, f"{h}.{p}".encode()))}'


class FakeService:
    """Just enough of pay.archymedes.xyz: one licence, seats, device signatures, nonces."""

    def __init__(self, key=KEY, lic_exp=NOW + 365 * DAY, status='active'):
        self.key, self.lic_exp, self.status = key, lic_exp, status
        self.requests, self.acts, self.nonces, self.now = [], {}, set(), NOW
        self.claim = None
        self.down = False

    def cert(self, act):
        a = self.acts[act]
        exp = min(self.now + 30 * DAY, self.lic_exp)
        return {'certificate': jws({'iss': 'pay.archymedes.xyz', 'aud': 'argus', 'sub': 'lic_T', 'plan': 'server',
                                    'seats': 1, 'act': act, 'dev': a['dev'], 'dpk': a['dpk'], 'iat': self.now,
                                    'exp': exp, 'lic_exp': self.lic_exp, 'renew_after': exp - 7 * DAY}),
                'activation_id': act}

    def check_sig(self, body, action, subject, dpk):
        msg = f'argus|v1|{action}|{subject}|{body["nonce"]}|{body["ts"]}'.encode()
        if not ed25519.verify(device.unb64url(dpk), msg, device.unb64url(body['sig'])):
            return 401, {'code': 'bad_signature', 'error': 'not signed by the device'}
        if body['nonce'] in self.nonces:
            return 401, {'code': 'replay', 'error': 'this request was already used'}
        if abs(self.now - body['ts']) > 300:
            return 401, {'code': 'clock', 'error': 'clock'}
        self.nonces.add(body['nonce'])
        return None

    def handle(self, endpoint, body):
        if endpoint == 'licence/activate':
            if body['key'] != self.key:
                return 404, {'code': 'unknown_key', 'error': 'the licence service does not know this key'}
            if self.status != 'active':
                return 403, {'code': self.status, 'error': f'this licence is {self.status}'}
            live = [k for k, a in self.acts.items() if not a.get('released')]
            for k in live:
                if self.acts[k]['dpk'] == body['dpk']:
                    return 200, self.cert(k)
            if live:
                return 409, {'code': 'seat_taken', 'error': 'this key is already active on "srv1". Deactivate it there '
                             '(argus licence deactivate), or release that machine at https://pay.archymedes.xyz/manage',
                             'manage_url': 'https://pay.archymedes.xyz/manage'}
            act = f'act_{len(self.acts):020d}'
            self.acts[act] = {'dev': body['dev'], 'dpk': body['dpk']}
            return 200, self.cert(act)
        if endpoint in ('licence/renew', 'licence/release') or endpoint.startswith('content/'):
            a = self.acts.get(body['act'])
            if not a:
                return 404, {'code': 'not_activated', 'error': 'not activated'}
            action = 'content' if endpoint.startswith('content/') else endpoint.split('/')[1]
            subject = f'{endpoint.split("/")[1]}:{body["act"]}' if action == 'content' else body['act']
            bad = self.check_sig(body, action, subject, a['dpk'])
            if bad:
                return bad
            if action == 'release':
                a['released'] = True
                return 200, {'released': True}
            if a.get('released'):
                return 404, {'code': 'not_activated', 'error': 'this machine was released'}
            if self.status != 'active':
                return 403, {'code': self.status, 'error': f'this licence was {self.status}'}
            if action == 'content':
                return 200, {'pack': jws({'aud': 'argus', 'pack': 'sample', 'act': body['act'], 'data': {'ok': 1}},
                                         typ='argus-pack+jwt')}
            return 200, self.cert(body['act'])
        if endpoint == 'licence/claim':
            self.claim = {'dev': body['dev'], 'dpk': body['dpk'], 'bound': None}
            cid = 'clm_' + 'A' * 32
            return 200, {'claim_id': cid, 'user_code': 'ABCD-EFGH', 'verify_url': 'https://pay.archymedes.xyz/link',
                         'expires_in': 1800, 'interval': 5,
                         'buy': {'server': f'https://pay.archymedes.xyz/buy/argus-server?claim={cid}',
                                 'desktop': f'https://pay.archymedes.xyz/buy/argus-desktop?claim={cid}'}}
        if endpoint == 'licence/claim/poll':
            bad = self.check_sig(body, 'poll', body['claim_id'], self.claim['dpk'])
            if bad:
                return bad
            if not self.claim['bound']:
                return 202, {'status': 'pending'}
            return 200, {'status': 'active', 'key': self.key, **self.cert(self.claim['bound'])}
        return 404, {'code': 'not_found', 'error': 'not found'}

    def bind_claim(self):
        act = f'act_{len(self.acts):020d}'
        self.acts[act] = {'dev': self.claim['dev'], 'dpk': self.claim['dpk']}
        self.claim['bound'] = act

    def __call__(self, req, timeout=None):
        body = json.loads(req.data)
        self.requests.append((req.full_url, req.get_method(), dict(req.header_items()), body))
        if self.down:
            raise OSError('down')
        endpoint = req.full_url.split('pay.archymedes.xyz/', 1)[1]
        code, answer = self.handle(endpoint, body)
        if code >= 400:
            raise urllib.error.HTTPError(req.full_url, code, 'x', {}, io.BytesIO(json.dumps(answer).encode()))
        resp = io.BytesIO(json.dumps(answer).encode())
        resp.status = code
        return resp


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, licence.FILENAME)
        self.svc = FakeService()
        device._cache.clear()
        self.mid = mock.patch.object(device, 'machine_id', side_effect=lambda source=None: self.machine)
        self.machine = MID
        self.mid.start()
        self.src = mock.patch.object(device, 'default_source', return_value='linux')
        self.src.start()

    def tearDown(self):
        self.mid.stop()
        self.src.stop()
        self.tmp.cleanup()

    def activate(self, key=KEY, now=NOW):
        self.svc.now = now
        return licence.activate(self.path, key, label='srv1', now=now, opener=self.svc, trusted=TRUSTED)

    def status(self, now=NOW + 60, **kw):
        return licence.status(self.path, now=now, trusted=TRUSTED, **kw)

    def edit(self, fn):
        with open(self.path) as fh:
            rec = json.load(fh)
        fn(rec)
        with open(self.path, 'w') as fh:
            json.dump(rec, fh)


class Keys(Base):
    def test_format_check_character_and_lenient_input(self):
        self.assertEqual(licence.normalise(KEY.lower().replace('-', ' ')), KEY)
        self.assertEqual(licence.normalise(KEY.replace('ARGUS-', '').replace('0', 'O').replace('1', 'l')), KEY)
        self.assertEqual(licence.normalise(f'argus://activate?key={KEY}'), KEY)
        typo = KEY[:-1] + ('Z' if KEY[-1] != 'Z' else 'Y')
        with self.assertRaises(licence.LicenceError) as cm:
            licence.normalise(typo)
        self.assertEqual(cm.exception.code, 'bad_check')
        for bad in ('', 'hello', 'ARGUS-SERVER-1C285B2D-6CE6-4BC7-B8BE-ADB6A7E304DA', KEY + 'X', KEY + '; rm -rf /'):
            with self.subTest(bad=bad), self.assertRaises(licence.LicenceError) as cm:
                licence.normalise(bad)
            self.assertEqual(cm.exception.code, 'bad_key')

    def test_shared_vectors_with_the_worker(self):
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, 'fixtures', 'licence', 'vectors.json')) as fh:
            v = json.load(fh)
        for body, check in v['check']:
            self.assertEqual(keys.check_char(body), check)
        for text, canon in v['parse']:
            if canon:
                self.assertEqual(keys.parse(text)[0], canon)
            else:
                self.assertRaises(keys.KeyFormatError, keys.parse, text)

    def test_checkout_links(self):
        self.assertEqual(licence.SERVER_CHECKOUT, 'https://pay.archymedes.xyz/buy/argus-server')
        self.assertEqual(licence.DESKTOP_CHECKOUT, 'https://pay.archymedes.xyz/buy/argus-desktop')


class Activation(Base):
    def test_activate_sends_the_key_a_fingerprint_and_a_public_key_only(self):
        rec = self.activate()
        self.assertEqual(rec['plan'], 'server')
        (url, method, headers, body), = self.svc.requests
        self.assertEqual(url, 'https://pay.archymedes.xyz/licence/activate')
        self.assertNotIn('Authorization', headers)
        self.assertEqual(set(body), {'key', 'dev', 'dpk', 'label'})
        self.assertNotIn(MID, json.dumps(body))
        self.assertEqual(body['dev'], device.fingerprint(body['dpk'], MID))
        self.assertTrue(self.status()['licensed'])

    def test_files_are_owner_only_and_hold_no_raw_machine_id(self):
        self.activate()
        for name in (licence.FILENAME, device.KEY_FILE):
            p = os.path.join(self.tmp.name, name)
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        with open(self.path) as fh:
            text = fh.read()
        self.assertNotIn(MID, text)
        self.assertNotIn(base64.b64encode(SEED).decode(), text)

    def test_seat_taken_says_what_to_do(self):
        self.activate()
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        self.machine = 'bb' * 16
        with self.assertRaises(licence.LicenceError) as cm:
            licence.activate(os.path.join(other.name, licence.FILENAME), KEY, now=NOW, opener=self.svc, trusted=TRUSTED)
        self.assertEqual(cm.exception.code, 'seat_taken')
        self.assertIn('argus licence deactivate', str(cm.exception))
        self.assertIn('https://pay.archymedes.xyz/manage', str(cm.exception))

    def test_reactivating_the_same_install_is_idempotent(self):
        first = self.activate()
        again = self.activate(now=NOW + 100)
        self.assertEqual(first['activation_id'], again['activation_id'])

    def test_unknown_key_is_not_stored(self):
        with self.assertRaises(licence.LicenceError) as cm:
            self.activate(key=make_key(data='ZZZZZZZZZZZZZZZZZZZZZZZZ'))
        self.assertEqual(cm.exception.code, 'unknown_key')
        self.assertFalse(os.path.exists(self.path))

    def test_a_certificate_signed_by_an_unknown_key_is_refused_at_activation(self):
        with self.assertRaises(licence.LicenceError) as cm:
            licence.activate(self.path, KEY, now=NOW, opener=self.svc, trusted={'other': PUB})
        self.assertEqual(cm.exception.code, 'bad_certificate')
        self.assertFalse(os.path.exists(self.path))


class Refusals(Base):
    """§10: every one of these must make status() refuse, offline."""

    def test_valid_passes_offline(self):
        self.activate()
        with mock.patch('urllib.request.urlopen', side_effect=AssertionError('network')):
            st = self.status(now=NOW + 29 * DAY)
        self.assertTrue(st['licensed'], st['reason'])
        self.assertEqual(st['product'], 'Argus Server')

    def test_tampered_certificate(self):
        self.activate()

        def bump(rec):
            h, p, s = rec['certificate'].split('.')
            claims = json.loads(device.unb64url(p))
            claims['exp'] += 365 * DAY
            rec['certificate'] = f'{h}.{device.b64url(json.dumps(claims).encode())}.{s}'
        self.edit(bump)
        st = self.status()
        self.assertFalse(st['licensed'])
        self.assertIn('signature does not verify', st['reason'])

    def test_unknown_kid(self):
        self.activate()
        st = licence.status(self.path, now=NOW + 60, trusted={'t2': PUB})
        self.assertFalse(st['licensed'])
        self.assertIn('does not know', st['reason'])

    def test_empty_trust_store(self):
        self.activate()
        self.assertIn('no licence signing key', licence.status(self.path, now=NOW, trusted={})['reason'])

    def test_wrong_audience(self):
        self.activate()
        self.edit(lambda rec: rec.update(certificate=jws({'aud': 'orion', 'exp': NOW + DAY, 'iat': NOW})))
        self.assertIn('not for Argus', self.status()['reason'])

    def test_wrong_fingerprint(self):
        self.activate()
        self.machine = 'cc' * 16
        st = self.status()
        self.assertFalse(st['licensed'])
        self.assertIn('another machine', st['reason'])

    def test_wrong_device_key(self):
        self.activate()
        with open(os.path.join(self.tmp.name, device.KEY_FILE), 'w') as fh:
            fh.write(device.b64url(bytes(32)))
        self.assertIn('another Argus install', self.status()['reason'])

    def test_expired_lease(self):
        self.activate()
        st = self.status(now=NOW + 30 * DAY)
        self.assertFalse(st['licensed'])
        self.assertTrue(st['needs_check'])
        self.assertIn('licence needs checking', st['reason'])
        self.assertIn('argus licence refresh', st['reason'])

    def test_clock_rolled_back(self):
        self.activate()
        self.assertTrue(self.status(now=NOW + 10 * DAY)['licensed'])     # stamps last-seen
        st = self.status(now=NOW + 2 * DAY)
        self.assertFalse(st['licensed'])
        self.assertIn('clock is behind', st['reason'])
        self.assertTrue(self.status(now=NOW + 10 * DAY - 300)['licensed'])  # within the tolerance

    def test_editing_last_seen_does_not_reset_the_guard_below_the_signed_issue_time(self):
        self.activate(now=NOW + 5 * DAY)
        self.edit(lambda rec: rec.update(last_seen=0))
        self.assertIn('clock is behind', self.status(now=NOW)['reason'])

    def test_revoked_licence_fails_at_the_next_renewal(self):
        self.activate()
        self.svc.status = 'revoked'
        self.svc.now = NOW + 24 * DAY
        with self.assertRaises(licence.LicenceError) as cm:
            licence.refresh(self.path, now=NOW + 24 * DAY, opener=self.svc, trusted=TRUSTED)
        self.assertEqual(cm.exception.code, 'revoked')
        st = self.status(now=NOW + 24 * DAY)
        self.assertFalse(st['licensed'])
        self.assertIn('cancelled or refunded', st['reason'])

    def test_replayed_renew_request_is_refused_by_the_service(self):
        self.activate()
        self.svc.now = NOW + 24 * DAY
        licence.refresh(self.path, now=NOW + 24 * DAY, opener=self.svc, trusted=TRUSTED)
        _url, _m, _h, body = self.svc.requests[-1]
        code, answer = self.svc.handle('licence/renew', body)
        self.assertEqual((code, answer['code']), (401, 'replay'))

    def test_plan_must_match_the_feature(self):
        self.activate()
        self.assertFalse(self.status(plans=('desktop',))['licensed'])


class Renewal(Base):
    def test_no_call_before_renew_after_one_call_after(self):
        self.activate()
        self.assertFalse(licence.maybe_renew(self.path, now=NOW + 22 * DAY, opener=self.svc, trusted=TRUSTED))
        self.assertEqual(len(self.svc.requests), 1)
        self.svc.now = NOW + 24 * DAY
        self.assertTrue(licence.maybe_renew(self.path, now=NOW + 24 * DAY, opener=self.svc, trusted=TRUSTED))
        self.assertEqual(self.svc.requests[-1][0], 'https://pay.archymedes.xyz/licence/renew')
        self.assertTrue(self.status(now=NOW + 50 * DAY)['licensed'])

    def test_failure_keeps_working_until_the_lease_ends_and_backs_off(self):
        self.activate()
        self.svc.down = True
        self.assertFalse(licence.maybe_renew(self.path, now=NOW + 24 * DAY, opener=self.svc, trusted=TRUSTED))
        n = len(self.svc.requests)
        licence.maybe_renew(self.path, now=NOW + 24 * DAY + 3600, opener=self.svc, trusted=TRUSTED)
        self.assertEqual(len(self.svc.requests), n, 'backs off 6 hours')
        self.assertTrue(self.status(now=NOW + 29 * DAY)['licensed'])
        st = self.status(now=NOW + 31 * DAY)
        self.assertIn('licence needs checking', st['reason'])
        self.assertIn('could not be reached', st['reason'])

    def test_auto_renew_off_makes_no_call(self):
        self.activate()
        licence.set_auto_renew(self.path, False)
        self.assertFalse(licence.maybe_renew(self.path, now=NOW + 24 * DAY, opener=self.svc, trusted=TRUSTED))
        self.assertEqual(len(self.svc.requests), 1)


class Deactivate(Base):
    def test_deactivate_frees_the_seat_and_forgets_the_licence(self):
        self.activate()
        licence.deactivate(self.path, now=NOW + 10, opener=self.svc)
        self.assertFalse(os.path.exists(self.path))
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, device.KEY_FILE)))
        self.machine = 'dd' * 16
        other = os.path.join(tempfile.mkdtemp(dir=self.tmp.name), licence.FILENAME)
        licence.activate(other, KEY, now=NOW, opener=self.svc, trusted=TRUSTED)


class Claim(Base):
    def test_in_app_purchase_activates_without_typing(self):
        c = licence.claim_start(self.path, label='laptop', now=NOW, opener=self.svc)
        self.assertIn('?claim=clm_', c['buy']['desktop'])
        self.assertEqual(licence.claim_poll(self.path, now=NOW, opener=self.svc, trusted=TRUSTED), 'pending')
        self.svc.bind_claim()
        self.assertEqual(licence.claim_poll(self.path, now=NOW + 5, opener=self.svc, trusted=TRUSTED), 'active')
        st = self.status()
        self.assertTrue(st['licensed'])
        self.assertEqual(st['key_hint'], KEY[-4:])

    def test_login_shows_a_code_and_waits(self):
        import time
        self.svc.now = int(time.time())
        lines = []
        polls = iter([None, 'bind'])

        def sleep(_s):
            if next(polls) == 'bind':
                self.svc.bind_claim()
        licence.login(self.path, out=lines.append, sleep=sleep, opener=self.svc, trusted=TRUSTED)
        self.assertIn('ABCD-EFGH', '\n'.join(lines))
        self.assertTrue(self.status(now=self.svc.now + 60)['licensed'])


class Content(Base):
    def test_a_pack_is_fetched_with_a_device_signature_and_verified(self):
        self.activate()
        self.svc.now = NOW + 1
        self.assertEqual(licence.fetch_content(self.path, 'sample', now=NOW + 1, opener=self.svc, trusted=TRUSTED), {'ok': 1})
        self.svc.status = 'revoked'
        with self.assertRaises(licence.LicenceError):
            licence.fetch_content(self.path, 'sample', now=NOW + 2, opener=self.svc, trusted=TRUSTED)


class DaemonApi(Base):
    """jarvis/web/licenceapi.py: what the desktop app's Licence screen calls."""

    def setUp(self):
        super().setUp()
        from jarvis.web import licenceapi
        self.api = licenceapi
        self.db = os.path.join(self.tmp.name, 'jarvis.db')
        for p in (mock.patch.dict(trust.PUBLIC_KEYS, TRUSTED, clear=True),
                  mock.patch.object(licenceapi, '_maybe_renew_in_background', lambda path: None),
                  mock.patch('urllib.request.urlopen', self.svc),
                  mock.patch('time.time', return_value=NOW)):
            p.start()
            self.addCleanup(p.stop)

    def test_unlicensed_state_carries_buy_and_manage_links(self):
        st = self.api.state(self.db)
        self.assertFalse(st['licensed'])
        self.assertTrue(st['needs_key'])
        self.assertEqual(st['links']['buy_desktop'], licence.DESKTOP_CHECKOUT)
        self.assertEqual(st['links']['manage'], licence.MANAGE_URL)

    def test_activate_bad_key_seat_taken_and_deactivate(self):
        code, body = self.api.action(self.db, 'activate', {'key': KEY[:-1] + ('Z' if KEY[-1] != 'Z' else 'Y')})
        self.assertEqual((code, body['ok'], body['code']), (200, False, 'bad_check'))
        code, body = self.api.action(self.db, 'activate', {'key': KEY})
        self.assertTrue(body['ok'], body)
        self.assertTrue(body['state']['licensed'])
        self.assertNotIn('activation_id', body['state'])
        code, body = self.api.action(self.db, 'deactivate', {})
        self.assertTrue(body['ok'])
        self.assertFalse(body['state']['licensed'])

    def test_upgrade_returns_the_checkout_to_open_and_poll_installs(self):
        code, body = self.api.action(self.db, 'upgrade', {'plan': 'desktop'})
        self.assertTrue(body['open'].startswith('https://pay.archymedes.xyz/buy/argus-desktop?claim=clm_'))
        self.assertFalse(self.api.action(self.db, 'poll', {})[1]['active'])
        self.svc.bind_claim()
        code, body = self.api.action(self.db, 'poll', {})
        self.assertTrue(body['active'])
        self.assertTrue(body['state']['licensed'])

    def test_monthly_desktop_opens_its_own_offer_with_the_same_claim(self):
        code, body = self.api.action(self.db, 'upgrade', {'plan': 'desktop-monthly'})
        self.assertRegex(body['open'], r'^https://pay\.archymedes\.xyz/buy/argus-desktop-monthly\?claim=clm_[0-9A-Z]{32}$')

    def test_an_unknown_plan_falls_back_to_yearly_desktop_never_an_arbitrary_offer(self):
        code, body = self.api.action(self.db, 'upgrade', {'plan': '../../evil'})
        self.assertTrue(body['open'].startswith('https://pay.archymedes.xyz/buy/argus-desktop?claim=clm_'))

    def test_unknown_action_is_404(self):
        self.assertEqual(self.api.action(self.db, '../x', {})[0], 404)

    def test_a_promo_code_is_passed_to_the_checkout_link_and_nowhere_else(self):
        for plan, offer in (('desktop', 'argus-desktop'), ('desktop-monthly', 'argus-desktop-monthly')):
            with self.subTest(plan=plan):
                code, body = self.api.action(self.db, 'upgrade', {'plan': plan, 'promo': '  Launch_20-x  '})
                self.assertEqual(code, 200)
                self.assertTrue(body['ok'], body)
                self.assertRegex(body['open'], rf'^https://pay\.archymedes\.xyz/buy/{offer}\?claim=clm_[0-9A-Z]{{32}}'
                                               r'&promo=Launch_20-x$')
                self.assertTrue(body['promo_sent'])
        # never sent to the licence service with the claim, never written to the licence file
        self.assertTrue(any(u.endswith('/licence/claim') for u, _m, _h, _b in self.svc.requests))
        self.assertNotIn('Launch_20', json.dumps([(u, b) for u, _m, _h, b in self.svc.requests]))
        with open(self.path) as fh:
            self.assertNotIn('Launch_20', fh.read())

    def test_no_or_empty_promo_keeps_the_plain_claim_link(self):
        for payload in ({'plan': 'desktop'}, {'plan': 'desktop', 'promo': ''}, {'plan': 'desktop', 'promo': '   '},
                        {'plan': 'desktop', 'promo': None}):
            with self.subTest(payload=payload):
                body = self.api.action(self.db, 'upgrade', payload)[1]
                self.assertRegex(body['open'], r'^https://pay\.archymedes\.xyz/buy/argus-desktop\?claim=clm_[0-9A-Z]{32}$')
                self.assertFalse(body['promo_sent'])

    def test_a_malformed_promo_is_refused_before_any_network_call(self):
        bad = ['A' * 41, 'SAVE 20', 'x&allow_promotion_codes=false', 'a/b', '<b>', 'ÉTÉ20', 'a.b', '%41', 20, ['X'], {'c': 'X'}]
        for promo in bad:
            with self.subTest(promo=promo):
                before = len(self.svc.requests)
                code, body = self.api.action(self.db, 'upgrade', {'plan': 'desktop', 'promo': promo})
                self.assertEqual((code, body['ok'], body['code']), (200, False, 'bad_promo'))
                self.assertNotIn('open', body)
                self.assertEqual(len(self.svc.requests), before)          # no claim opened
                if isinstance(promo, str):
                    self.assertNotIn(promo, body['error'])
        self.assertFalse(os.path.exists(self.path))                         # nothing pending


class ReviewPreview(Base):
    def setUp(self):
        super().setUp()
        self.db = os.path.join(self.tmp.name, 'jarvis.db')
        Store(self.db).close()
        self.path = licence.path_for(self.db)
        trust_patch = mock.patch.dict(trust.PUBLIC_KEYS, TRUSTED, clear=True)
        trust_patch.start()
        self.addCleanup(trust_patch.stop)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), mock.patch('urllib.request.urlopen', self.svc):
            code = cli.main(['--db', self.db, *argv])
        return code, out.getvalue(), err.getvalue()

    def test_unlicensed_review_is_a_preview_with_enter_a_key_and_buy(self):
        code, out, err = self.run_cli('review')
        self.assertEqual(code or 0, 0)
        self.assertIn('(preview)', out)
        self.assertIn('enter a licence key: argus licence activate', out)
        self.assertIn(licence.SERVER_CHECKOUT, out)
        self.assertIn('preview only', err)

    def test_preview_keeps_states_counts_and_blind_spots_but_no_findings(self):
        rv = {'sections': [{'job': 'x', 'finding_count': 3, 'findings': [{'title': 't'}], 'truncated': 0}]}
        pv = review.preview(rv, 'https://buy')
        self.assertEqual(pv['sections'][0]['findings'], [])
        self.assertEqual(rv['sections'][0]['findings'], [{'title': 't'}], 'input is not modified')

    def test_cli_activate_status_deactivate(self):
        with mock.patch('time.time', return_value=NOW):
            self.svc.now = NOW
            code, out, err = self.run_cli('licence', 'activate', KEY.lower())
            self.assertEqual(code or 0, 0, err)
            self.assertIn('Argus Server activated', out)
            self.assertIn('renews or ends', out)
            code, out, _ = self.run_cli('review')
            self.assertNotIn('(preview)', out)
            code, out, _ = self.run_cli('licence', 'status')
            self.assertTrue(out.startswith('licensed:'))
            code, _out, err = self.run_cli('licence', 'activate', KEY[:-1] + ('Z' if KEY[-1] != 'Z' else 'Y'))
            self.assertEqual(code, 2)
            self.assertIn('check character', err)
            code, out, _ = self.run_cli('licence', 'deactivate')
            self.assertIn('the seat on', out)
            code, out, _ = self.run_cli('licence', 'status')
            self.assertIn('not licensed: no licence installed', out)
            self.assertIn('enter a licence key', out)


if __name__ == '__main__':
    unittest.main()
