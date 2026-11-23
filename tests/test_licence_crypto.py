"""Ed25519 for licences (jarvis/licensing/ed25519.py): RFC 8032 vectors, both code paths, and
signatures made by the licence service's WebCrypto (tests/fixtures/licence/vectors.json)."""

import json
import os
import unittest

from jarvis.licensing import device, ed25519, licence

# RFC 8032 section 7.1, tests 1 and 2.
RFC = [
    ('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
     'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
     'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
    ('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
     '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
     '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'),
]
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures', 'licence', 'vectors.json')
PATHS = [True] + ([False] if ed25519.HAVE_CRYPTOGRAPHY else [])


class Ed25519(unittest.TestCase):
    def test_rfc8032_vectors_on_every_available_path(self):
        for fallback in PATHS:
            for seed, pub, msg, sig in RFC:
                with self.subTest(fallback=fallback, msg=msg):
                    s, m = bytes.fromhex(seed), bytes.fromhex(msg)
                    self.assertEqual(ed25519.public_key(s, fallback).hex(), pub)
                    self.assertEqual(ed25519.sign(s, m, fallback).hex(), sig)
                    self.assertTrue(ed25519.verify(bytes.fromhex(pub), m, bytes.fromhex(sig), fallback))
                    bad = bytearray(bytes.fromhex(sig))
                    bad[5] ^= 1
                    self.assertFalse(ed25519.verify(bytes.fromhex(pub), m, bytes(bad), fallback))
                    self.assertFalse(ed25519.verify(bytes.fromhex(pub), m + b'x', bytes.fromhex(sig), fallback))

    def test_malformed_input_is_false_not_an_exception(self):
        for fallback in PATHS:
            self.assertFalse(ed25519.verify(b'\xff' * 32, b'', b'\x00' * 64, fallback))
            self.assertFalse(ed25519.verify(b'short', b'', b'\x00' * 64, fallback))
            self.assertFalse(ed25519.verify(bytes(32), b'', b'\xff' * 64, fallback))  # s >= L

    def test_signatures_match_the_licence_service_byte_for_byte(self):
        with open(FIXTURE) as fh:
            v = json.load(fh)['ed25519']
        seed = device.unb64url(v['seed'])
        for fallback in PATHS:
            self.assertEqual(device.b64url(ed25519.public_key(seed, fallback)), v['pub'])
            self.assertEqual(device.b64url(ed25519.sign(seed, v['message'].encode(), fallback)), v['sig'])

    def test_a_certificate_signed_by_the_worker_verifies(self):
        with open(FIXTURE) as fh:
            v = json.load(fh)['jws']
        claims = licence.verify_certificate(v['token'], {v['kid']: v['pub']})
        self.assertEqual(claims['sub'], 'lic_TEST')
        with self.assertRaises(licence.CertificateError):
            licence.verify_certificate(v['token'][:-3] + 'AAA', {v['kid']: v['pub']})


if __name__ == '__main__':
    unittest.main()
