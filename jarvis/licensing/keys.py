"""Argus licence key format: ARGUS-SRV-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (or ARGUS-DSK-...).

The same algorithm as hosted/licence-cloudflare/src/keys.ts; tests/fixtures/licence/vectors.json
keeps the two in step. 24 Crockford base32 data symbols (120 random bits) and one Luhn mod 32
check symbol over the product code and the data, so a mistyped character is caught here,
before anything is sent. Accepted case- and space-insensitively, with or without dashes or the
ARGUS prefix; O reads as 0, I and L as 1.
"""

import re

ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
PLANS = {'SRV': 'server', 'DSK': 'desktop'}
PRODUCTS = {'server': 'Argus Server', 'desktop': 'Argus Desktop'}
DATA = 24


class KeyFormatError(ValueError):
    """`reason` is 'format' (not an Argus key) or 'check' (one character is wrong)."""

    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason


def check_char(text):
    factor, total = 2, 0
    for ch in reversed(text):
        add = factor * ALPHABET.index(ch)
        factor = 1 if factor == 2 else 2
        total += add // 32 + add % 32
    return ALPHABET[(32 - total % 32) % 32]


def parse(value):
    """(canonical key, plan) or KeyFormatError."""
    s = re.sub(r'[\s\-_]', '', str(value or '').upper())[:80]
    if s.startswith('ARGUS'):
        s = s[5:]
    code, body = s[:3], s[3:].replace('O', '0').replace('I', '1').replace('L', '1')
    if code not in PLANS or len(body) != DATA + 1 or any(c not in ALPHABET for c in body):
        raise KeyFormatError('format', 'that is not an Argus licence key (it starts with ARGUS-SRV- or '
                                       'ARGUS-DSK- and has five groups of five characters)')
    if check_char(code + body[:DATA]) != body[DATA]:
        raise KeyFormatError('check', 'one character of this key is wrong (the check character does not '
                                      'match); compare it with your email')
    return f'ARGUS-{code}-' + '-'.join(body[i:i + 5] for i in range(0, DATA + 1, 5)), PLANS[code]
