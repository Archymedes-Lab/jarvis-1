"""Strict wire schema, origin signatures and owner-only encrypted projections."""
import hashlib
import hmac
import json
import os
import re
import time

ZERO = '0' * 64
MAX_WIRE = 2 * 1024 * 1024
MAX_ROWS = 500
MAX_SCAN = 2000
HEX = re.compile(r'^[0-9a-f]+$')
ACTIONS = {'start', 'exit', 'access', 'remote_thread', 'tamper', 'image_load',
           'image_unload', 'clipboard', 'present'}


class MeshError(ValueError):
    pass


def crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise MeshError('mesh requires optional cryptography dependency') from exc
    return Ed25519PrivateKey, Ed25519PublicKey, AESGCM


def wire(value):
    try:
        data = json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise MeshError('invalid wire value') from exc
    if len(data) > MAX_WIRE:
        raise MeshError('wire capacity exceeded')
    return data


def digest(value):
    return hashlib.sha256(wire(value)).hexdigest()


def hex_bytes(value, length):
    if not isinstance(value, str) or len(value) != 2 * length or not HEX.fullmatch(value):
        raise MeshError('invalid hex field')
    return bytes.fromhex(value)


def integer(value, low=0, high=100_000):
    if type(value) is not int or not low <= value <= high:
        raise MeshError('integer out of bounds')
    return value


def public(private):
    private_type = crypto()[0]
    from cryptography.hazmat.primitives import serialization
    return private_type.from_private_bytes(hex_bytes(private, 32)).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign(body, private):
    return dict(body, signature=crypto()[0].from_private_bytes(
        hex_bytes(private, 32)).sign(wire(body)).hex())


def verify(signed, key):
    if not isinstance(signed, dict) or 'signature' not in signed:
        raise MeshError('missing signature')
    body = {k: v for k, v in signed.items() if k != 'signature'}
    try:
        crypto()[1].from_public_bytes(hex_bytes(key, 32)).verify(
            hex_bytes(signed['signature'], 64), wire(body))
    except MeshError:
        raise
    except Exception as exc:
        raise MeshError('signature verification failed') from exc
    return body


def validate_block(block):
    fields = {'v', 'stream', 'height', 'previous', 'nonce', 'ciphertext', 'signature'}
    if not isinstance(block, dict) or set(block) != fields or type(block['v']) is not int or block['v'] != 1:
        raise MeshError('unsupported block schema')
    hex_bytes(block['stream'], 32)
    integer(block['height'], 1)
    hex_bytes(block['previous'], 32)
    hex_bytes(block['nonce'], 12)
    ciphertext = block['ciphertext']
    if not isinstance(ciphertext, str) or not 32 <= len(ciphertext) <= MAX_WIRE // 2 or len(ciphertext) % 2:
        raise MeshError('ciphertext capacity exceeded')
    hex_bytes(ciphertext, len(ciphertext) // 2)
    verify(block, block['stream'])
    return block


def make_block(payload, identity, height, previous):
    header = {'v': 1, 'stream': public(identity['signing']), 'height': height,
              'previous': previous, 'nonce': os.urandom(12).hex()}
    ciphertext = crypto()[2](archive_key(identity, 'encryption')).encrypt(
        bytes.fromhex(header['nonce']), wire(payload), wire(header))
    return validate_block(sign(dict(header, ciphertext=ciphertext.hex()), identity['signing']))


def decrypt(block, identity):
    validate_block(block)
    if block['stream'] != public(identity['signing']):
        raise MeshError('archive belongs to another identity')
    header = {k: v for k, v in block.items() if k not in ('signature', 'ciphertext')}
    try:
        data = crypto()[2](archive_key(identity, 'encryption')).decrypt(
            bytes.fromhex(block['nonce']), bytes.fromhex(block['ciphertext']), wire(header))
        return json.loads(data)
    except Exception as exc:
        raise MeshError('archive authentication failed') from exc


def archive_key(identity, purpose):
    return hmac.new(hex_bytes(identity['archive'], 32),
                    ('jarvis/peerledger/v1/' + purpose).encode(), hashlib.sha256).digest()


def pseudonym(identity, label, value):
    if value is None or value == '':
        return None
    # Domain separation keeps private commitments and identifiers distinct.
    return hmac.new(archive_key(identity, 'pseudonyms'),
                    wire([label, value]), hashlib.sha256).hexdigest()


def project(event, identity):
    sampled = (event.get('category') == 'sensor' and
               (event.get('attrs') or {}).get('observation') == 'process_present')
    if event.get('category') != 'process' and not sampled:
        return None
    action = 'present' if sampled else event.get('action')
    if action not in ACTIONS:
        return None
    proc, parent = event.get('process') or {}, event.get('parent') or {}
    base = [event.get('host'), event.get('boot')]
    instance = proc.get('guid') or ([proc.get('pid'), proc.get('started')]
                                  if proc.get('started') else None)
    # A bare PID does not establish process identity. Keep it explicitly unknown.
    import datetime
    try:
        stamp = datetime.datetime.fromisoformat(event['time'].replace('Z', '+00:00'))
        minute = int(stamp.timestamp()) // 60 if stamp.tzinfo is not None else None
    except (KeyError, ValueError, TypeError, OverflowError):
        minute = None
    return {'seq': integer(event['seq'], 1, 2**63 - 1), 'minute': minute,
            'action': action, 'sampled': sampled,
            'process': pseudonym(identity, 'process', [base, instance]) if instance else None,
            'parent': pseudonym(identity, 'process', [base, parent['guid']]) if parent.get('guid') else None,
            'image': pseudonym(identity, 'image', proc.get('image')),
            'identity_complete': bool(instance)}


def request(identity, op, height=0, block=None):
    if op not in ('put', 'get', 'head'):
        raise MeshError('unknown operation')
    body = {'v': 1, 'stream': public(identity['signing']), 'op': op,
            'height': integer(height), 'nonce': os.urandom(16).hex()}
    if op == 'put':
        body['block'] = validate_block(block)
    return sign(body, identity['signing'])


def validate_request(req, allowed):
    if not isinstance(req, dict):
        raise MeshError('invalid request')
    fields = {'v', 'stream', 'op', 'height', 'nonce', 'signature'}
    if req.get('op') == 'put':
        fields.add('block')
    if set(req) != fields or type(req['v']) is not int or req['v'] != 1 or req['op'] not in ('put', 'get', 'head'):
        raise MeshError('invalid request schema')
    if req['stream'] not in allowed:
        raise MeshError('producer not enrolled')
    integer(req['height'])
    hex_bytes(req['nonce'], 16)
    verify(req, req['stream'])
    if req['op'] == 'put':
        validate_block(req['block'])
        if req['block']['stream'] != req['stream'] or req['block']['height'] != req['height']:
            raise MeshError('request block identity mismatch')


def response(req, block, private, now=None):
    return sign({'v': 1, 'witness': public(private), 'request': digest(req),
                 'stream': req['stream'], 'op': req['op'], 'nonce': req['nonce'],
                 'time': int(time.time() if now is None else now),
                 'height': block['height'] if block else 0,
                 'digest': digest(block) if block else ZERO,
                 'block': block if req['op'] == 'get' else None}, private)


def validate_response(resp, req, witness, now=None, fresh=True):
    fields = {'v', 'witness', 'request', 'stream', 'op', 'nonce', 'time',
              'height', 'digest', 'block', 'signature'}
    if not isinstance(resp, dict) or set(resp) != fields or type(resp['v']) is not int or resp['v'] != 1:
        raise MeshError('invalid response schema')
    verify(resp, witness)
    if (resp['witness'] != witness or resp['request'] != digest(req) or
            any(resp[k] != req[k] for k in ('stream', 'op', 'nonce'))):
        raise MeshError('response challenge mismatch')
    integer(resp['height'])
    integer(resp['time'], 0, 2**63 - 1)
    hex_bytes(resp['digest'], 32)
    if fresh and abs((time.time() if now is None else now) - resp['time']) > 120:
        raise MeshError('stale witness response')
    if req['op'] == 'put' and (resp['height'] != req['height'] or resp['digest'] != digest(req['block'])):
        raise MeshError('receipt does not match committed block')
    if req['op'] == 'get':
        block = validate_block(resp['block'])
        if block['stream'] != req['stream'] or block['height'] != req['height'] or digest(block) != resp['digest']:
            raise MeshError('retrieved block mismatch')
    elif resp['block'] is not None:
        raise MeshError('unexpected response payload')
    return resp
