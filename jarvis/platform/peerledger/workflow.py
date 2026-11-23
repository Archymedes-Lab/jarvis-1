"""Prepare, replicate, challenge and recover bounded private evidence batches."""
import json
from pathlib import Path

from . import protocol as p
from . import source
from .store import Ledger, identity, new_file, private_path
from .transport import exchange, peer


def peers(values):
    result = [peer(value) for value in values]
    if not 1 <= len(result) <= 8 or len({key for _, key in result}) != len(result):
        raise p.MeshError('configure 1..8 distinct witness keys')
    return result


def receipt_count(ledger, block, keys):
    valid = set()
    for saved in ledger.receipts(block['stream'], block['height']):
        req, resp = saved['request'], saved['response']
        key = resp.get('witness')
        if key in keys:
            p.verify(req, block['stream'])
            if req.get('op') != 'put' or req.get('block') != block:
                raise p.MeshError('stored receipt request mismatch')
            p.validate_response(resp, req, key, fresh=False)
            valid.add(key)
    return len(valid)


def prepare(log, ledger, owner):
    stream = p.public(owner['signing'])
    ledger.verify(stream)
    head = ledger.head(stream)
    last = p.decrypt(head, owner) if head else None
    after = last['through'] if last else 0
    if log.last_seq < after:
        raise p.MeshError('canonical history rolled back')
    anchor = last['source_head'] if last and last['source_head']['segment'] else None
    def transform(event):
        return {'seq': event['seq'], 'row': p.project(event, owner),
                'commitment': p.pseudonym(owner, 'source-record', event)}
    records = iter(source.events(log, after, anchor, transform))
    if last and after > 0:
        previous = next(records, None)
        if (previous is None or previous['seq'] != after or
                previous['commitment'] != last['source_record']):
            raise p.MeshError('canonical cursor evidence missing or rewritten')
    rows, scanned, skipped, through, final = [], 0, 0, after, None
    for event in records:
        if event['seq'] != through + 1:
            raise p.MeshError('source gap requires explicit investigation')
        through, final = event['seq'], event
        scanned += 1
        row = event['row']
        if row is None:
            skipped += 1
        else:
            rows.append(row)
        if scanned >= p.MAX_SCAN or len(rows) >= p.MAX_ROWS:
            break
    if not scanned:
        return None
    payload = {'v': 1, 'after': after, 'through': through, 'scanned': scanned,
               'skipped': skipped, 'rows': rows, 'source_head': log.head(),
               'source_record': final['commitment'],
               'coverage': 'observed process events and sampled presence only'}
    block = p.make_block(payload, owner, head['height'] + 1 if head else 1,
                         p.digest(head) if head else p.ZERO)
    ledger.append(block)
    return block


def publish(log, ledger, owner, configured, quorum=1, send=exchange):
    if type(quorum) is not int or not 1 <= quorum <= len(configured):
        raise p.MeshError('quorum exceeds explicitly configured witnesses')
    keys = {key for _, key in configured}
    stream = p.public(owner['signing'])
    ledger.verify(stream)
    head = ledger.head(stream)
    # Finish the last committed batch before recording another. Local receipts
    # describe historical custody; current availability is checked separately.
    pending = head and receipt_count(ledger, head, keys) < quorum
    block = head if pending else prepare(log, ledger, owner)
    if block is None:
        return {'ok': True, 'prepared': False, 'height': head['height'] if head else 0,
                'fresh_receipts_checked': False}
    failures, confirmed = [], set()
    for url, key in configured:
        try:
            # A new peer can catch up within a bounded 16-block pass. Refuse
            # rollback below the last receipt retained for this particular peer.
            head_req = p.request(owner, 'head')
            remote = p.validate_response(send(url, key, head_req), head_req, key)
            height = remote['height']
            if height > block['height']:
                raise p.MeshError('witness ahead of local chain')
            if height and remote['digest'] != p.digest(ledger.get(stream, height)):
                raise p.MeshError('witness fork')
            saved = ledger.db.execute(
                'SELECT max(height) FROM receipts WHERE stream=? AND witness=?', (stream, key)).fetchone()[0]
            if saved and height < saved:
                raise p.MeshError('witness rolled back retained custody')
            # Re-put current head to get a fresh bound receipt if already there.
            for n in range(height + 1 if height < block['height'] else height,
                           min(block['height'], height + 16) + 1):
                item = ledger.get(stream, n)
                req = p.request(owner, 'put', n, item)
                resp = p.validate_response(send(url, key, req), req, key)
                ledger.receipt(item, req, resp)
                if n == block['height']:
                    confirmed.add(key)
        except (p.MeshError, OSError) as exc:
            failures.append({'witness': key, 'error': str(exc)[:100]})
    copies = receipt_count(ledger, block, keys)
    return {'ok': len(confirmed) >= quorum, 'height': block['height'], 'digest': p.digest(block),
            'receipt_copies': copies, 'required': quorum, 'failures': failures,
            'fresh_confirmations': len(confirmed),
            'custody': 'historical commits; independent administration and current retention unproven'}


def check(ledger, owner, configured, send=exchange):
    stream = p.public(owner['signing'])
    local = ledger.verify(stream)
    results = []
    for url, key in configured:
        try:
            req = p.request(owner, 'head')
            resp = p.validate_response(send(url, key, req), req, key)
            if resp['height'] != local['height'] or resp['digest'] != local['digest']:
                raise p.MeshError('witness head differs from retained local checkpoint')
            results.append({'witness': key, 'ok': True, 'height': resp['height']})
        except (p.MeshError, OSError) as exc:
            results.append({'witness': key, 'ok': False, 'error': str(exc)[:100]})
    return {'ok': all(r['ok'] for r in results), 'peers': results,
            'limit': 'a matching head does not prove every historical payload remains retrievable'}


def checkpoint(ledger, owner, path):
    stream = p.public(owner['signing'])
    ledger.verify(stream)
    head = ledger.head(stream)
    if not head:
        raise p.MeshError('no chain to checkpoint')
    saved = ledger.receipts(stream, head['height'])
    if not saved:
        raise p.MeshError('no witness receipt for latest block')
    for item in saved:
        p.validate_response(item['response'], item['request'], item['response']['witness'], fresh=False)
    new_file(path, p.wire({'v': 1, 'stream': stream, 'height': head['height'],
                          'digest': p.digest(head), 'receipts': saved}))
    return {'ok': True, 'height': head['height'], 'digest': p.digest(head),
            'instruction': 'retain this file independently of the origin'}


def recover(owner, destination, checkpoint_path, configured, send=exchange):
    saved_path = private_path(checkpoint_path)
    if saved_path.stat().st_size > p.MAX_WIRE:
        raise p.MeshError('checkpoint too large')
    saved = json.loads(saved_path.read_bytes())
    stream = p.public(owner['signing'])
    if set(saved) != {'v', 'stream', 'height', 'digest', 'receipts'} or saved['v'] != 1 or saved['stream'] != stream:
        raise p.MeshError('checkpoint identity mismatch')
    p.integer(saved['height'], 1)
    p.hex_bytes(saved['digest'], 32)
    keys, valid = {key for _, key in configured}, set()
    if not isinstance(saved['receipts'], list) or len(saved['receipts']) > 32:
        raise p.MeshError('checkpoint receipts invalid')
    for item in saved['receipts']:
        req, resp = item['request'], item['response']
        if resp['witness'] not in keys:
            continue
        p.verify(req, stream)
        p.validate_response(resp, req, resp['witness'], fresh=False)
        if (req['op'] != 'put' or resp['stream'] != stream or
                resp['height'] != saved['height'] or resp['digest'] != saved['digest']):
            raise p.MeshError('checkpoint receipt mismatch')
        valid.add(resp['witness'])
    if not valid:
        raise p.MeshError('checkpoint lacks a pinned witness')
    # Bounded recoveries may resume an interrupted destination; no overwrite.
    destination = Path(destination)
    if not destination.exists():
        destination.mkdir(mode=0o700)
        new_file(destination / 'identity.json', p.wire(owner))
    if identity(destination) != owner:
        raise p.MeshError('recovery destination identity mismatch')
    with Ledger(destination) as ledger:
        current = ledger.verify(stream)['height']
        if current > saved['height']:
            raise p.MeshError('recovery destination ahead of checkpoint')
        for n in range(current + 1, min(saved['height'], current + 16) + 1):
            found = False
            for url, key in configured:
                try:
                    req = p.request(owner, 'get', n)
                    resp = p.validate_response(send(url, key, req), req, key)
                    p.decrypt(resp['block'], owner)  # Authenticate private archive too.
                    if n == saved['height'] and p.digest(resp['block']) != saved['digest']:
                        raise p.MeshError('recovery checkpoint mismatch')
                    ledger.append(resp['block'])
                    found = True
                    break
                except (p.MeshError, OSError):
                    continue
            if not found:
                raise p.MeshError('recovery blocked; retained destination is incomplete')
        head = ledger.verify(stream)
        complete = head['height'] == saved['height']
        if complete and head['digest'] != saved['digest']:
            raise p.MeshError('recovery checkpoint mismatch')
        return {'ok': complete, 'complete': complete, 'height': head['height'],
                'target': saved['height'], 'limit': 'minimized projection only; uncheckpointed tails unknown'}
