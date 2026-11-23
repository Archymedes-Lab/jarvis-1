"""Verify source headers and the payloads consumed in this bounded pass.

Hash the complete touched segment, retaining only a bounded selection in
memory. Yield that selection only after its containing payload verifies.
Already copied history is covered by mesh commitments; this is not a full
periodic audit of every old canonical payload.
"""
import gzip
import hashlib
import json

from jarvis.core.eventlog import GENESIS, header_hash

from .protocol import MAX_SCAN, MeshError, wire

MAX_SEGMENT_BYTES = 256 * 1024 * 1024
MAX_VERIFY_BYTES = 256 * 1024 * 1024
MAX_SELECTED_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_HEADERS = 100_000
MAX_HEADER_BYTES = 256 * 1024


def events(log, after, anchor, transform):
    if len(log.chain) > MAX_HEADERS:
        raise MeshError('source header verification bound exceeded')
    previous, expected, anchored = GENESIS, 1, anchor is None
    pruned = log._pruned()
    for index, header in enumerate(log.chain):
        if (header['segment'] != index + 1 or header['previous_hash'] != previous or
                header_hash(header) != header['hash'] or
                (header.get('count') and header['first_seq'] != expected)):
            raise MeshError('source header chain verification failed')
        if anchor and header['segment'] == anchor['segment'] and header['hash'] == anchor['hash']:
            anchored = True
        if header['segment'] not in pruned and not log._segment_path(header['segment']).is_file():
            raise MeshError('source payload missing')
        previous, expected = header['hash'], header['last_seq'] + 1
    if not anchored:
        raise MeshError('source checkpoint lost or rewritten')
    verified_bytes, count, selected_bytes = 0, 0, 0
    limit = MAX_SCAN + int(after > 0)
    for header in log.chain:
        if header['last_seq'] < max(after, 1) or header['segment'] in pruned:
            continue
        declared = header.get('payload_bytes')
        if type(declared) is not int or not 0 <= declared <= MAX_SEGMENT_BYTES:
            raise MeshError('source segment capacity exceeded')
        if verified_bytes + declared > MAX_VERIFY_BYTES:
            raise MeshError('source verification byte budget exhausted')
        selected, read, hasher = [], 0, hashlib.sha256()
        try:
            with gzip.open(log._segment_path(header['segment']), 'rb') as file:
                line = file.readline(MAX_HEADER_BYTES + 1)
                if len(line) > MAX_HEADER_BYTES or json.loads(line) != header:
                    raise MeshError('source segment header mismatch')
                while True:
                    line = file.readline(MAX_LINE_BYTES + 1)
                    if not line:
                        break
                    read += len(line)
                    if len(line) > MAX_LINE_BYTES or read > declared:
                        raise MeshError('source payload read budget exceeded')
                    hasher.update(line)
                    if count >= limit:
                        continue  # Still hash every remaining byte before yielding.
                    row = json.loads(line)
                    if 'cursor' not in row and max(after, 1) <= row['seq'] <= log.last_seq:
                        count += 1
                        projected = transform(row)
                        selected_bytes += len(wire(projected))
                        if selected_bytes > MAX_SELECTED_BYTES:
                            raise MeshError('source selection memory budget exceeded')
                        selected.append(projected)
                if read != declared or hasher.hexdigest() != header['payload_sha256']:
                    raise MeshError('source payload integrity failed')
        except MeshError:
            raise
        except (OSError, ValueError, EOFError) as exc:
            raise MeshError('source segment unreadable or invalid') from exc
        verified_bytes += read
        yield from selected
        if count >= limit:
            return
    if log.active.exists() and log.active.stat().st_size > MAX_SEGMENT_BYTES:
        raise MeshError('active source capacity exceeded')
    # The canonical reader exposes only batches with their commit cursor.
    for row in log._iter_active(max(after - 1, 0), log.last_seq):
        count += 1
        if count > limit:
            return
        yield transform(row)
