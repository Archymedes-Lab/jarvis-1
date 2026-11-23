"""Owner-only bounded durable storage; no pruning or implicit source mutations."""
import json
import os
import sqlite3
import stat
from pathlib import Path

from .protocol import ZERO, MeshError, digest, hex_bytes, public, validate_block, wire

DEFAULT_BUDGET = 64 * 1024 * 1024


def private_path(path, directory=False):
    path = Path(path)
    st = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise MeshError('mesh paths must be owner-only, owned, and not symlinks')
    return path


def new_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        # Preserve interrupted files for explicit inspection, never overwrite.
        raise


def init(root):
    root = Path(root)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    identity = {'v': 1, 'signing': os.urandom(32).hex(), 'archive': os.urandom(32).hex()}
    new_file(root / 'identity.json', wire(identity))
    return {'public_key': public(identity['signing']), 'root': str(root)}


def identity(root):
    root = private_path(root, directory=True)
    path = private_path(root / 'identity.json')
    if path.stat().st_size > 1024:
        raise MeshError('identity file too large')
    value = json.loads(path.read_bytes())
    if set(value) != {'v', 'signing', 'archive'} or value['v'] != 1:
        raise MeshError('identity schema mismatch')
    hex_bytes(value['signing'], 32)
    hex_bytes(value['archive'], 32)
    return value


class Ledger:
    def __init__(self, root, budget=DEFAULT_BUDGET):
        if type(budget) is not int or not 8192 <= budget <= 1024**3:
            raise MeshError('invalid storage budget')
        self.root = private_path(root, directory=True)
        self.budget = budget
        path = self.root / 'mesh.db'
        if not path.exists():
            try:
                new_file(path, b'')
            except FileExistsError:
                pass
        private_path(path)
        for suffix in ('-journal', '-wal', '-shm'):
            side = self.root / ('mesh.db' + suffix)
            if side.exists() or side.is_symlink():
                private_path(side)
        self.db = sqlite3.connect(path, timeout=0.2)
        try:
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA journal_mode=DELETE')
            page_size = self.db.execute('PRAGMA page_size').fetchone()[0]
            pages = self.db.execute('PRAGMA page_count').fetchone()[0]
            if pages * page_size > budget:
                raise MeshError('existing database exceeds budget')
            self.db.execute(f'PRAGMA max_page_count={budget // page_size}')
            self.db.executescript('''
                CREATE TABLE IF NOT EXISTS blocks(
                    stream TEXT, height INTEGER, digest TEXT, data BLOB NOT NULL,
                    PRIMARY KEY(stream, height));
                CREATE TABLE IF NOT EXISTS receipts(
                    stream TEXT, height INTEGER, witness TEXT, data BLOB NOT NULL,
                    PRIMARY KEY(stream,height,witness));
            ''')
        except BaseException:
            self.db.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.db.close()

    def head(self, stream):
        row = self.db.execute('SELECT data FROM blocks WHERE stream=? ORDER BY height DESC LIMIT 1',
                              (stream,)).fetchone()
        return json.loads(row[0]) if row else None

    def get(self, stream, height):
        row = self.db.execute('SELECT data FROM blocks WHERE stream=? AND height=?',
                              (stream, height)).fetchone()
        if not row:
            raise MeshError('block unavailable')
        return json.loads(row[0])

    def append(self, block):
        validate_block(block)
        data, block_digest = wire(block), digest(block)
        try:
            self.db.execute('BEGIN IMMEDIATE')
            existing = self.db.execute('SELECT digest,data FROM blocks WHERE stream=? AND height=?',
                                      (block['stream'], block['height'])).fetchone()
            if existing:
                if existing[0] != block_digest or existing[1] != data:
                    raise MeshError('fork or modified existing block')
                self.db.commit()
                return False
            head = self.head(block['stream'])
            if (block['height'] != (head['height'] + 1 if head else 1) or
                    block['previous'] != (digest(head) if head else ZERO)):
                raise MeshError('chain gap, rollback or fork')
            count, size = self.db.execute('SELECT count(*),coalesce(sum(length(data)),0) FROM blocks').fetchone()
            if count >= 100_000 or size + len(data) > self.budget:
                raise MeshError('storage capacity exhausted; no pruning')
            self.db.execute('INSERT INTO blocks VALUES(?,?,?,?)',
                            (block['stream'], block['height'], block_digest, data))
            self.db.commit()
            return True
        except BaseException:
            self.db.rollback()
            raise

    def receipt(self, block, req, resp):
        # Caller validates challenge and signature before persisting.
        if self.get(block['stream'], block['height']) != block:
            raise MeshError('cannot receipt unknown block')
        if req.get('op') != 'put' or req.get('block') != block:
            raise MeshError('receipt request does not identify stored block')
        # The signed request can be reconstructed from its immutable block.
        # Do not duplicate the ciphertext once for every witness receipt.
        compact_req = {k: v for k, v in req.items() if k != 'block'}
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO receipts VALUES(?,?,?,?)',
                            (block['stream'], block['height'], resp['witness'],
                             wire({'request': compact_req, 'response': resp})))

    def receipts(self, stream, height):
        values = [json.loads(row[0]) for row in self.db.execute(
            'SELECT data FROM receipts WHERE stream=? AND height=? LIMIT 32', (stream, height))]
        for saved in values:
            if 'block' not in saved['request']:
                saved['request'] = dict(saved['request'], block=self.get(stream, height))
        return values

    def verify(self, stream):
        previous, height = ZERO, 0
        for stored_digest, data in self.db.execute(
                'SELECT digest,data FROM blocks WHERE stream=? ORDER BY height LIMIT 100001', (stream,)):
            block = validate_block(json.loads(data))
            if (block['stream'] != stream or block['height'] != height + 1 or
                    block['previous'] != previous or digest(block) != stored_digest):
                raise MeshError('stored chain verification failed')
            height, previous = block['height'], stored_digest
        if height > 100_000:
            raise MeshError('verification bound exceeded')
        return {'height': height, 'digest': previous}
