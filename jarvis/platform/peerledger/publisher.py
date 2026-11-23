"""Bounded supervised publication. No collector mutation or response authority."""
import os
import socket
import sqlite3
import time
from pathlib import Path

from jarvis.core import filelock
from jarvis.core.eventlog import EventLog, LogError

from . import protocol as p
from . import source, workflow
from .store import DEFAULT_BUDGET, Ledger, identity, private_path

INTERVAL = 30
MAX_BATCHES = 4
HEARTBEAT = 300


def notify(message):
    """User-service watchdog liveness, separate from signed custody freshness."""
    address = os.environ.get('NOTIFY_SOCKET')
    if not address or not address.startswith(('/', '@')):
        return
    if address.startswith('@'):
        address = '\0' + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.1)
            sock.sendto(message.encode('ascii'), address)
    except OSError:
        pass


def atomic_state(root, value):
    root = private_path(root, directory=True)
    target, pending = root / 'publisher-state.json', root / 'publisher-state.new'
    if target.exists() or target.is_symlink():
        private_path(target)
    if pending.exists() or pending.is_symlink():
        private_path(pending)
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as file:
        file.write(p.wire(value))
        file.flush()
        os.fsync(file.fileno())
    os.replace(pending, target)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class PublisherLock:
    def __init__(self, root):
        path = private_path(root, directory=True) / 'publisher.lock'
        if path.exists() or path.is_symlink():
            private_path(path)
        self.fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            filelock.acquire(self.fd)
        except OSError as exc:
            os.close(self.fd)
            raise p.MeshError('another continuous publisher owns this stream') from exc

    def __enter__(self):
        return self

    def __exit__(self, *args):
        os.close(self.fd)


def baseline(log, ledger, owner):
    """Explicit live-only baseline; prior history stays local and unreplicated."""
    stream = p.public(owner['signing'])
    if ledger.head(stream):
        raise p.MeshError('cannot reset or replace an existing mesh stream')
    through = log.last_seq
    def transform(ev):
        return {'seq': ev['seq'], 'commitment': p.pseudonym(owner, 'source-record', ev)}
    record = next(iter(source.events(log, through, None, transform)), None) if through else None
    if through and (record is None or record['seq'] != through):
        raise p.MeshError('baseline cursor lacks committed source evidence')
    payload = {'v': 1, 'after': through, 'through': through, 'scanned': 0, 'skipped': 0,
               'rows': [], 'source_head': log.head(),
               'source_record': record['commitment'] if record else None,
               'unreplicated_prefix': [1, through] if through else None,
               'baseline': True, 'coverage': 'live stream; pre-baseline history not replicated'}
    block = p.make_block(payload, owner, 1, p.ZERO)
    ledger.append(block)
    return {'height': 1, 'unreplicated_through': through}


def heartbeat(ledger, owner):
    head = ledger.head(p.public(owner['signing']))
    if not head:
        return None
    previous = p.decrypt(head, owner)
    # Keep the same committed source reference; a heartbeat invents no event.
    payload = dict(previous, after=previous['through'], rows=[], scanned=0, skipped=0,
                   heartbeat=True, baseline=False)
    block = p.make_block(payload, owner, head['height'] + 1, p.digest(head))
    ledger.append(block)
    return block


def cycle(root, log_root, configured, send, budget=DEFAULT_BUDGET, now=None, heartbeat_due=False):
    owner = identity(root)
    started = time.monotonic()
    wall = time.time() if now is None else now
    state = {'v': 1, 'time': wall, 'ok': False, 'batches': 0,
             'scope': 'fresh hosted custody; collector completeness not established'}
    try:
        with Ledger(root, budget) as ledger:
            with EventLog(log_root) as log:
                if ledger.head(p.public(owner['signing'])) is None:
                    state['baseline'] = baseline(log, ledger, owner)
                wrote = False
                for _ in range(MAX_BATCHES):
                    result = workflow.publish(log, ledger, owner, configured, quorum=len(configured), send=send)
                    state['last_publish'] = result
                    if not result['ok']:
                        raise p.MeshError('hosted custody not confirmed')
                    if result.get('prepared') is False:
                        if heartbeat_due and not wrote:
                            heartbeat(ledger, owner)
                            heartbeat_due = False
                            continue
                        break
                    wrote = True
                    state['batches'] += 1
                checked = workflow.check(ledger, owner, configured, send=send)
                if not checked['ok']:
                    raise p.MeshError('hosted head is missing, stale, invalid or mismatched')
                head = ledger.head(p.public(owner['signing']))
                payload = p.decrypt(head, owner)
                state.update(ok=True, height=head['height'], digest=p.digest(head),
                             source_cursor=payload['through'], observed_source_cursor=log.last_seq,
                             source_backlog=max(0, log.last_seq - payload['through']),
                             fresh_witnesses=len(checked['peers']),
                             heartbeat_written=bool(payload.get('heartbeat')) and wrote)
    except (p.MeshError, LogError, OSError, sqlite3.Error, ValueError, KeyError, TypeError) as exc:
        state['error'] = str(exc)[:100] if isinstance(exc, p.MeshError) else type(exc).__name__
    state['duration_seconds'] = round(time.monotonic() - started, 3)
    atomic_state(root, state)
    return state


def run(root, log_root, configured, send, interval=INTERVAL, budget=DEFAULT_BUDGET,
        stop=None, wait=None):
    if type(interval) is not int or not INTERVAL <= interval <= 3600 or len(configured) != 1:
        raise p.MeshError('continuous publisher requires one pinned hosted peer and 30..3600 second interval')
    stop = stop or (lambda: False)
    wait = wait or time.sleep
    last_write = time.monotonic()
    with PublisherLock(root):
        notify('READY=1')
        while not stop():
            start = time.monotonic()
            state = cycle(root, log_root, configured, send, budget,
                          heartbeat_due=start - last_write >= HEARTBEAT)
            if state['ok'] and state['batches']:
                last_write = time.monotonic()
            notify('WATCHDOG=1')
            wait(max(interval, interval - (time.monotonic() - start)))


def main():
    import argparse

    from .transport import exchange
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--log', required=True)
    parser.add_argument('--peer', required=True)
    parser.add_argument('--interval', type=int, default=INTERVAL)
    parser.add_argument('--budget', type=int, default=DEFAULT_BUDGET)
    args = parser.parse_args()
    run(Path(args.root), args.log, workflow.peers([args.peer]), exchange, args.interval, args.budget)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
