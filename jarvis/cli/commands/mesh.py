"""Opt-in permissioned encrypted process history replication."""
import json
import sqlite3
import ssl
from functools import partial

from jarvis.core.eventlog import DEFAULT_ROOT, EventLog, LogError
from jarvis.platform.peerledger import protocol, store, transport, workflow


def cmd_mesh(args, _store):
    try:
        if args.action == 'init':
            result = store.init(args.root)
        elif args.action == 'serve':
            if not args.cert or not args.tls_key:
                raise protocol.MeshError('serve requires TLS certificate and key')
            with transport.server(args.root, args.allow_producer, args.cert, args.tls_key,
                                  args.bind, args.port, args.budget) as server:
                server.serve_forever(poll_interval=0.5)
            return 0
        else:
            owner = store.identity(args.root)
            configured = workflow.peers(args.peer) if args.action in ('publish', 'check', 'recover') else []
            send = partial(transport.exchange, context=ssl.create_default_context(cafile=args.ca_file))
            if args.action == 'recover':
                if not args.destination or not args.checkpoint:
                    raise protocol.MeshError('recover requires destination and independently retained checkpoint')
                result = workflow.recover(owner, args.destination, args.checkpoint, configured, send=send)
            else:
                with store.Ledger(args.root, args.budget) as ledger:
                    stream = protocol.public(owner['signing'])
                    if args.action == 'publish':
                        with EventLog(args.log) as log:
                            result = workflow.publish(log, ledger, owner, configured, args.quorum, send=send)
                    elif args.action == 'check':
                        result = workflow.check(ledger, owner, configured, send=send)
                    elif args.action == 'checkpoint':
                        if not args.output:
                            raise protocol.MeshError('checkpoint requires new output file')
                        result = workflow.checkpoint(ledger, owner, args.output)
                    elif args.action == 'read':
                        ledger.verify(stream)
                        block = ledger.get(stream, args.height) if args.height else ledger.head(stream)
                        result = protocol.decrypt(block, owner) if block else {'rows': []}
                    else:
                        result = ledger.verify(stream)
                        result['public_key'] = stream
                        result['saved_receipt_records'] = len(ledger.receipts(stream, result['height']))
                        result['receipts_verified_against_pins'] = False
                        result['live_replication_verified'] = False
        print(json.dumps(result, indent=2))
        return 0 if result.get('ok', True) else 2
    except (ValueError, TypeError, KeyError, OSError, sqlite3.Error, LogError) as exc:
        # Fixed error types prevent accidentally printing key file contents.
        print(json.dumps({'ok': False, 'error': str(exc)[:200] if isinstance(exc, protocol.MeshError)
                          else type(exc).__name__}))
        return 2


def add_parser(sub):
    p = sub.add_parser('mesh', help='opt-in encrypted peer process history; explicit pinned witnesses')
    p.add_argument('action', choices=('init', 'serve', 'publish', 'status', 'check', 'checkpoint', 'recover', 'read'))
    p.add_argument('--root', required=True, help='owner-only mesh identity/store directory')
    p.add_argument('--log', default=DEFAULT_ROOT)
    p.add_argument('--peer', action='append', default=[], help='https://HOST:PORT,WITNESS_PUBLIC_HEX')
    p.add_argument('--quorum', type=int, default=1)
    p.add_argument('--budget', type=int, default=store.DEFAULT_BUDGET)
    p.add_argument('--allow-producer', action='append', default=[])
    p.add_argument('--cert')
    p.add_argument('--tls-key')
    p.add_argument('--ca-file', help='explicit CA bundle for self-hosted TLS; certificate verification stays enabled')
    p.add_argument('--bind', default='127.0.0.1')
    p.add_argument('--port', type=int, default=9443)
    p.add_argument('--output')
    p.add_argument('--checkpoint')
    p.add_argument('--destination')
    p.add_argument('--height', type=int, help='read a particular historical block; default latest')
    p.set_defaults(fn=cmd_mesh)
