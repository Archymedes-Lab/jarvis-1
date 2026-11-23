"""Prepare and exercise two local witness servers without touching JARVIS services.

Run as a module: python3 -m scripts.mesh_local prepare|serve|publish|check.
All generated keys and databases live in an ignored owner-only directory.
"""
import argparse
import datetime
import ipaddress
import json
import ssl
from functools import partial
from pathlib import Path

from jarvis.core.eventlog import DEFAULT_ROOT, EventLog
from jarvis.platform.peerledger import protocol, store, transport, workflow

DEFAULT_ROOT_LOCAL = Path(__file__).resolve().parents[1] / '.peer-mesh-local'


def prepare(root):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    root = Path(root)
    root.mkdir(mode=0o700, exist_ok=False)
    nodes = {}
    for index, name in enumerate(('origin', 'witness1', 'witness2')):
        nodes[name] = store.init(root / name)['public_key']
        if index:
            private = ec.generate_private_key(ec.SECP256R1())
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
            now = datetime.datetime.now(datetime.timezone.utc)
            certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                           .public_key(private.public_key()).serial_number(x509.random_serial_number())
                           .not_valid_before(now - datetime.timedelta(minutes=1))
                           .not_valid_after(now + datetime.timedelta(days=30))
                           .add_extension(x509.SubjectAlternativeName([
                               x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                           .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                           .sign(private, hashes.SHA256()))
            store.new_file(root / name / 'tls-key.pem', private.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            store.new_file(root / name / 'tls.pem', certificate.public_bytes(serialization.Encoding.PEM))
    store.new_file(root / 'ca.pem', b''.join((root / name / 'tls.pem').read_bytes()
                                           for name in ('witness1', 'witness2')))
    config = {'v': 1, 'nodes': nodes, 'ports': {'witness1': 9443, 'witness2': 9444},
              'limit': 'same-host experiment; no independent machine survival'}
    store.new_file(root / 'public-config.json', protocol.wire(config))
    return config


def load(root):
    store.private_path(root, directory=True)
    path = store.private_path(Path(root) / 'public-config.json')
    if path.stat().st_size > 4096:
        raise protocol.MeshError('local configuration too large')
    return json.loads(path.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'serve', 'publish', 'check', 'checkpoint', 'recover'))
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT_LOCAL)
    parser.add_argument('--node', choices=('witness1', 'witness2'))
    parser.add_argument('--log', default=DEFAULT_ROOT)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--destination', type=Path)
    args = parser.parse_args()
    if args.action == 'prepare':
        result = prepare(args.root)
    else:
        config = load(args.root)
        if args.action == 'serve':
            if not args.node:
                parser.error('serve requires --node')
            root = args.root / args.node
            with transport.server(root, [config['nodes']['origin']], root / 'tls.pem',
                                  root / 'tls-key.pem', port=config['ports'][args.node]) as server:
                print(json.dumps({'ready': True, 'node': args.node, 'port': server.server_port}), flush=True)
                server.serve_forever(poll_interval=0.5)
            return 0
        configured = workflow.peers([
            'https://127.0.0.1:' + str(config['ports'][name]) + ',' + config['nodes'][name]
            for name in ('witness1', 'witness2')])
        send = partial(transport.exchange, context=ssl.create_default_context(cafile=str(args.root / 'ca.pem')))
        owner = store.identity(args.root / 'origin')
        if args.action == 'recover':
            if not args.output or not args.destination:
                parser.error('recover requires --output CHECKPOINT and --destination NEW_DIRECTORY')
            result = workflow.recover(owner, args.destination, args.output, configured, send=send)
        else:
            with store.Ledger(args.root / 'origin') as ledger:
                if args.action == 'publish':
                    with EventLog(args.log) as log:
                        result = workflow.publish(log, ledger, owner, configured, quorum=2, send=send)
                elif args.action == 'check':
                    result = workflow.check(ledger, owner, configured, send=send)
                else:
                    if not args.output:
                        parser.error('checkpoint requires --output NEW_FILE')
                    result = workflow.checkpoint(ledger, owner, args.output)
    print(json.dumps(result, indent=2))
    return 0 if result.get('ok', True) else 2


if __name__ == '__main__':
    raise SystemExit(main())
