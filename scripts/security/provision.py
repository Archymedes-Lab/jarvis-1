#!/usr/bin/env python3
"""Explicit, local development-tool installation; never called by the campaign."""
import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.security.campaign import Step, execute  # noqa: E402

LIMIT = 128 * 1024 * 1024


def sha(path):
    with open(path, 'rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def download(spec, path):
    # Fixed official HTTPS URLs, no credentials or environment proxy configuration.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    size, digest, started = 0, hashlib.sha256(), time.monotonic()
    with opener.open(spec['url'], timeout=30) as response, path.open('xb') as target:
        if not response.url.startswith('https://'):
            raise ValueError('non-HTTPS redirect')
        while data := response.read(65536):
            size += len(data)
            if size > LIMIT or time.monotonic() - started > 120:
                raise ValueError('download bound exceeded')
            target.write(data)
            digest.update(data)
    if digest.hexdigest() != spec['sha256']:
        raise ValueError('artifact digest mismatch')


def install(directory):
    if directory.is_symlink():
        raise ValueError('symlink toolchain refused')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = directory.stat()
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise ValueError('toolchain must be owned by this user and private')
    if (directory / 'receipt.json').exists():
        raise ValueError('toolchain already provisioned; choose a new directory')
    native = directory / 'native'
    (native / 'bin').mkdir(parents=True, exist_ok=True)
    spec = json.loads((ROOT / 'scripts/security/toolchain.json').read_text())
    with tempfile.TemporaryDirectory(prefix='setup-', dir=directory) as work:
        scratch = Path(work)
        home = scratch / 'home'
        home.mkdir()
        def command(name, argv, timeout=300):
            result = execute(Step(name, 'configuration', tuple(argv)), home, timeout=timeout)
            print(json.dumps(result), flush=True)
            if result['status'] != 'passed':
                raise RuntimeError('tool setup step failed: ' + name)
        if not (directory / 'python/bin/python').is_file():
            command('python-venv', ['uv', 'venv', '--python', sys.executable, str(directory / 'python')])
        command('python-hashed-tools', ['uv', 'pip', 'sync', '--python', str(directory / 'python/bin/python'),
                '--require-hashes', '--only-binary', ':all:', '--index-url', 'https://pypi.org/simple',
                str(ROOT / 'scripts/security/requirements.txt')], timeout=600)
        archive = scratch / 'gitleaks.tgz'
        download(spec['gitleaks'], archive)
        with tarfile.open(archive) as tar:
            entries = [m for m in tar if m.name == 'gitleaks' and m.isfile() and m.size < LIMIT]
            if len(entries) != 1:
                raise ValueError('unexpected gitleaks artifact')
            with tar.extractfile(entries[0]) as source:
                binary = source.read(LIMIT + 1)
            path = native / 'bin/gitleaks'
            if path.exists():
                if path.is_symlink() or path.read_bytes() != binary:
                    raise ValueError('existing gitleaks binary differs from pinned archive')
            else:
                path.write_bytes(binary)
        (native / 'bin/gitleaks').chmod(0o700)
        archive = scratch / 'cargo-audit.crate'
        download(spec['cargo-audit'], archive)
        source_dir = scratch / 'source'
        source_dir.mkdir()
        with tarfile.open(archive) as tar:
            members = tar.getmembers()
            if len(members) > 2000 or sum(m.size for m in members) > LIMIT:
                raise ValueError('crate extraction bound exceeded')
            if any(not (m.isfile() or m.isdir()) for m in members):
                raise ValueError('crate links refused')
            tar.extractall(source_dir, filter='data')
        source = source_dir / ('cargo-audit-' + spec['cargo-audit']['version'])
        env = dict(CARGO_HOME=str(directory / 'cargo-cache'), RUSTUP_HOME=str(Path.home() / '.rustup'),
                   RUSTUP_AUTO_INSTALL='0', CARGO_BUILD_JOBS='2', CARGO_TARGET_DIR=str(directory / 'cargo-target'))
        # Cargo's embedded lockfile is verified as part of the pinned crate.
        # Keep logs private; no production credentials enter this process.
        result = execute(Step('cargo-audit-build', 'configuration', ('cargo', 'install', '--locked',
                         '--path', str(source), '--root', str(native), '--jobs', '2')),
                         home, timeout=1800, environment=env)
        print(json.dumps(result), flush=True)
        if result['status'] != 'passed':
            raise RuntimeError('cargo-audit build failed')
    bins = {}
    for name in ['bandit', 'semgrep', 'pip-audit', 'z3', 'gitleaks', 'cargo-audit']:
        candidates = [directory / 'python/bin' / name, native / 'bin' / name]
        if name == 'z3':
            candidates.extend((directory / 'python/lib').glob('python*/site-packages/z3/bin/z3'))
        path = next((p for p in candidates if p.is_file()), None)
        if path is None:
            raise RuntimeError('installed tool missing: ' + name)
        bins[name] = {'path': str(path.relative_to(directory)), 'sha256': sha(path)}
    receipt = {'schema': 1, 'requirements_sha256': sha(ROOT / 'scripts/security/requirements.txt'),
               'manifest_sha256': sha(ROOT / 'scripts/security/toolchain.json'), 'tools': bins}
    (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    (directory / 'receipt.json').chmod(0o600)
    print(json.dumps({'toolchain': str(directory), 'tools': sorted(bins)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path)
    args = parser.parse_args()
    directory = args.directory or Path(tempfile.mkdtemp(prefix='argus-security-tools-'))
    try:
        install(directory.absolute())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({'status': 'failed', 'toolchain': str(directory)}))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
