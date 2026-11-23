"""Create a review packet or validate a separately signed, source-bound review.

A signature attests to the registered reviewer's statement; it does not prove
human diligence, prove the implementation, or authorize any protected action.
This tool neither generates a reviewer key nor signs/approves a review.
"""
import argparse
import datetime
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.security.campaign import source_snapshot  # noqa: E402

SCOPES = ('authority', 'transport', 'release', 'privacy', 'tooling', 'vm-isolation', 'dependency-patch')
ALLOWED = ROOT / 'scripts/security/reviewers.allowed'
MAX_BYTES = 128 * 1024


def validate(record, source, now):
    if not isinstance(record, dict) or type(record.get('schema')) is not int or record.get('schema') != 1 or source.get('status') != 'measured':
        return False
    if record.get('source_sha256') != source.get('sha256'):
        return False
    if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', str(record.get('reviewer', ''))):
        return False
    try:
        reviewed = datetime.datetime.fromisoformat(record['reviewed_at'])
        if reviewed.tzinfo is None or not 0 <= (now - reviewed).total_seconds() <= 30 * 86400:
            return False
    except (TypeError, KeyError, ValueError):
        return False
    scopes = record.get('scopes')
    if (record.get('independent_of_author') is not True or not isinstance(scopes, list)
            or not all(isinstance(scope, str) for scope in scopes) or len(scopes) != len(SCOPES)
            or set(scopes) != set(SCOPES)):
        return False
    findings = record.get('findings')
    return isinstance(findings, list) and all(isinstance(item, dict) and item.get('status') == 'resolved'
          and re.fullmatch('[0-9a-f]{64}', str(item.get('evidence_sha256', ''))) for item in findings)


def bounded(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise ValueError('review input bound')
        raw = file.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError('review input grew')
        return raw


def verify(path, signature, allowed=ALLOWED, source=None, now=None):
    try:
        raw, sig, signers = bounded(path), bounded(signature), bounded(allowed)
        record = json.loads(raw)
        source = source if source is not None else source_snapshot()
        now = now or datetime.datetime.now(datetime.timezone.utc)
        if not validate(record, source, now):
            return False
        with tempfile.TemporaryDirectory(prefix='argus-review-verify-') as scratch:
            sig_path, allowed_path = Path(scratch) / 'signature', Path(scratch) / 'signers'
            sig_path.write_bytes(sig)
            allowed_path.write_bytes(signers)
            result = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(allowed_path), '-I', record['reviewer'],
                                     '-n', 'argus-security-review', '-s', str(sig_path)], input=raw,
                                    capture_output=True, timeout=10, check=False)
        return result.returncode == 0
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--signature', type=Path)
    args = parser.parse_args()
    if args.receipt or args.signature:
        passed = bool(args.receipt and args.signature and verify(args.receipt, args.signature))
        print(json.dumps({'review_record_verified': passed, 'scope': 'registered reviewer statement only'}))
        return 0 if passed else 2
    snapshot = source_snapshot()
    directory = Path(tempfile.mkdtemp(prefix='argus-review-packet-'))
    packet = {'schema': 1, 'source_sha256': snapshot.get('sha256'), 'source_status': snapshot['status'],
              'reviewer': None, 'reviewed_at': None, 'independent_of_author': False, 'scopes': list(SCOPES),
              'findings': [], 'status': 'pending',
              'instructions': 'Independent registered reviewer supplies findings, date and identity; signs exact JSON with ssh-keygen -Y sign -n argus-security-review. No approval is inferred.'}
    path = directory / 'review.json'
    path.write_text(json.dumps(packet, indent=2) + '\n')
    path.chmod(0o600)
    print(json.dumps({'packet': str(path), 'status': 'pending'}))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
