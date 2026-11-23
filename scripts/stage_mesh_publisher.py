"""Stage only reviewed publisher dependencies; never switches collector releases."""
import hashlib
import json
import os
from pathlib import Path


def stage(repo, releases):
    repo, releases = Path(repo), Path(releases)
    names = ['jarvis/__init__.py', 'jarvis/core/__init__.py',
             'jarvis/core/event.py', 'jarvis/core/eventlog.py',
             'jarvis/core/filelock.py', 'jarvis/core/inflate.py', 'jarvis/core/pagecache.py',
             'jarvis/platform/__init__.py']
    names += [str(p.relative_to(repo)) for p in sorted(
        (repo / 'jarvis/platform/peerledger').glob('*.py'))]
    contents = {name: (repo / name).read_bytes() for name in names}
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}
    encoded = json.dumps(manifest, sort_keys=True).encode()
    release = releases / hashlib.sha256(encoded).hexdigest()[:24]
    releases.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Exclusive creation preserves every prior release and rejects partial reuse.
    release.mkdir(mode=0o700)
    for name, data in contents.items():
        target = release / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o444)
    launcher = '''import hashlib, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
MANIFEST = %r
for name, expected in MANIFEST.items():
    target = ROOT / name
    if target.is_symlink() or hashlib.sha256(target.read_bytes()).hexdigest() != expected:
        raise SystemExit('publisher release integrity failure')
sys.path.insert(0, str(ROOT))
from jarvis.platform.peerledger.publisher import main
raise SystemExit(main())
''' % manifest
    (release / 'launch.py').write_text(launcher)
    (release / 'launch.py').chmod(0o444)
    (release / 'manifest.json').write_bytes(encoded)
    (release / 'manifest.json').chmod(0o444)
    for directory, _, _ in os.walk(release, topdown=False):
        Path(directory).chmod(0o500)
    return release


if __name__ == '__main__':
    print(stage(Path(__file__).resolve().parents[1],
                Path(__file__).resolve().parents[1] / '.peer-mesh-local/publisher-releases'))
