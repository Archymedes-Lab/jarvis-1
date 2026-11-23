"""Instrument the real Rust privacy module; execute only in a restricted container."""
import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.security.campaign import Step, execute  # noqa: E402

NIGHTLY = 'nightly-2026-10-25'
IMAGE = 'sha256:d9b8c34d61a9b9a3c44cab883d7d2f2619d674966ab520186f799cf32e3e0377'
MODULE = ROOT / 'desktop/src/screenguard.rs'
NEGATIVE = {
    'address': '''fn main() { unsafe {
        let layout = std::alloc::Layout::from_size_align(16, 8).unwrap();
        let p = std::alloc::alloc(layout); std::alloc::dealloc(p, layout);
        std::ptr::write_volatile(p, 7);
    } }''',
    'thread': '''static mut DATA: u64 = 0;
    fn main() { let b = std::sync::Arc::new(std::sync::Barrier::new(2));
      let c = b.clone(); let t = std::thread::spawn(move || { c.wait();
        for _ in 0..10000 { unsafe { std::ptr::write_volatile(&raw mut DATA, 1); } } });
      b.wait(); for _ in 0..10000 { unsafe { std::ptr::write_volatile(&raw mut DATA, 2); } }
      t.join().unwrap(); }''',
}


def container(work, name, binary, *args):
    return ('docker', 'run', '--rm', '--name', name, '--network', 'none', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--read-only', '--memory', '1g', '--cpus', '1.5',
            '--cpu-shares', '128', '--pids-limit', '128', '--user', f'{os.getuid()}:{os.getgid()}',
            '--tmpfs', '/tmp:rw,size=128m', '-v', f'{work}:/work:ro', IMAGE,
            '/work/' + binary, *args)


def run(rustup_home):
    if not shutil.which('docker') or not (rustup_home / 'toolchains' / (NIGHTLY + '-x86_64-unknown-linux-gnu')).is_dir():
        return {'status': 'unavailable'}, 2
    source = MODULE.read_bytes()
    report = {'source_sha256': hashlib.sha256(source).hexdigest(), 'module': 'desktop/src/screenguard.rs',
              'scope': 'Linux privacy module and Rust std; system libraries and Windows code uninstrumented',
              'toolchain': NIGHTLY, 'container_image': IMAGE, 'results': []}
    with tempfile.TemporaryDirectory(prefix='argus-native-') as scratch:
        work, home = Path(scratch), Path(scratch) / 'home'
        (work / 'production.rs').write_bytes(source)
        (work / 'negative.rs').write_text(NEGATIVE['address'])
        (work / 'Cargo.toml').write_text('[package]\nname="argus-sanitizer-fixture"\nversion="0.0.0"\nedition="2021"\n[lib]\npath="production.rs"\n[[bin]]\nname="negative"\npath="negative.rs"\n')
        compiler = rustup_home / 'toolchains' / (NIGHTLY + '-x86_64-unknown-linux-gnu') / 'bin/rustc'
        cargo = compiler.with_name('cargo')
        env = {'RUSTUP_HOME': str(rustup_home), 'RUSTUP_AUTO_INSTALL': '0', 'CARGO_HOME': str(work / 'cargo'), 'CARGO_BUILD_JOBS': '2', 'RUSTC': str(compiler)}
        locked = execute(Step('native-lock', 'sanitizers', (str(cargo), 'generate-lockfile', '--offline'), str(work)), home, environment=env)
        if locked['status'] != 'passed':
            return {**report, 'status': 'incomplete', 'lock': locked}, 2
        for sanitizer in ('address', 'thread'):
            for negative in (False, True):
                stem = sanitizer + ('-negative' if negative else '-production')
                if negative:
                    (work / 'negative.rs').write_text(NEGATIVE[sanitizer])
                env.update(RUSTFLAGS='-Zsanitizer=' + sanitizer, CARGO_TARGET_DIR=str(work / ('target-' + sanitizer)))
                argv = (str(cargo), 'build' if negative else 'test', '-Zbuild-std', '--locked',
                        '--target', 'x86_64-unknown-linux-gnu', '--message-format=json')
                argv += ('--bin', 'negative') if negative else ('--lib', '--no-run')
                build_output = bytearray()
                compiled = execute(Step(stem + '-compile', 'sanitizers', argv, str(work)), home,
                                   timeout=600, environment=env, output_consumer=build_output.extend)
                if compiled['status'] != 'passed':
                    report['results'].append({'sanitizer': sanitizer, 'status': 'incomplete', 'compile': compiled})
                    continue
                if negative:
                    executable = work / ('target-' + sanitizer) / 'x86_64-unknown-linux-gnu/debug/negative'
                else:
                    executables = []
                    for line in build_output.splitlines():
                        try:
                            message = json.loads(line)
                        except ValueError:
                            continue
                        if message.get('reason') == 'compiler-artifact' and message.get('profile', {}).get('test') and message.get('executable'):
                            executables.append(Path(message['executable']))
                    if len(executables) != 1 or not executables[0].is_relative_to(work):
                        report['results'].append({'sanitizer': sanitizer, 'status': 'incomplete'})
                        continue
                    executable = executables[0]
                shutil.copyfile(executable, work / stem)
                (work / stem).chmod(0o700)
                output = bytearray()
                name = 'argus-native-' + os.urandom(6).hex()
                try:
                    executed = execute(Step(stem, 'sanitizers', container(work, name, stem,
                                       *(() if negative else ('--test-threads=1',)))),
                                       home, timeout=60, output_consumer=output.extend)
                finally:
                    execute(Step('native-cleanup', 'sanitizers', ('docker', 'rm', '-f', name)), home, timeout=20)
                text = bytes(output)
                if negative:
                    marker = (b'AddressSanitizer: heap-use-after-free' if sanitizer == 'address'
                              else b'ThreadSanitizer: data race')
                    passed = executed['status'] == 'failed' and marker in text
                    tests = None
                else:
                    match = re.search(rb'test result: ok\. (\d+) passed; 0 failed;', text)
                    tests = int(match.group(1)) if match else 0
                    passed = executed['status'] == 'passed' and tests > 0
                report['results'].append({'sanitizer': sanitizer, 'negative_control': negative,
                                          'passed': passed, 'test_count': tests, 'execution': executed})
    complete = len(report['results']) == 4 and all(row.get('passed') for row in report['results'])
    report['status'] = 'passed' if complete else 'incomplete'
    return report, 0 if complete else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustup-home', type=Path, required=True)
    args = parser.parse_args()
    try:
        report, code = run(args.rustup_home)
    except (OSError, ValueError):
        report, code = {'status': 'incomplete'}, 2
    print(json.dumps(report))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
