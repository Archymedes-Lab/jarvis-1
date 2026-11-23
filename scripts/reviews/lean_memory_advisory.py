"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'reduce the resident memory of a long-lived Python security daemon (thread per scheduler lane '
            'and per API request, SQLite store of about 1 GB) without losing evidence or protection',
    'measured': {
        'live_daemon': '617-835 MB resident, 595 MB anonymous; service cgroup 2.07 GB with 1.44 GB page cache',
        'job_peaks_today': 'hunt 305 MB, sysmon_linux 360 MB, state build 406 MB; Python objects only 19-53 MB',
        'cause': 'per-connection SQLite 64 MiB private cache plus 256 MiB memory map, glibc arenas keeping '
                 'freed pages; an isolated child re-opens a large event log cold every minute (2.4 s, 149 MB)',
        'phase1_result': 'daemon-shaped workload peak 814-891 MB -> 111-149 MB, anonymous at end 169-231 MB -> '
                         '37-49 MB, CPU about 10 percent higher',
    },
    'options': {
        'storage_allocator': '4 MiB cache, no mmap, glibc arena cap 2, malloc_trim after each job and request',
        'per_run_isolation': 'run every heavy job in a fresh child process',
        'persistent_workers': 'long-lived isolated workers with warm state, deadline kill and memory-ceiling recycle',
        'cgroup_ceilings': 'lower MemoryHigh after live readback',
        'rewrite': 'rewrite the daemon in Rust',
    },
}
QUESTIONS = {
    'best_first': {'type': 'choice', 'instructions':
        'Given the measurements, which option should be built first to reduce resident memory?',
        'criteria': {'storage_allocator': 'Right-size SQLite and the allocator',
                     'per_run_isolation': 'Isolate every heavy job per run',
                     'persistent_workers': 'Persistent bounded isolated workers',
                     'cgroup_ceilings': 'Lower the cgroup ceilings',
                     'rewrite': 'Rewrite in Rust'}},
    'cpu_tradeoff_ok': {'type': 'noul', 'instructions':
        'Is about 10 percent more CPU in the measured workload an acceptable price for cutting peak resident '
        'memory by about 85 percent on an 8 GB workstation that also runs other software?',
        'criteria': {'true': 'Acceptable', 'false': 'Not acceptable'}},
    'hidden_risk': {'type': 'choice', 'instructions':
        'Which risk of the storage and allocator change most deserves a live check after deployment?',
        'criteria': {'latency': 'Dashboard or API latency regresses under real load',
                     'lock_contention': 'More SQLite busy or locked errors',
                     'trim_cost': 'malloc_trim pauses the process noticeably',
                     'no_effect_live': 'The live daemon does not shrink as the harness did',
                     'none': 'No material risk'}},
    'next_phase': {'type': 'choice', 'instructions': 'After the first phase is live, which phase adds most?',
        'criteria': {'persistent_workers': 'Persistent bounded workers for the isolated collectors',
                     'cgroup_ceilings': 'Lower the cgroup ceilings',
                     'page_cache_hints': 'Drop page cache after large sequential reads',
                     'none': 'Stop after the first phase'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
