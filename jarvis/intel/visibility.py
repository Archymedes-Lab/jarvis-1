"""Hidden Activity Detector: invariants over one bounded window.

Evaluates jarvis.core.execution.invariants.check over already-collected,
metadata-only state and returns VisibilityViolation records (never
"malware"). Observation stays sensitive; interpretation stays
disciplined: each violation cites keys/seqs for replay. Pure.
"""

from jarvis.core.execution import invariants as inv


def detect(*, threads=(), connections=(), modules=(), creations=(),
           snapshots=(), post_exit_samples=(), known_processes=frozenset(),
           start_keys=frozenset(), approved_modules=frozenset(),
           jit_keys=frozenset(), load_keys=frozenset(),
           coverage_valid=True, limit=50):
    violations = inv.check(
        threads=threads, connections=connections, modules=modules,
        creations=creations, snapshots=snapshots,
        post_exit_samples=post_exit_samples,
        known_processes=known_processes, start_keys=start_keys,
        approved_modules=approved_modules, jit_keys=jit_keys,
        load_keys=load_keys, coverage_valid=coverage_valid, limit=limit)
    return [{"category": "visibility", "host": "win", **v}
            for v in violations]
