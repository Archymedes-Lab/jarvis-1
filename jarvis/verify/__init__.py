"""Verification ladder, in-tree and standard-library only.

    props   randomised property checks over the pure engines (seeded, replayable)
    mc      exhaustive explicit-state model checking of small protocols
    models  the protocols JARVIS depends on, driven through the real code where
            the code is pure (seal findings, release expect-base), abstract where
            it is not (scheduler lanes)

Each level answers a different question. A property check says "no random case
in this space broke the invariant"; a model check says "no reachable state of
this protocol breaks it"; neither says anything about states or inputs the
model leaves out, and docs/architecture/VERIFICATION-LADDER.md names those.
"""
