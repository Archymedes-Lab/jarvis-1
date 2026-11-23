"""Replay: score an existing recorded event-log window again.

Produces nothing. The scenario's `spec.window` gives an inclusive sequence
range `[first, last]` (or `since`/`until` times) in the live event log, which
the runner reads. This is how a real incident, once recorded, becomes a
permanent regression test that every future JARVIS build must still handle.
"""


def produce(scenario, log):
    # Nothing to generate; the runner reads the existing window named in spec.
    return None
