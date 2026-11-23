"""Scenario providers: how a scenario's telemetry comes to exist.

  synthetic  generate events straight into a throwaway event log (no OS action)
  replay     score an existing recorded event-log window again
  tamper     self-defense: corrupt the run's own sealed history, expect detection
  atomic     import Atomic Red Team tests as scenario specifications (never run)
  caldera    import MITRE CALDERA abilities as specifications (never run)

`get(name)` returns the provider module; each exposes `produce(scenario, log)`
for the executing providers, returning the (first_seq, last_seq) window it
wrote, or None when it only points at existing history.
"""

import importlib


def get(name):
    if name not in ("synthetic", "replay", "atomic", "tamper", "caldera"):
        raise ValueError(f"unknown provider {name!r}")
    return importlib.import_module(f"jarvis.lab.providers.{name}")
