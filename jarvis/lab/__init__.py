"""JARVIS Arena: continuous adversarial validation of the Defender.

The question is not "does JARVIS detect malware" but whether the whole chain
holds — observed, understood, correlated, classified, intervened, contained,
removed, restored, verified — measured per property, not pass/fail. Every
scenario becomes a permanent regression test, so a defence, once earned, is
hard to lose.

Safety is structural, not advisory (`isolation.py`):

  - The default and only tier runnable on a normal machine is synthetic
    telemetry replay: scenarios that feed recorded or generated events through
    the real ingestion, normalization, event log and detectors. Nothing is
    executed on the OS.
  - Anything that runs a real primitive on the host (`live`) is refused unless
    the process is inside an approved, marked sandbox, and detonation of actual
    malware is refused in automation entirely.

This layer reads the engine (core, collectors, response) and drives it. Nothing
below it imports it.
"""
