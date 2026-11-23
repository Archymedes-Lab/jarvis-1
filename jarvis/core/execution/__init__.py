"""JARVIS Execution Intelligence: layered observability, escalated depth.

The rule this package enforces: never inspect every instruction of every
process continuously. Watch everything cheaply, detect discrepancies, then
escalate *selected* processes into deeper analysis.

Layers (cheap -> deep, each with an explicit cost ceiling):

  L0  Hardware / PMU counters (aggregate only; never per-instruction)
  L1  Kernel process truth (creation/exit callbacks, ETW, Sysmon)
  L2  Threads / modules / memory snapshot (one read, many consumers)
  L3  Native execution / stacks (bounded sampling of selected pids)
  L4  .NET runtime intelligence (memscan + assemblies + CLR settings)
  L5  Behavioral correlation (temporal detectors over the ordered feed)
  L6  Deep forensic trace (memory dump / instruction trace; human-gated)
  L7  Cross-view covert-process detection (reconciliation verdicts)

L6 never runs automatically: it needs explicit human authorization and a
recovery contract. L3/L4 run only on discrepancy (see escalate.decide) and
yield under governor pressure. Jev output is advisory and cannot change a
verdict or authorize L6.
"""

LAYERS = ("L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7")

CHEAP_LAYERS = ("L0", "L1", "L2", "L5", "L7")
DEEP_LAYERS = ("L3", "L4")
GATED_LAYERS = ("L6",)
