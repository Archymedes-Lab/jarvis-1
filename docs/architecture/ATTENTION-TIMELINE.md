# Attention timeline foundation

The authoritative canonical event log remains the evidence. This first layer is a
bounded, replayable projection over its committed sequence. It does not capture
screens, infer user intent, call a model, or authorize response.

## Invariants

- Evidence continuity: never replace or delete canonical events. An episode holds
  source sequence bounds and counts; important discrete events remain milestones.
- Freshness and integrity: sequence gaps, out-of-order input, missing sequence or
  malformed timestamps fail closed. No synthetic continuity across a gap.
- Privacy: persist no pixels, window titles, paths, domains, command lines or raw
  source objects in the projection. Application/activity labels must come from a
  separate local, consented observer in a later phase.
- Bounded resources: limit each projection to a fixed number of input events and
  output milestones. Overflow is explicit, never a silent safe summary.
- Authority and recovery: attention is an observation request only. Existing
  protection and response policy do not consume its output; replay from the
  canonical log reconstructs the projection after interruption.

## Design choice

Use a pure reducer over the existing event log. A second writable timeline would
need transactions, independent retention, reconciliation and another tamper
surface. A pure projection costs replay CPU, but bounded windows and cursors can
control that cost. Reconsider materializing summaries after measuring replay
latency and daily event volume, with source sequences and gap accounting intact.

Next phases require a consented foreground/idle sensor, capture denial for
sensitive contexts, local frame difference and vision benchmarking, and a durable
episode cache with replay tests. No visual capture is enabled by this foundation.
