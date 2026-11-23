# Unowned connection classification, 2026-09-24

## Threat and evidence boundary

A socket present in `/proc/net` but absent from visible process fd tables is an
attribution discrepancy, not a compromise verdict. In WSL, another distro or
the utility VM may own a socket that this distro cannot enumerate. A connection
may also close during a scan. JARVIS must retain the evidence and explain these
limits without claiming that an invisible owner is malicious.

The collector uses two fresh socket and fd views. It matches the same inode and
connection fields before reporting a confirmed discrepancy. If the first
socket table is unreadable, the collector fails rather than reporting clean.
If the second table is inconclusive, the initial candidate remains visible as
inconclusive. Permission-denied fd reads are counted and reported even when no
candidate socket remains.

The current socket-table reader cannot distinguish a partially unreadable
protocol table from one that legitimately contains no rows. Full per-protocol
read status is a remaining visibility gap; the classifier must not describe a
missing finding as proof that no unowned socket exists.

## Classification and response

| Observation | Finding | Response boundary |
| --- | --- | --- |
| Peerless loopback or WSL DNS endpoint | Medium; owner outside this distro is plausible | Investigate; no automatic block |
| Local peer connection, broad bound endpoint, or nonlocal peer connection | High; classify the observed scope | Investigate; no automatic block |
| Malformed address | High with scope unknown | Recheck and investigate; no automatic block |
| Incomplete recheck | Keep the scope-based priority and state uncertainty | Recheck; no automatic block |
| Permission-denied fd scan | Low visibility finding alongside any candidate | Improve visibility; no clean attribution claim |

No socket is killed, process suspended, firewall rule added, or connection
blocked based only on this discrepancy. Such an action needs actor identity,
independent evidence, a scoped rollback, and the existing human authority gate.
Severity preserves investigation priority; it does not assert malice.

## Design choice and validation

Three approaches were considered: deterministic scope and coverage rules with
offline Jev review, per-socket runtime Jev classification, and automatic
blocking. The first has bounded local cost, avoids sending raw addresses or
telemetry to a model, and preserves operation when Jev is unavailable. Jev's
metadata-only Choice favored it (0.85 probability, 0.77 confidence); a Noul
supported keeping persistent nonlocal discrepancies high without automatic
blocking (0.88). An implementation review prioritized fd-coverage checks
(Choice 0.84 probability, 0.78 confidence); its high-finding invariant Noul
was 0.92. These are advisory judgments, not validation or authorization.

Executable regression cases cover fresh views, transient and persistent
inodes, inode reuse, failed recheck, fd permission denial, empty initial table,
scope classes, and visibility reporting. The complete Python suite and a fresh
deployed collector run are required before a live capability claim. No live
result or score gain is inferred from the checkout alone.
