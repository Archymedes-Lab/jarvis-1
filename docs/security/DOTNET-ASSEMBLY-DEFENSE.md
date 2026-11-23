# In-memory .NET assembly defense (2026-09-28)

## Scope and invariants

The read-only memory scanner samples private and pagefile-backed PE images that
have no mapped file. It parses managed metadata without loading the image.
`dotnet` separately checks CLR injection, replacement runtime components, runtime
ETW suppression, and AMSI registration every 30 minutes. Neither job contains or
removes an image.

Preserve evidence continuity, scanner freshness, process and script identity,
privacy, bounded reads and model calls, and recovery. A scan error or unreadable
process cannot mean clean. Recognised JARVIS assemblies remain inventoried. Jev
receives coarse metadata only, never names, paths, command lines, or raw image
bytes, and cannot change severity or authorize action. The existing release and
installed broker remain rollback paths until a measured cutover.

## Design choice

| Design | Cost and limit |
| --- | --- |
| Sample memory and parse PE metadata (chosen) | Reuses the existing read-only scanner and reports copied images, including .NET assemblies. Sampling misses short-lived images and erased headers. |
| CLR ETW assembly-load stream | Better timing, but needs a new durable collector, loss accounting and elevated live validation. Reconsider when sampling gaps are measured. |
| Treat PowerShell Add-Type images as harmless | Lower cost, but silently excuses attacker assemblies in a common host. Rejected. |

Recognition requires the host to run a byte-for-byte reviewed JARVIS script, all
metadata identifiers to come from that script or compiler constructs, and the
number of images to stay within that script's Add-Type count. A native copied
DLL is high. An unrecognised managed image is medium by default and high outside
PowerShell or with sensitive APIs or offensive tool names. Recognition and severity
are deterministic; the bounded Jev note is advisory.

The scan caps image size and reads without write access. The advisory path makes
at most three calls per scan with a ten-second timeout and caches valid results.
The separate configuration probe is read-only. It reports harmless developer
variable names in an ok summary without exposing their values.

## Evidence and remaining gates

On 2026-09-28, an unelevated live scan found three in-memory assemblies; each
matched a JARVIS script. The real resident `inputhook.ps1` and `hidden.ps1`
collectors were recognised. Isolated test processes produced high findings for
an assembly naming injection APIs and a copied native DLL, and medium findings
for benign, imitation and partial-copy cases. The `dotnet` probe completed in
about 1.3 seconds on the live machine and reported the measured baseline clean.
These are observations, not proof of continuous or elevated coverage.

The interrupted soak log contains four samples spaced five minutes apart. They
showed only recognised JARVIS assemblies and scanner-self images, with 176-180
processes opened per sample and scan times of 4.2-10.3 seconds. It does not
establish a one-hour soak. Elevated service processes remain unmeasured. A loader
that erases or never writes a PE header is invisible; PowerShell and other JIT
processes still excuse their private executable memory; a short-lived image may
fall between scans. Machine.config and per-executable AppDomainManager settings
are follow-up configuration checks.

Before release, run the full suite and lint, stage the reviewed rename and .NET
files together on the live sealed base, then run the full suite in that stage.
Before cutover, record fresh per-job findings and scores. After cutover, verify
the release identity, service health, fresh `memscan` and `dotnet` receipts,
finding-by-finding changes, broker copy, and repeat readings across intervals.
Roll back on errors, stale evidence or unexplained disappearing findings.
