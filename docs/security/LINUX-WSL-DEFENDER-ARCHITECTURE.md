# Linux and WSL defender architecture — 2026-09-29

Status: proposed extension to the [continuous monitoring beta contract](SECURITY-HEALTH-RELEASE-RFC-2026-09-29.md).
This is a target, not evidence of installed protection. The governing
[Maximum Assurance directive](MAXIMUM-ASSURANCE.md) applies. A quiet feed,
successful collector run, control score or absent alert is never proof that
Linux or WSL is safe. Implementations must update `jarvis/core/assurance.py`
only when measured evidence changes a claim.

## Goal and domain model

Maintain a continuously reconciled, privacy-preserving model of Linux
execution, persistence, privilege, files, network, credentials, kernel state,
containers and the Windows/WSL boundary. A coherent contradiction should
start a bounded investigation with its supporting and missing evidence.
Windows, each WSL distribution, and native Linux are separate trust domains.
Crossing through DrvFs, Windows executable interop, `wsl.exe`, shared
networking or host-managed storage is an explicit edge with two-sided identity
where available. Neither side may fill a missing edge by inference alone.

```text
Windows sources ─┐
                 ├─ canonical temporal events ─ identity/epoch reconciliation
Linux sources ───┘                              ├─ activity and behavior
Windows/WSL boundary receipts ──────────────────├─ investigations
                                                └─ visibility and gaps
```

This architecture cannot guarantee detection after a kernel, hypervisor or
host compromise. Windows host administrator control over WSL storage and
configuration is a fundamental trust limit. A remote integrity anchor could
improve tamper evidence only after independent key protection, freshness,
availability and recovery have been demonstrated; a local hash chain is not
such an anchor.

## Invariants and design choice

1. **Evidence continuity:** each source has source identity, boot/epoch,
   monotonic sequence/cursor, read and event times where available, loss,
   restart and policy-change receipts. Dropped events stay visible; a later
   `/proc` match never repairs a historical gap.
2. **Fresh identity:** process keys include host/domain, distribution or
   container, boot, PID namespace, PID and start identity. Joins require a
   coherent window and corroborating IDs; PID reuse, WSL restart and clock
   steps cannot create false parentage.
3. **Privacy and authority:** collect bounded metadata, selected digests and
   protected local evidence references. Do not retain secret values, full
   command lines, private file contents or broad `/proc/*/environ` dumps.
   Advisers cannot authorize containment; profile changes and enforcement
   require a separate, scoped, reversible owner decision.
4. **Bounded resources and recovery:** hot-path buffers have measured limits,
   drop counters and backpressure. Deep inspection has a trigger, time and
   capacity limit. Sensor restart, source failure and retry exhaustion become
   visible gaps; rollback preserves earlier evidence and known-good state.
5. **Honest claims:** `current`, `limited`, `unavailable`, `unsupported`,
   `restricted` and `not_applicable` are distinct per source and path. A
   source's ability to attach, an installed binary and a fresh heartbeat do
   not establish event capture or containment.

| Candidate | Benefit | Decision |
| --- | --- | --- |
| Extend periodic `/proc` and configuration scans only | Smallest dependency and lowest idle cost | Retain as reconciliation and fallback; it misses short-lived transitions. |
| Depend on one eBPF stream | Fast event history with useful kernel context | Insufficient alone: kernel capabilities differ, events can drop, and a compromised observer can lie. |
| Capability-probed event sensor plus independent snapshots and boundary receipts | Detects short-lived activity and exposes disagreement | Target. Start with one measured lifecycle stream, then expand only where positive controls, loss and cost justify it. |

The proposed hot path is a small memory-safe Rust sensor using eBPF where
supported. This is a design choice, not a mandate to install BPF on every
machine. Probe tracepoints, kprobes, BTF, BPF LSM, perf, fanotify and audit
independently at runtime; report effective attachment and loss. Use supported
fallbacks only for the specific transitions they can observe. Reconsider
the source mix if attachment, kernel compatibility, event loss, CPU or
operator cost exceed a measured budget. Python can perform policy,
interpretation and projection; Rust can handle bounded acquisition. Keep
the repository's existing layer rules rather than creating an unregistered
top-level Python package.

## Linux observation planes

### Process Truth is the foundation

The first Linux subsystem is `LinuxProcessTruth`: a live graph of every
*observable* task, with process and thread instance keys, parentage, PID and
other namespace IDs, cgroups/systemd ownership, executable identity,
privilege state, mappings, files and sockets as their source paths become
measured. Kernel threads are a separate entity type. A process can be
represented even when its executable, owner or namespace is restricted;
unknown fields remain unknown. Container processes share this graph and
retain container/image identity only when an actual source supplies it.

Four desired, separately qualified views are lifecycle tracepoints/eBPF,
`/proc` and task snapshots, scheduler activity, and socket/cgroup/namespace
ownership. The first source-tested slice provides only a bounded `/proc`
snapshot and a pure reconciliation contract. `/proc` enumeration, direct
getdents and `/proc` stat are related views, not independent kernel proof.
No lifecycle completeness claim is possible until a running event source
has a verified boot, start coverage, sequence, loss count and effective
attachment receipt. The process key must include boot, PID namespace, PID
and start ticks; pidfds can protect targeted follow-up inspection where
available. A PID alone never identifies an execution instance.

Depth is governed per process: level 0 records existence, lifecycle and
identity for all tasks an attached source can observe; level 1 adds bounded
threads, privilege, cgroup, socket and file metadata; level 2 is targeted
mapping and process-access watch; level 3 is short, human-gated forensic
capture. Escalation is deterministic, identity-scoped, time/capacity bounded
and records drops. Pre-event buffers may be retained only under an explicit
privacy and disk budget. The goal is exhaustive observable lifecycle history,
not exhaustive forensic tracing of every task.

Process observability objectives are measured separately: lifecycle capture
against isolated positive controls, long-lived snapshot reconciliation,
PID-reuse errors, unexplained active tasks, event gaps, silent downtime,
and unknown namespaces. A result such as `10,000 created / 10,000 observed`
is valid only for the named Forge workload, host, source policy and window;
it is not universal 100% coverage. Missing-but-reconciled and
missing-without-any-indication are different outcomes. Any unexplained active
task or lost lifecycle stream blocks a *Process Truth readiness claim*, while
the activity view continues to show the evidence and limits.

| Plane | Initial observation and reconciliation | Important limitation |
| --- | --- | --- |
| Process and execution | Fork/clone, exec, exit, thread and credential/namespace changes; compare with `/proc`, cgroups, scheduler and socket ownership. Normalize to canonical `PROCESS_EXECUTION` and related events. | `/proc` is a snapshot; one source cannot prove complete lifecycle history. |
| Executable memory and process access | Selected `memfd`, anonymous executable mappings, RW→RX/RWX changes, thread entry, `ptrace` and `process_vm_*` relationships. Correlate with JIT identity, files, modules and network. | JIT and debuggers are legitimate; map transitions do not alone establish injection. |
| Persistence | Inventory systemd effective units, drop-ins, generators and timers; cron/at; shell profiles; SSH authorization; loader paths and `LD_PRELOAD`; sudoers/PAM; user/group changes; XDG autostart; container restart settings. Diff semantic configuration as well as file hashes. | Files outside declared paths and ephemeral changes remain gaps until a matching source is measured. |
| Privilege and kernel | Root transitions, sudo/su, capabilities (effective, ambient and file), setuid, mounts, namespace changes, module and BPF loads, sysctls, LSM/lockdown/boot state. Inventory JARVIS's own BPF objects. | UID 0 and a capability are risk context, not a compromise verdict. WSL host controls some kernel state. |
| Network and files | Attribute listeners and connections to process instance, namespace and cgroup; watch priority executable/configuration paths with event sources and incremental hash reconciliation. Record bind-address and reachability changes. | Listener bind address alone cannot prove LAN reachability; multiple firewall layers matter. |
| Credentials and packages | Track access metadata for SSH/GPG/cloud/browser and developer credential locations, agent sockets, package repositories, package transactions and install hooks. | Do not read or upload secret values; package signatures and update policy vary by distribution. |
| Containers | Separate host and container identity using PID/mount/network namespaces, cgroup, container/image ID when attributable; watch daemon sockets, privileged launches, host mounts, capabilities and restart policies. | Docker socket access can confer root-level control; container discovery alone cannot validate isolation. |

Every event should carry source, process instance, actor and target when
known, namespace/cgroup context, event/read time, cursor/sequence, integrity
reference and confidence. Executable paths, argv and working directories are
privacy-sensitive: use locally protected exact values only when justified;
routine views and remote advisory state use selected fields or digests. A
failed source or unresolved identity remains explicit. Do not label a
cross-view mismatch `rootkit` without independent investigation.

Prioritize continuous integrity for `/etc`, systemd, sudoers/PAM, SSH,
loader configuration, executable/package locations and JARVIS itself;
event-driven checks for declared home credentials and developer configuration;
incremental scans for large trees. Inode, device, size and timestamps can
avoid redundant hashing, but neither timestamps nor hashes alone identify a
writer. Use fanotify only where probe results and measured overhead support
it. `hidepid`, LSM/AppArmor and seccomp are native Linux posture or
confinement candidates; changing them requires compatibility tests and an
authorized, reversible policy change. Ubuntu documents that AppArmor is
installed but not enabled by default in Ubuntu on WSL, so WSL confinement
must be reported by effective state, not inferred from installation.

## WSL boundary planes

| Boundary | Evidence and desired interpretation |
| --- | --- |
| Linux → Windows files | Identify DrvFs mounts and Linux writes to Windows-backed paths; correlate with Windows file evidence and mark sensitive targets. No write attribution when only mount or file snapshots exist. |
| Linux → Windows execution | Observe WSL interop launch and match the Linux process instance to a Windows process using independently observed IDs/times and an authenticated correlation receipt where possible. Emit `WSL_WINDOWS_EXEC` only when the edge is supported. |
| Windows → Linux execution | Observe Windows `wsl.exe` ancestry, distribution selection and Linux child execution. Emit `WINDOWS_WSL_EXEC` only after matching both sides; otherwise show two events with a missing edge. |
| Configuration and offline state | Baseline `%USERPROFILE%\.wslconfig`, `/etc/wsl.conf`, kernel identity, boot arguments, automount/interop, firewall, networking, DNS/proxy, disk and debugging settings. Compare critical files after each WSL start against prior protected checkpoint, and name the unobserved offline interval. |
| Network policy | Reconcile Linux listeners/firewall, Windows Firewall and Hyper-V firewall with effective NAT/mirrored mode and port forwarding. Show WSL-local, Windows-localhost and LAN reachability as measured or unknown, never extrapolated from a listening port. |
| Sensor continuity | Watch Linux sensor binary/unit/configuration, attachments, spool, event rate and receipt advance. Silence with independently observed activity is a contradiction, subject to false-positive and source-continuity checks. |

WSL configuration and policy are version-dependent. Probe the actual kernel,
LSM list, BPF features, WSL version, configuration and effective Windows
policy. Do not assume BPF LSM, AppArmor, Hyper-V firewall or localhost/LAN
exposure solely from a feature name or default. A custom or unknown kernel
or command line makes kernel-source assurances `limited` or `unavailable`
until their provenance and sensor behavior are verified. A failed provenance
gate blocks a claim that depends on trusted kernel events; it does not prove
compromise or authorize a disruptive response.

WSL modes are **proposed policy profiles**, never automatic changes:

| Mode | Intended posture | Adoption gate |
| --- | --- | --- |
| Compatible | DrvFs and interop available, with explicit boundary monitoring. | Measure all claimed boundary paths. |
| Hardened | Limit mounts/exposure and Windows PATH; retain only needed interop. | Verify developer workflows and rollback. |
| Maximum isolation | Explicit or disabled Windows mounts, interop and Windows PATH; constrained inbound access and risky WSL features. | First replace JARVIS's own PowerShell/DrvFs dependencies with a narrow authenticated Windows broker; obtain owner authorization and test recovery. |

`[interop] enabled=false` and `appendWindowsPath=false` are documented WSL
controls. They must not be applied while JARVIS's installed WSL collectors
still depend on unrestricted Windows interop. A broker request must bind
actor, target, operation, expiry and evidence to an authenticated identity;
it is a future design, not an existing containment boundary. Network policy,
automount changes, kernel settings, Windows policy and Hyper-V firewall
changes likewise need explicit authorization and live readback.

## Contradictions, assurance and rollout

Examples to investigate: a `/proc` process or active scheduler task missing
from a continuous lifecycle stream; a socket without a coherent owner;
an executable-memory sequence with an unexpected thread; an effective
systemd command changing without an accounted file or package event; an
unrecognized BPF object; or a DrvFs write seen by only one side. First check
source loss, epoch mismatch, PID reuse, namespace translation and legitimate
JIT/developer activity. Escalate to a bounded deeper capture only after those
checks. Preserve the factual disagreement even when the cause is unresolved.

Publish a Linux/WSL coverage matrix by execution, memory, persistence,
privilege, credentials, filesystem, network, packages, kernel, containers and
each boundary edge. Each row says `covered`, `partial`, `unsupported by
environment` or `not yet implemented`, with exact source, effective-policy
receipt, last positive and benign control, event loss and blind spot.
Technique mappings (including Linux ATT&CK) can organize this matrix but
cannot confer coverage. Named control checks may show pass/fail/unknown; no
overall Linux security percentage is introduced by this proposal. A source
outage or unknown custom kernel must block dependent readiness claims without
turning unrelated controls into failures.

Implementation sequence:

1. Freeze domain/identity/event and capability-probe contracts; record live
   baseline, gaps, idle cost and known WSL interop dependencies.
2. Add one Linux exec/exit source and `/proc` reconciliation end to end, with
   loss accounting, PID-reuse, short-lived process, interruption and retry
   exhaustion tests. Prove fresh service receipts and exact release readback.
3. Add persistence, privilege/capability, network and priority-file planes
   one at a time. Add thread/memory and container planes only after kernel
   capability and workload cost tests.
4. Add DrvFs and both interop directions, then configuration/network-policy
   reconciliation. Cross-domain joins need matched positive, negative and
   missing-side tests. Introduce a broker before considering isolation.
5. Add anti-tamper and startup/offline checks with an independently protected
   anchor if available. Test WSL restart, host reboot, sleep, sensor stop,
   event suppression, rollback and retention limits.

Forge Linux/WSL controls belong in isolated VMs or disposable distributions,
never the protected user's data. Include benign developer and JIT lookalikes
beside systemd/cron/SSH/loader drift, capability/setuid changes, `memfd` and
process-access sequences, Docker socket/privileged container use, new
listeners, DrvFs writes, both interop directions, firewall/config changes,
sensor interruption and offline drift. Every scenario specifies expected
telemetry, gap behavior, latency, false-positive check and safe recovery.
Passing a pure model test is not live sensor validation. Promotion requires
focused regressions, the full suite, measured CPU/RAM/disk and loss budgets,
exact sealed-stage tests, real-service receipts and post-cutover readback.

## Source notes

The design is informed by current vendor documentation, subject to per-host
verification: [WSL configuration and interop](https://learn.microsoft.com/en-us/windows/wsl/wsl-config),
[WSL networking and Hyper-V firewall](https://learn.microsoft.com/en-us/windows/wsl/networking),
[WSL enterprise controls](https://learn.microsoft.com/en-us/windows/wsl/intune),
[Ubuntu on WSL security](https://ubuntu.com/wsl/docs/latest/explanation/security-overview/),
and [Docker daemon privilege](https://docs.docker.com/engine/install/linux-postinstall/).

## Source implementation note — 2026-09-29

`jarvis timeline linux-truth --json` now exposes a bounded local `/proc`
inventory with boot/PID-namespace/PID/start-tick identity, task threads,
namespace links, cgroups, capabilities, parent links and bounded open
descriptor identities. `--deep-pid PID` samples executable mappings after
checking the exact process start identity. It returns no command lines,
environment values, full descriptor paths or memory contents. The pure
reconciler requires a same-boot continuous lifecycle receipt with zero loss
before it can call a missing creation a contradiction; this receipt is not
connected yet. The CLI always labels its snapshot `partial`.

The permitted host-path readback represented 128 process instances, 699
threads and 1,541 descriptors in 0.207 seconds, with zero scan errors and no
budget exhaustion. Some namespace/thread and descriptor details remained
incomplete. Those counts describe one live sample, not all host tasks over
time. Sysmon for Linux was installed and running on the host and supplied
process create/exit records during a bounded journal probe; no durable Linux
cursor, event-to-instance join, source loss proof or Forge capture rate was
established. The code has not been staged or installed in the sealed service.

## Source implementation note — 2026-09-30: WSL boundary and offline drift

`jarvis timeline wsl-boundary [--json] [--accept] [--checkpoint FILE]
[--wslconfig PATH]` reads allowlisted `/etc/wsl.conf` and `.wslconfig` keys,
DrvFs (9p `aname=drvfs`) mounts, `WSLInterop` registration, the count of
`/mnt/` entries in `PATH` and Docker socket presence. Nothing else in those
files is retained. Each source reports `current`, `absent` (defaults apply) or
`unavailable`.

Invariants: comparison never writes; `--accept` is the only way to append a
checkpoint, so drift cannot be absorbed into a new baseline silently. Entries
are hash chained; a broken chain or unreadable file is `checkpoint_invalid`
and blocks `--accept`. A boot-id change makes differences `OFFLINE_STATE_DRIFT`,
same-boot differences `STATE_DRIFT`. A fact that vanished because its source
became unreadable is `EVIDENCE_LOST`, never "removed" or "clean". Changes to
the custom kernel, kernel command line, networking mode, interop, automount,
`boot.command`, DrvFs mounts, Windows PATH entries and Docker socket are marked
critical. Tests: `tests/test_wsl_boundary.py`.

Not done: no scheduled comparison or alert wiring, no accepted live baseline
(that is an owner decision), no independent anchor for the chain, and no
Windows-to-Linux or Linux-to-Windows process edges. The local chain proves
internal consistency only.
