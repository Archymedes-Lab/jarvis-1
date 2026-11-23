# Deploying ARGUS-1 safely on many kinds of computer

Status: target architecture adopted 2026-11-02; **phase 1 built** on branch `feat/host-facts`
(source-tested on fixture hosts, not yet run on a real RHEL, Alpine, container or macOS host).

## Goal and the hard limits

One signed agent that installs and runs safely on Ubuntu, Debian, the RHEL family, Alpine,
containers, VMs, WSL and Windows (macOS later), run by individuals and small teams. It must be
local-first: protection never depends on a server being reachable.

Limits no architecture removes (they decide what "agnostic" can honestly mean):
- **macOS**: kernel-level process and file events need Apple's Endpoint Security entitlement
  (granted to vetted vendors), a signed and notarized system extension, user or MDM approval,
  and Full Disk Access. Until then macOS is reported unsupported, not half-run.
- **Windows**: the deepest telemetry (ETW Threat-Intelligence) is open only to PPL
  anti-malware processes, which needs an ELAM driver signed through Microsoft. Without it the
  agent relies on Sysmon, ETW providers open to administrators, and the event log.
- **Linux**: eBPF sensors with CO-RE need kernel BTF (`/sys/kernel/btf/vmlinux`); older or
  stripped kernels need the auditd path. Containers do not boot their own kernel.

## What exists today (review of 5fe1588, 2026-11-02)

Strengths: clean layering (core and platform import nothing above them); one collector
registry (`core/mechanisms.py`, 72 collectors) and one capability register
(`core/assurance.py`, 54 entries, none promoted without measurement), both test-enforced; an
evidence-safe event log; a CI-only, hash-pinned, signed, reproducibility-minded release;
three runtime dependencies, all hash-pinned, no known advisories (OSV, 2026-11-02).

Gaps for many computers:
1. **Host model too coarse**: three kinds (windows, wsl, linux); macOS fell through to "linux";
   no notion of distribution family, init system, container, package database or BTF.
   Collectors with nothing to observe ran and failed or reported misleading absence.
2. **Product not separated from the developer's machine**: a WSL drop-in naming one Windows
   account shipped inside the signed server release; owner scripts, sudoers and watchdogs sit
   in the tree; the register's evidence text describes one host.
3. **Collectors share threads**: 3 of 72 run in a killable child; one hung read stalls a lane.
4. **No fleet plane**: no enrolment, per-device identity, policy channel, staged content or
   agent updater; one release-signing key.
5. **Evidence continuity bug** (fixed in phase 1): the Linux Sysmon cursor moved before the
   read, so a timed-out read skipped its window for good.

## Designs compared

| Design | For | Against |
|---|---|---|
| **A. Facts first** (adopted): measured host facts + per-collector requirements in the existing agent, then isolation, then a fleet plane | Same binary everywhere; each step testable and reversible; keeps 72 collectors and their evidence semantics | Python footprint; per-OS sensors still ours to maintain |
| B. osquery as the sensor substrate | Mature cross-OS tables incl. macOS Endpoint Security and Windows events | Second agent to ship and update; its table semantics replace ours; heavier footprint |
| C. Rewrite as one static Go/Rust binary | Small, fast | Months of regression risk before any new host is covered |
| D. Central fleet server first | Fleet views early | Builds management for an agent that cannot yet tell what applies on a host |

Jev (jev-1.14.0, advisory, `scripts/reviews/agnostic_architecture_advisory.py`): facts first
0.72 (osquery 0.27, rewrite 0.01, server first 0.00); gating hides real gaps unless
requirements name only the observed thing 0.86; content through the same staged rings as code
0.77; protection fully local when the server is unreachable 0.92.

B stays open as an optional backend: the osquery cross-view (88f1fac, `feat/osquery-crossview`)
can become a sensor source behind the same facts and requirements.

Reconsider A if: a target host family needs more than ~10 collectors reimplemented; idle RSS on
the native build exceeds the budget on a 1 GB VPS; or macOS becomes a priority before the
Endpoint Security entitlement exists (then B's macOS tables are the faster route).

## Target architecture

```
           ┌────────────── optional, outbound only ───────────────┐
           │  Fleet plane: enrolment → per-device key, signed     │
           │  policy and content in rings, fleet views            │
           └───────────────▲───────────────────────────▲──────────┘
                           │ store-and-forward          │ signed metadata (TUF-style)
┌──────────────────────────┴───────────────────────────┴──────────────────────┐
│ Agent (one signed binary per OS/arch)                                        │
│  Supervisor ── health, restart budget, updater (verify → stage → switch →    │
│  │             health gate → keep or roll back)                              │
│  ├─ Host facts (measured once, re-probed on change) ── platform/facts.py     │
│  ├─ Registry: every collector's contract + `requires` ── core/mechanisms.py  │
│  ├─ Applicability: facts × requires → run, or "not applicable: needs X"      │
│  ├─ Scheduler: lanes, leases, deadlines; collectors in killable children     │
│  ├─ Evidence: event log, cursors that move only after a good read, receipts  │
│  └─ Local API + dashboard + alerts (works with no server at all)             │
└──────────────────────────────────────────────────────────────────────────────┘
```

Invariants of the whole design:
- **Same binary, measured behaviour**: what runs is derived from host facts, never from a
  machine name, user name or developer path. The release gate refuses home-folder paths of any
  user, including Windows homes seen through a WSL mount.
- **Not applicable is explicit**: an unmet requirement lists the collector with the missing
  fact; never failing, never healthy, never silently dropped.
- **Requirements name the observed thing, never the sensor**: a missing audit sensor stays a
  reported gap (auditd, sysmon_linux, netflow, heartbeat declare no requirement; tested).
- **Unknown is unmet**: an unreadable fact never satisfies a requirement.
- **Local-first**: protection, alerts and the local API work with no server; the fleet plane
  only adds enrolment, policy, staged content and views.
- **Content is code**: rule packs and policy go through signed metadata, version floors, rings
  and automatic halt, like program updates (the July 2024 Channel File 291 outage shipped
  content outside the staged path).
- **Updates verify before they run**: signed metadata with expiry and a persisted version
  floor (rollback and freeze defence, TUF model); a failed health gate rolls back.
- **Evidence continuity**: a cursor never moves past data it did not read.

## Phases

| Phase | What | Exit evidence |
|---|---|---|
| **1. Facts and applicability** (built) | `platform/facts.py`; `Collector.requires` + `REQUIREMENTS`; `schedule.applicable(facts=)`; macOS reported unsupported and `serve` refuses there; WSL-home release marker; owner drop-in out of the server release; Sysmon cursor fix | Fixture tests per host shape; this host's schedule unchanged; VM matrix on Ubuntu/Debian; first real Rocky and Alpine-container runs |
| 2. Isolation and layout | All collectors with external reads in deadline-bounded children; one `Layout` (state, config, account, port) per install mode (system service, per-user, container); owner files moved out of the product tree | Hung-collector test kills and records; no owner path anywhere in the product tree (gate on the tree, not only the artifact) |
| 3. Signed channels | TUF-style metadata (root/targets/snapshot/timestamp, threshold, expiry, persisted floor) for the binary and for rule packs; supervisor updater with health-gated switch and rollback; second releaser key | Freeze, rollback and mix-and-match attacks refused in tests; a bad update rolls back by itself on a VM |
| 4. Fleet plane (optional) | Enrolment token → per-device key pair (TPM-bound where present); outbound-only mTLS; policy and content rings with automatic halt; fleet views | Agents keep protecting with the server down; a ring halts on a failed health signal |
| 5. More platforms | Container image (read-only rootfs, documented host mounts); RHEL-family OVAL source; macOS only with the Endpoint Security entitlement | Real-host matrix rows per platform in `assurance.py` |

## Phase 1 details

`jarvis/platform/facts.py` reads only files (os-release, `/proc/sys/kernel/osrelease`,
`/proc/1/cgroup`, loader names, package-database paths, engine sockets, BTF) with a 64 KB read
cap; no subprocess, network, write or privilege. Facts on the development host (WSL Ubuntu
24.04): systemd, journald, dpkg, Docker, BTF, glibc; no `/dev/input`, so no requirement uses
input devices (that would have dropped `keyreaders` here).

Declared requirements (each names the observed thing):

| Collector | Requires | Why |
|---|---|---|
| pkgverify, patches | package-db (dpkg or rpm) | `dpkg --verify` / `rpm -V`; apt or dnf |
| opshealth | systemd | failed units, kernel journal |
| bootchain, keyreaders | own-kernel (not a container) | a container has no boot chain or HID of its own |
| containers | container-engine | Docker or Podman installed (stopped still runs: reported unavailable) |
| distrovuln | oval-source (Ubuntu, Debian) | the only OVAL sources implemented |

Measured in real container filesystems (Docker on this WSL host, `--network none`, read-only,
2026-11-02):

| Image | Facts | Not applicable |
|---|---|---|
| python:3.12-slim-bookworm (Debian 12) | debian family, dpkg, glibc, container docker, no init | containers, opshealth, bootchain, keyreaders |
| rockylinux:9 | rhel family, rpm, glibc, container docker | (facts only: see below) |
| python:3.12-alpine (3.24) | alpine family, apk, musl, container docker | the four above + pkgverify, patches, distrovuln |

Finding: Rocky Linux 9 ships Python 3.9 and the source uses 3.10 syntax (`str | None` in
`core/mechanisms.py`), so a source install cannot import the registry there; the signed native
build bundles its own Python and is unaffected. Phase 2 must state the source floor (or keep
the native build as the only supported install on RHEL 9).

Sysmon for Linux: `journal.read_since` returns `(text, ok, why)`; a timeout or failure is a
failed read; the incremental cursor advances only after a good read and a failed pass reports
"Linux Sysmon events not read this pass" and re-reads the window next pass; the syslog
fallback reads at most its last 8 MB (it is a duplicate of the journal; one host's rsyslog copy
reached 9 GB).

Sources: Fleet/Orbit agent and TUF updater (fleetdm.com/docs/configuration/agent-configuration);
Wazuh enrolment (documentation.wazuh.com, authd); Velociraptor comms
(docs.velociraptor.app/docs/deployment); TUF specification (github.com/theupdateframework/specification);
Elastic Fleet enrolment and rollback (elastic.co/docs/reference/fleet); Tetragon FAQ (tetragon.io);
Apple Endpoint Security (developer forums, Elastic and Red Canary write-ups); ETW-TI and PPL
(research write-ups; Microsoft ELAM documentation to confirm); CrowdStrike Channel File 291 RCA
(CISA alert 2024-07-19); SPIRE node attestation (CNCF self-assessment).
