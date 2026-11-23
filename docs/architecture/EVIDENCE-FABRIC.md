# JARVIS Evidence Fabric

## Network identity and roam invariant (2026-09-25)

`known_aps` is a sighting ledger, not a trust store. Repeated observation of an
SSID/BSSID pair cannot establish AP ownership: a radio can replay those labels.
The collector retains every sample and transition, including repeated sightings.
An exact pair of recent, same-interface, same-SSID samples with different BSSIDs,
strong unchanged authentication/cipher, and unchanged nonempty gateway IP, gateway
MAC and DNS supports a *coherent but unverified roam*: medium. It does not prove
the new AP belongs to the venue. Missing evidence, weak/unknown authentication,
stale pairing, or divergent network topology leaves the AP finding high. Separate
crypto-downgrade, gateway and DNS findings retain their own severity. An exact
historical pair may contextualize a stored high for scoring without changing the
raw event; missing paired samples fail closed. The change affects no network
settings and is reversible by a sealed release rollback.

One missing gateway MAC may be filled for *audit interpretation only* from at
most 12 same-interface, same-SSID, same-BSSID, same-auth/cipher/gateway/DNS
samples within 10 minutes of the missing reading. Every nonempty candidate
must agree with the other side of the transition. A conflicting, absent or
overfull set leaves high. This is bounded confirmation of an ARP measurement,
not an AP identity claim; the raw high event and all samples stay intact. Jev
favored this bounded medium outcome (Choice confidence 0.98). The historical
replay and failure-path tests are the independent gates.

Norrsken House Kigali's [official page](https://www.norrsken.org/houses/kigali)
confirms a large coworking campus, but
publishes no AP inventory. The observed Norrsken Members transition retained
WPA3-Personal H2E/CCMP, gateway address and MAC, and DNS across adjacent samples.
The venue page and these observations do not authenticate the BSSID. Alternatives
were high for every new BSSID, automatic low from a repeated BSSID, and a medium
only for coherent recent context (selected). Jev Choice favored the last with
confidence 0.93 and gave 0.05 yes probability that the exact AP's ownership was
established. This is advisory; regression tests and fresh service readback decide
whether the implementation preserves the invariant. Reconsider if the venue
provides an independently verifiable AP or EAP server identity.

Adopted 2026-09-24 from the owner's architecture brief ("explainable by construction").
Two implementers build it in parallel. The file split is in
[FABRIC-COORDINATION.md](FABRIC-COORDINATION.md). This document records the
invariants, the designs chosen and why, and what is actually built and measured.

The governing principle: **JARVIS never becomes less sensitive in order to become
quieter. It becomes better informed.** No change here edits the scoring formula,
downgrades a finding because of a name or path, or turns an attribution into
permission.

```text
SENSOR       observe                      (Windows sensor, WSL collectors, network)
FABRIC       preserve evidence            (append-only, typed, sequenced)
PROVENANCE   explain who caused an action (execution identities, releases, managed persistence)
CORRELATOR   reconstruct reality          (process/identity/topology/temporal graphs)
POLICY       decide invariant violations
RESPONSE     score / alert / contain / explain
RELEASE      change JARVIS safely         (single writer, content-addressed)
```

## Lane A: provenance and release

### Invariants

- **P1: paths and names are never identity.** A release is identified by the SHA-256
  of its file manifest (`release_id`), not by the directory it was built from.
  A task, service or process is trusted only through an exact comparison with a
  declaration shipped in the sealed release, or a signature from a key that the
  protected user's processes cannot read.
- **P2: provenance is attribution, not permission.** A verified execution identity
  records who launched a process tree. It never lowers a severity by itself, and it
  never suppresses a finding. Jev agreed (P(yes) = 0.07 for "a capsule identity alone
  may lower severity"). Missing, expired, unsigned, mismatched or unverifiable
  provenance means *no provenance*, never *benign*.
- **P3: fail closed and explicit.** No signing key means no identities are issued,
  and the capsule reports that. A malformed ledger row is skipped and counted. An
  unknown checkout refuses the deploy rather than guessing.
- **P4: the actor claim is labelled with its strength.** JARVIS's own daemon identity
  is *observed*, because the daemon issues it for itself. An agent session's actor
  (`codex`, `claude`, `test_suite`) is *declared* by the launcher. The binding
  (pid, process start time, boot id, executable) is *observed* by the daemon through
  kernel peer credentials. It is never taken from the request.
- **P5: single release writer.** Only one deploy can hold `/opt/jarvis/.deploy.lock`.
  A candidate staged from base release X refuses to switch when the live release is
  no longer X (`--expect-base`), so two narrow releases cannot silently drop each
  other's changes.
- **P6: no world-writable execution.** Release sources, staging trees and capsule
  temp directories are never under a world-writable directory. The deploy refuses
  such a source, and capsules point `TMPDIR` at a private 0700 workspace.
- **P7: bounded resources.** Ledger rows are bounded in size and count and rotate at a
  fixed byte budget. Identities expire (24 h maximum). Ancestry walks are bounded
  (64 hops). Socket requests are bounded (4 KiB, 2 s).
- **P8: recovery.** The previous release stays on disk, and `--rollback` still works.
  Deleting the ledger loses attribution and never grants trust. Removing the key
  disables issuance only.

### Designs compared

| Decision | Options | Chosen | Why | Reconsider when |
|---|---|---|---|---|
| Signing model | Daemon-held Ed25519 key (root 0400, read only through the daemon's `CAP_DAC_READ_SEARCH`) / user HMAC file / unsigned ledger | Daemon Ed25519 | A same-user attacker cannot read the key: `ptrace_scope=1`, `suid_dumpable=0`, and a capability-holding target resists same-uid ptrace. The public key lets any verifier, the Windows broker included, check without a secret. Jev Choice 1.0. | The daemon loses its capabilities (issuance stops; attribution becomes unavailable, never trusted), or a TPM-backed key becomes available |
| Release single writer | Root lock plus expected base / patch-queue service / convention | Lock plus expected base | No new long-running privileged service. Optimistic concurrency catches the observed collision exactly. Jev Choice 0.88 (queue 0.12). | More than two writers need ordering, not just refusal |
| Managed persistence | Per-task hand-written branches / one declaration per task compared field by field | Declarations | One reviewable table. Every field is exact, and the fingerprint comes from the sealed release. Jev gave P(yes) = 0.31 that this weakens detection, so each rejection path from the old code stays covered by regression tests. | A task needs a check the declaration cannot express |
| Agent attribution | Environment variable / cgroup scope / process ancestry from a signed capsule root with a child subreaper | Ancestry plus subreaper | Environment and same-user cgroups are forgeable by the user. A parent PID can't be rewritten, and the subreaper keeps double-forked children attached. | A Windows-side process (interop) needs attribution; that is the joint interop broker |

### Lane A status, 2026-09-24

Built (source-tested, not yet deployed):

| Part | Where | What it does |
|---|---|---|
| Release identity | `jarvis/platform/provenance/release.py` | `release_id` = SHA-256 of the sorted path/digest manifest; a recorded id that disagrees with its own files is refused |
| Release controller | `scripts/deploy_root_runtime.py` | Exclusive `/opt/jarvis/.deploy.lock`; `--expect-base`; root-owned `INSTALL.json` records the checkout, and an unknown checkout refuses instead of guessing; world-writable sources refused; release dirs named by `release_id`; provisions the Ed25519 key in `/etc/jarvis/provenance` |
| Narrow-release stager | `jarvis release stage --file …` (`jarvis/platform/provenance/stage.py`) | Live sealed release (each file hash-checked against its manifest) plus only the named reviewed files, committed in a private repository under `~/.cache/jarvis-release-staging/`; prints the one deploy command with `--expect-base` |
| Managed persistence | `jarvis/platform/provenance/persistence.py`, `trusted_tasks.py`, `control.py` | 9 JARVIS-managed tasks declared as data, compared field by field; any declared PowerShell task that fails verification is critical (adds connectivity guard and input hook to the critical set) |
| Execution identities | `jarvis/platform/provenance/identity.py`, `authority.py` | Daemon-issued Ed25519 identities bound to (pid, start, boot, exe); issued for the daemon itself (observed) and over a Unix socket for declared agent/test sessions; ledger verified on read, flood-resistant rotation; `lookup` / `attribute` for Lane B |
| Agent/test capsule | `jarvis capsule run --actor codex -- …` (`capsule.py`) | Private 0700 workspace with `TMPDIR` inside, child subreaper, verified signed identity with renewal, session record without command lines |

Measured:

- Live control data at 21:55: all 9 declared tasks verify against `~/jarvis`. With the
  staging clone as the checkout, exactly the two live criticals reproduce: `jarvis reviver` and
  `jarvis wake watchdog`, "arguments differ". The live release (`20260924T181631Z-0c40ae1d`) has no
  `checkout` in its RELEASE.json, so `SOURCE_ROOT` is the staging clone. That is the cause of both
  Persistence criticals and of the `jarvis-selfcheck.service` medium, whose template is filled
  with `SOURCE_ROOT`.
- Tests: `tests/test_release_controller.py`, `tests/test_managed_persistence.py`,
  `tests/test_provenance.py`, plus the updated `tests/test_root_runtime.py`.

Not yet true, stated plainly:

- No identity has been issued on this machine. The key only exists after a root deploy of this
  code, and issuance, lookup and renewal inside the live daemon are unmeasured. Jev ranked this as
  the first gap to close (Choice 0.95).
- A **declared** actor can be self-assigned by any process of the user: anything can run
  `jarvis capsule run --actor codex`. It is a grouping key. `mitigates_findings` is always false.
  Only a basis stronger than declaration, such as human confirmation of a session start, could ever
  inform policy, and then only alongside independent evidence. Jev gave P(yes) = 0.65 that
  same-user issuance grants more than a label. The concrete path found was eviction of genuine
  identities by a request flood, fixed with live-identity carry-over and covered by a test.
- Capsule capabilities are declared, not enforced (no network or filesystem policy yet). Orphans
  that outlive the launcher lose attribution. Windows-side processes started through interop
  are not attributed; that is the joint interop broker (item 6).
- The capsule runs the user's command even without provenance. Failing closed applies to trust,
  never to the user's own work: an unattributed tree can only produce more findings.

To deploy (the human's step; the live deploy script predates `--expect-base` and `INSTALL.json`):

1. `jarvis release stage --file …` for the reviewed Lane A files. The staged tree carries the new
   deploy script.
2. `sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py --source <stage> --checkout ~/jarvis`.
   This is the old script: no `--expect-base` yet, but `--checkout` is honoured.
3. Every later deploy uses the new script with `--expect-base` as printed by the stager.
4. Recheck: `jarvis provenance status`, the control job's findings, and fresh collector receipts.

## Combined release

Both lanes ship in **one** narrow release from one sealed base; two releases staged separately
drop each other's changes. Lane B builds that single stage with `jarvis release stage`. The
Lane A "To deploy" steps above apply to it: the first switch runs the old live deploy script, so
it keeps `--checkout ~/jarvis` and drops `--expect-base`. Lane B's owner steps below
add a read-only dry run before the switch and the snapshots to recheck after it.

## Lane B — observations, epochs and host topology (Claude session pid 11021, 2026-09-24)

Scope from the owner's "90" brief: host topology and execution domains (item 5), observation
epochs and monotonic time (8, 9), KNOWN SAFE / KNOWN UNSAFE / UNKNOWN with separate sensor
health (14), and bounded coherent confirmation (15). Source-tested; **not deployed**.

### Invariants (written before editing)

1. Evidence continuity: nothing observed is deleted. An explained socket finding stays visible at
   low severity with its proof, and a transient first sighting is kept as a low record.
2. Fail closed: any unreadable fact (mountinfo, `/proc/<pid>/exe`, resolv.conf, fib_trie, a denied
   fd read, a failed re-query) produces no explanation. The original severity stands.
3. No name-based trust: a name alone never explains anything. Explanations need file identity
   (dev, ino), ownership, mode, mount options, or declarations WSL wrote itself.
4. Masquerade sensitivity is kept: a script or argv0 named like a system binary, located outside
   the system paths, still flags. So does a parenthesized name from an untrusted path, or a copy
   of `/init`.
5. Wall-clock differences across a boot, resume, clock step or release change are never computed.
   Opening an extra epoch is the safe error.
6. Confirmation is bounded: one re-query, at most 2 s apart. A failed re-query or an epoch change
   is inconclusive, never clean.
7. Bounded cost: the topology is read once per scan (four small files). Per-process checks run
   only for processes that already mismatch. The epoch ledger keeps 64 entries.

### Design choices and why

| Problem | Rejected | Selected |
|---|---|---|
| `scan` name mismatches (16 mediums: `/init` SessionLeader/Relay, udev, sd-pam, python scripts) | a name allowlist (masquerade by name); per-fingerprint owner approval (hides drift) | structural proof in `jarvis/platform/topology.py`: WSL runtime (same inode as the read-only, root-owned `/init` mount, root, a known alias, `/init` ancestry to the distro boundary), argv0 link to the same inode, shebang script name, systemd helper of a root-owned non-writable trusted binary |
| Ownerless `10.255.255.254:53` listeners (medium in `hidden` and `deep_hidden`) | downgrade all WSL loopback orphans (unknown owners) | declared-endpoint proof: resolv.conf generated by WSL names the address, the kernel routes it as a local /32, port 53, peerless, confirmed in two views, complete fd visibility. `udp/323` has no declaration and stays medium |
| Cross-standby time artifacts | direct wall-clock comparison | `jarvis/core/epochs.py`: an epoch opens on a boot-id change, a CLOCK_BOOTTIME−MONOTONIC suspend delta, a wall−monotonic step > 2 s, or a release change. `ordered()` and `wall_delta()` refuse cross-epoch deltas |
| Sentinels such as Defender age 65535 | special-casing in each collector | `jarvis/core/observation.py`: `reading()` decodes sentinels to UNKNOWN; a missing value is UNAVAILABLE and a malformed one DEGRADED; `judge()` applies policy only to real values |
| Race-prone orphan sockets | drop a transient silently (the old code) | `observation.confirm` semantics in `hidden/sockets.py`: confirmed / transient (kept, low) / inconclusive (original severity, including a sleep between views) |

Jev, before the design (metadata only): Choice structural_proof 1.0; Noul 0.79 for "declared DNS
tunnel → low, undeclared 323 stays medium"; Choice epochs 1.0; top validation gap init_replacement
(confidence 0.38), so all four gaps are tested. Jev, after the implementation: Noul 0.10 that
this is verified on the running service (it is not); Noul 0.84 that masquerade stays flagged;
Choice privileged_dry_run 0.89 as the next gate. All of this is advisory: the tests and live
readback are the gates.

What would change the decision: WSL starting to hold user processes under `/init` with new
aliases (they then stay flagged until the alias set is reviewed); a WSL version that stops
marking resolv.conf; a measured epoch-open rate that is too high under NTP slew.

### Files

`jarvis/core/observation.py`, `jarvis/core/epochs.py`, `jarvis/platform/topology.py` (new; the
layer test forbids a new top-level package); `collectors/process/detect.py` + `monitor.py`
(topology passed to `assess`); `collectors/process/hidden/{sockets,run}.py`;
`collectors/host/posture/sections.py` (typed signature age; a missing age is now a low
visibility finding, not silence); `service/jobs.py` (the `hidden` job passes `db_path` so the
epoch ledger records); `core/assurance.py`. Tests: `tests/test_topology.py`, `test_epochs.py`,
`test_observation.py`, and the updated `test_hidden_attribution.py`.

### Expected effect, not yet measured

After deployment: the 16 `scan` mediums above should become explained (the `scan` penalty goes
from 10 to about 0), and `hidden`/`deep_hidden` should go from 4 to 2 mediums each (8 → 4). No
high or critical changes. The Active threats area stays low because of its highs (sysmon_linux,
input, intrusion). These numbers are predictions until the fresh snapshots show them.

### Owner steps

1. Privileged read-only dry run (Jev's recommended next gate). It prints each current mismatch
   and its explanation, and the socket verdicts. It writes nothing:

   ```
   sudo python3 -I -c "import sys; sys.path.insert(0,'~/jarvis')
   from jarvis.platform import linux, topology
   from jarvis.collectors.process import detect
   from jarvis.collectors.process.hidden import sockets, run
   t = topology.snapshot()
   for p in linux.collect(with_sockets=False):
       if 'name-mismatch' in detect.traits(p):
           why = topology.name_explanation(p, t)
           print('EXPLAINED' if why else 'MISMATCH', p['pid'], p['name'], p['exe'], why or '')
   rows, denied = sockets.orphan_sockets()
   for f in run._orphan_findings(rows, denied, True, t): print(f['severity'], f['title'], f['detail'][:90])"
   ```
2. Include the Lane B files in the same reviewed narrow release as Lane A. Two releases staged
   separately from one sealed base drop each other's changes.
3. After the switch, wait for fresh `scan`, `hidden` and `deep_hidden` snapshots. Compare them
   with the findings listed above, and read `observation_epochs_v1` from the store meta.

### Not done in this lane

- Epochs are recorded but not yet consumed by Sysmon/native reconciliation (`temporal.py`,
  `telemetry/reconcile.py`). An auto-mode classifier denied a read-only search of those files in
  this session, so that integration is left for a session that can read them.
- Windows interop (`powershell.exe` whose Linux exe is `/init`, user-owned) stays a name mismatch
  until the joint interop broker (item 6) exists. Container execution domains are not modelled;
  the uvicorn container process is explained only by the shebang rule.
- The owner of loopback `udp/323` sits in the WSL VM root and is unobservable here; it stays medium.
