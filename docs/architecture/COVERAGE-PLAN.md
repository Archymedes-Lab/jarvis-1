# Attack-surface coverage plan

Status 2026-10-02: 11 validated, 34 claimed, 141 blind of 186 ATT&CK techniques (Windows and
Linux, parent techniques only). This plan raises the validated share. It follows the score-integrity
rule: a number moves only through a real detector, a proven measurement bug, or an explicit owner
decision. A technique is never promoted without a probe that makes the real detector fire.

## Status 2026-10-03: Phase 0 item 1 and Phase 3 A built, not deployed

Projected from a copy of the live catalogue and collector freshness: **73 validated, 32 claimed,
71 blind of 176** (41%). The live map does not change until the release is deployed and read back.

What landed:

- **Phase 0, item 1.** `feeds._attack` skips deprecated techniques and removes rows a full
  catalogue load no longer refreshes (never on a truncated load). 186 to 176.
- **Phase 3 A.** `jarvis/collectors/telemetry/techniques.py`: about 120 rules, each keyed on the
  image of the process that ran the tool plus its own arguments, wired into `sysmon.audit` and
  `sysmon_linux._rules`. The coverage map builds one probe per technique from the rule table and
  replays it through those two functions (`sysmon.audit(events=...)` is the new replay entry; it
  cannot write to the store).
- **Already detected, never mapped.** Probes for LSASS memory access (T1003), recovery destruction
  (T1490), DLL side-loading (T1574), raw device opens (T1006), measured-boot drift (T1542) and
  file-less images in memory (T1620).

Decisions that differ from the plan below:

- **Discovery bursts stay claimed.** The plan counted the 23 burst-only discovery techniques as
  validated. A single discovery command is deliberately silent, so the technique by itself is not
  caught; they are shown as claimed with that reason. Their probes still run, so a broken burst
  rule is reported as a regression.
- **Phase 1 was done through process rules**, not by mapping the posture collectors: T1685, T1686,
  T1688, T1690, T1496, T1611, T1037 and T1529 are validated by the command that does it. The
  collectors' own state checks are still unprobed.

Noise measured before scoring, as this plan requires: 256,397 Windows and 35,583 Linux retained
process starts replayed read-only. First pass: 1,281 Windows hits, almost all JARVIS's own
collectors (an inline script naming `root\subscription`, `cmdkey /list` from the identity
collector). After keying rules on creation verbs and dropping the `cmdkey` rule: under ten
findings, all real owner actions (sensor install, a task created by `schtasks`, a power-setting
change), and no discovery burst.

Still open from this plan: Phase 0 item 2 (a test that fails when a `COVERAGE` key such as T1562
is absent from the catalogue) and the `partial` level for sub-techniques; the remaining claimed
techniques of Phase 2 (T1056, T1078, T1110, T1133, T1204, T1497, T1556, T1557, T1571); Phase 3
B to F; and Arena emulation for any of it.

## Status 2026-10-04: Phase 2 and part of Phase 3 built

Live after the first release: 72 validated, 33 claimed, 81 blind of 186. This round projects
**90 validated, 24 claimed, 62 blind of 176** (51%) once deployed and the catalogue reloads.

- **Phase 2, proven through the collector's own rules.** Probes hand a synthetic payload to the
  real function (`data=`, `lines=`, `dirs=`, `home=` parameters; the same code runs either way):
  T1204 pasted-command lures, T1056 keyboard hooks, T1557 gateway and resolver changes, T1689
  Wi-Fi encryption downgrade, T1110 login-guess spikes, T1133 remote desktop logons, T1556 rogue
  PAM modules, T1068 exploitable drivers, T1102 dead-drop hosts, T1185 browser remote debugging,
  T1195 package-registry redirection, T1200 new option ROM code.
- **Phase 2, claims removed.** T1497 and T1571 had no rule a probe could fire; they are blind.
  The retired T1562 mapping is gone, and the map now reports any mapping to a technique the
  catalogue no longer lists (Phase 0 item 2, done at run time rather than as a unit test, since
  tests have no catalogue).
- **Held at claimed although the probe fires.** T1078: every successful remote logon is
  reported, but a stolen credential looks the same as the owner's. The 23 burst-only discovery
  techniques, as before. Both are listed in `attackmap.HELD` with the reason shown on the tile.
- **Phase 3 A additions.** Rules keyed on the parent process: a document application starting a
  script host (T1203), a server process starting a shell (T1190), the print spooler or LSASS
  starting one (T1068). These report the after-effect of an exploit, never the exploit, and say
  so. Certificate export (T1649).
- **Phase 3 C, first two.** Outbound file-share connection to a public address (T1187) and one
  process resolving 15 or more non-existent names in ten minutes (T1568), both from Sysmon
  events already ingested.

Noise, measured before scoring: 687,887 retained process, network and DNS events replayed through
`sysmon.audit` itself. The new rules produced nothing; the only findings were real owner actions.
No outbound public SMB exists in 294,236 network events, and no process reached the
non-existent-name threshold.

Live positive controls on the deployed rules: a seven-command discovery burst on Linux and one
on Windows were each reported within a minute.

A probe is registered only where its detector exists (`attackmap._optional`), so a narrow release
that lacks a module keeps that technique's mapped level instead of reporting a regression.
A contract test ties the fields the probes build to the fields the collection scripts emit.

Still open after that round: `partial` level for sub-techniques; T1674 input injection; Phase 3 B
file canaries, the rest of C, D, E and F; Arena emulation.

## Status 2026-10-04 (later): depth, three more techniques, and stricter holds

Live before this round: 89 validated, 25 claimed, 72 blind of 186. This round projects
**91 validated, 31 claimed, 64 blind of 186** in the narrow release (52% of 176 once the
catalogue reloads). The number moves little on purpose; most of the round is about how well
the validated ones are proven.

- **New, validated.** T1674 input injection: the input monitor's injected-event rule, now a
  function that reads the store alone (`inputwatch.analysis.injected_findings`), probed with a
  store of its own. T1495 firmware corruption, as an effect: firmware code measured differently
  (PCR 0) with no version change. T1566 phishing, as an effect: a script, shortcut or program
  run straight out of a mail attachment cache or an archive. The message itself is never seen,
  and the finding says so.
- **New, held at claimed.** T1189 (a browser starting a script host; `cmd.exe` is excluded
  because browsers start it for their own helpers all day), T1563 (`tscon`), T1484 (Group Policy
  cmdlets; this machine is in no domain), T1207 and T1606 (one attack tool's syntax each).
- **Demoted.** T1550 was counted as validated on Mimikatz syntax alone. The same rule that holds
  T1207 and T1606 now holds it. Jev judged the demotion consistent (0.89).
- **Registry-write rules (`techniques.REG_RULES`).** The same change whatever made it: reg.exe,
  PowerShell, an installer or an API call. Firewall profile off (T1686), a security service set
  to disabled (T1685), a service program in a user-writable path (T1543), a Run value naming a
  script host or a staging path (T1547), an Image File Execution Options debugger (T1546),
  WDigest plaintext caching (T1003). They add depth to techniques already validated; none
  validates a technique on its own account.
- **Ways proven.** Each row carries how many separate procedures are proven for it. A probe now
  replays every rule for its technique, and a technique with a hand probe and table rules needs
  both. A registry rule counts only where its key family has been seen recorded in the last 30
  days (`sysmon_registry_recorded_v1`, written by real runs, never by a replay): Jev put 0.11 on
  letting a silent rule count. The number is shown only in a technique's detail text (Jev 0.87
  for that over a headline count), because a count of procedures is not completeness.
- **Not buildable with current data, measured.** Mass file deletion or rewrite (T1486) and
  system-binary replacement on Linux (T1554): the Sysmon policy records file deletes only for
  `.ps1` in Temp and almost no file creation. They need a policy change or decoy files, both
  owner decisions.

Noise, measured before scoring: 752,569 retained events replayed with
`python3 -m scripts.dev.replay_techniques`. Two registry rules fired on real history, both
false: Defender's own service path under `ProgramData`, and an installer's `RunOnce` from the
package cache. `ProgramData` was removed from both patterns and both cases are now look-alikes
in the rule table. After that the new rules report nothing on this machine's history.

Also fixed, found while reading the score: the editor-extension inventory forgot everything
under a directory it could not read for one run, then reported all of it as new on the next
(23 false highs after a standby). See `COVERAGE-DEPTH-RELEASE-2026-10-04.md`.

Deployed 2026-10-04 18:25 EEST and read back: 91 / 31 / 64, nothing regressed.

## Status 2026-10-04 (evening): the blind side

Live before this round: 91 validated, 31 claimed, 64 blind of 186. This round projects
**100 validated, 40 claimed, 46 blind of 186** in the narrow release. Ten of the 46 are ids
ATT&CK has retired, so 36 real techniques stay blind, and the figure becomes 100 of 176 (57%)
when the catalogue reloads.

Jev was asked how each of 20 candidates should be counted and whether it would be noisy
(`scripts/reviews/coverage_blind_advisory.py`). Code applied the same policy as before.

- **Validated (9).** T1039 copy from a network share, T1119 one command collecting documents
  recursively, T1005 a key store, password database or wallet copied with a copy tool, T1029 a
  scheduled task or cron entry whose action uploads, T1132 data encoded and piped to a network
  tool, T1573 a shell carried over a TLS client, T1095 a shell carried over UDP, T1499 a fork
  bomb, T1020 one command looping over files and uploading each.
- **Built, held at claimed (9).** T1571 (network events: a script host reaching a public
  address on an unusual port), T1205 (the existing raw-packet-socket finding, through a new data
  seam in `sniffing._linux`), T1074, T1080, T1491, T1678, T1497, T1072, T1030. Each carries its
  reason in `attackmap.HELD`.
- **Dropped.** T1559: the document-application rule is already counted for two techniques and
  Jev put 0.28 on not mapping it a third time. T1011: I do not know the Bluetooth transfer
  program's command line well enough to write a rule that is not a guess.

Noise, measured before scoring: 758,278 Windows events and 514,553 Linux events (14 days)
replayed. The new rules reported nothing on Windows, including no unusual-port connection in
about 300,000 network events. On Linux the encoding rule fired once on a `grep` whose pattern
used `\|` between tool names; the rule now needs a real pipe and that command is a look-alike.
A shell rule still reads the text of the whole command line, so a command that only *contains*
such a pipeline as text (a here-document, this project's own tests typed at a shell) is
reported: seen once, on my own test command.

What stays blind, and what each group needs:

| Group | Techniques | Needs |
|---|---|---|
| Removable media | T1025, T1052, T1091, T1092 | a removable-volume inventory on Windows; buildable next (built 2026-10-05, see below; T1092 stays blind) |
| File contents and mass change | T1486, T1554, T1565, T1221 | a wider Sysmon file policy or decoy files (owner decision) |
| Inside a program | T1106, T1129, T1480, T1559, T1622, T1668, T1679 | API-level telemetry the sensors do not collect |
| Content of traffic | T1001, T1008, T1041, T1104, T1665 | decrypting traffic, which JARVIS does not do |
| Exploitation itself | T1210, T1211, T1212, T1687 | only effects are visible |
| Off the machine | T1111, T1199, T1213, T1534, T1621, T1657, T1659, T1667, T1669, T1684 | another vantage point (mail, identity provider, network) |
| Other | T1011, T1498 | a Bluetooth or tethering inventory; network volume |
| Retired ids | T1026, T1034, T1043, T1051, T1061, T1062, T1064, T1108, T1153, T1175 | nothing: they leave at the catalogue reload |

Still open: `partial` level for sub-techniques; removable media; file canaries and a wider
Sysmon file policy (owner decisions); Arena emulation; a live positive control for a
single-action rule.

## Status 2026-10-05: removable media, and the blind-side round restaged

Live before this round: still 91 validated, 31 claimed, 64 blind of 186. The blind-side round
above was staged but never deployed: the world-watch release went out on the same base, which
made that stage stale. This round restages it on the live release together with the work below
and projects **100 validated, 43 claimed, 43 blind of 186** (measured in the staged tree against
a copy of the live catalogue and collector freshness).

- **Built, held at claimed (3).** T1091 a program started from a removable drive, T1025 a
  command-line copy reading from one, T1052 a command-line copy writing to one. Jev put 0.92,
  0.54 and 0.61 on "claimed" (`scripts/reviews/coverage_media_advisory.py`), and no removable
  drive has been attached since they were written, so nothing has exercised them.
- **Still blind.** T1092: what a program exchanges through files on a stick is not visible.

Design, and why it won. Sysmon names the drive a program ran from, not what kind of drive it
is, so the rules need a drive inventory from Windows. Three ways to get one were compared:

| Design | Cost | Why not |
|---|---|---|
| Add the inventory to the posture script | none | the elevated broker trusts that script by hash; changing it drops the elevated posture read until the owner reinstalls the broker |
| Poll the inventory on a schedule | a PowerShell start every few minutes | a stick attached and removed between polls is never seen, and the cost is paid on days nothing is attached |
| Ask only when a process names a drive not known to be an internal disk (chosen) | about 3 s, once every 6 h and once per run while such a drive is in use | the drive may be gone before the 10-minute Sysmon run asks |

The chosen design reports a drive that is gone as "a drive that is no longer attached" and says
it may have been a network drive or a disk image (Jev 0.65 for reporting it over staying
silent). A USB hard disk calls itself a fixed disk, so the bus of the disk is read as well as
the drive type. Reconsider if the native sensor gains volume-arrival events (then the kind is
known at the time, and the "no longer attached" case disappears), or if a machine with network
drives mapped and unmapped all day makes that wording noisy.

Invariants, each with a test in `tests/test_techniques.py` (`RemovableMediaTests`): an internal
disk is never reported; a drive's kind comes from Windows or is said to be unknown; Windows is
asked at most once a run and never when every drive named is known to be internal; a failed
read keeps the last good inventory, judges nothing, and is reported as low "drive types could
not be read"; a replay never asks; file names on a drive are never quoted.

Noise, measured before scoring: 842,563 retained Windows events replayed with only `C:` given
as internal, the most the rules can report. They reported nothing: all 290,795 retained process
starts ran from `C:`, and no copy command named another drive. The real inventory read was run
once through the collector's own function: `C: Fixed, NVMe`, 3 s.

What these rules do not see: files dragged in Explorer or written by a program (no copy tool
starts); a Linux guest mount; and anything at all until a drive is attached.

Still open: a live positive control with a real stick (it also promotes nothing by itself:
the owner decides whether one exercised procedure is enough); `partial` level for
sub-techniques; file canaries and a wider Sysmon file policy (owner decisions); Arena
emulation; a live positive control for a single-action rule.

## Rules for every phase

- **No claim without a probe.** New mappings land together with a probe in
  `jarvis/service/attackmap.py`, so they enter as validated or not at all.
- **A probe proves the rule, not the sensor.** Sensor liveness stays judged by collector freshness.
  Arena scenarios (`jarvis/lab/`) add end-to-end proof for the highest-value techniques.
- **Unobservable is said, not hidden.** Techniques this machine cannot observe are listed with a
  reason and stay in the denominator unless the owner removes them.
- **Each phase ships as a narrow release** with a written baseline and a live readback.

## Phase 0: make the measurement correct

Two defects were found on 2026-10-02. Both are measurement bugs, not coverage.

1. `jarvis/intel/feeds.py` drops revoked techniques but keeps deprecated ones. Ten deprecated
   techniques sit in the denominator as blind: T1026, T1034, T1043, T1051, T1061, T1062, T1064,
   T1108, T1153, T1175. Fix: skip `x_mitre_deprecated`. Denominator 186 to about 176.
2. ATT&CK split T1562 (Impair Defenses) into T1685 to T1690. The catalogue no longer has T1562,
   so the existing claim counts for nothing and the successors read blind. Fix: a test that fails
   when a `COVERAGE` key is absent from the catalogue, then remap each successor on its own
   evidence.

Also decide how sub-technique coverage counts. Today T1003, T1555 and T1195 read blind although
T1003.001, T1555.003 and T1195.001 are mapped. Proposal: a `partial` level, shown separately and
never added to validated.

## Phase 1: map what existing collectors already detect

Candidates, each to be confirmed against the collector's code and given a probe:

| Technique | Existing collector |
|---|---|
| T1685 Disable or Modify Tools | control, posture |
| T1686 Disable or Modify System Firewall | firewall |
| T1688 Safe Mode Boot, T1689 Downgrade Attack | posture, preos (boot options) |
| T1690 Prevent Command History Logging | evasion |
| T1496 Resource Hijacking | resources |
| T1611 Escape to Host | containers |
| T1669 Wi-Fi Networks | netwatch |
| T1200 Hardware Additions | controls, preos (option ROM code) |
| T1037 Boot or Logon Initialization Scripts | startup, asep |
| T1529 System Shutdown/Reboot | preos (unclean shutdowns) |

Expected: 8 to 11 techniques from blind to validated.

## Phase 2: prove the 34 claimed techniques

12 probes exist. Write one for each remaining claimed technique, calling the real detector
with synthetic evidence. A probe that cannot be made to fire is a finding: the claim is removed.
Expected: most of 34 from claimed to validated. This is the largest honest gain for the least new code.

## Phase 3: new detection, grouped by data source

Ordered by techniques closed per unit of work. Sources A and B reuse event streams JARVIS already
ingests (Sysmon, native sensor, Sysmon for Linux).

**A. Command-line and process rules on existing streams (about 45 techniques)**
- Discovery burst: many discovery commands from one process tree in a short window, one sequence
  rule. T1007, T1012, T1016, T1018, T1033, T1046, T1049, T1057, T1069, T1083, T1087, T1120, T1124,
  T1135, T1201, T1217, T1482, T1615, T1652, T1654, T1673, T1680. Single commands stay silent;
  the burst is the signal.
- Proxy execution: T1047, T1127, T1202, T1216, T1220, T1569, T1559, T1129.
- Impact preparation: T1490 (shadow-copy and recovery deletion), T1489, T1485, T1531, T1561, T1222.
- Credential tooling: T1003, T1558, T1649, T1134, T1550.
- Collection and staging: T1560, T1074, T1119, T1140, T1005.

**B. File-system canaries (impact)**
Decoy files in user folders, watched for mass rename, rewrite or deletion: T1486, T1485, T1565,
T1491. This closes most of the impact tactic, which is at zero today.

**C. Network egress baselines (exfiltration and command-and-control)**
Per-process upload volume and destination baselines from netwatch: T1041, T1048, T1567, T1020,
T1029, T1030, T1011. DNS behaviour: T1568, T1572, T1071. Protocol shape: T1095, T1102, T1008,
T1104. Volume: T1498, T1499.

**D. Removable media and hardware**
Device arrival and volume mount events: T1091, T1052, T1025, T1092, T1200.

**E. Identity and credentials**
T1555, T1539, T1606, T1621, T1111, T1187 (outbound authentication to untrusted hosts), T1185.

**F. Initial access**
Download provenance (mark-of-the-web lineage from browser to execution): T1566, T1189, T1204.
Exposed services: T1190, T1210. Supply chain: T1195.

## Phase 4: techniques this machine cannot observe

For the owner to rule on, one by one. Proposed reasons:

- No domain: T1207, T1482, T1484, T1615.
- Happens off the machine or to the person: T1657, T1667, T1684, T1534, T1199.
- Content of encrypted traffic: T1001, T1132, T1573, T1665. Only metadata is visible without
  decrypting traffic, which JARVIS does not do.
- Exploitation itself (only its effects are visible): T1068, T1203, T1211, T1212, T1687.

These stay blind and listed with their reason unless the owner removes them from the denominator.

## Expected numbers

| After | Validated | Claimed | Blind | Of |
|---|---|---|---|---|
| Today | 11 | 34 | 141 | 186 |
| Phase 0 | 11 | 34 | about 131 | about 176 |
| Phases 1 and 2 | about 50 | under 5 | about 121 | about 176 |
| Phase 3 A and B | about 95 | under 5 | about 76 | about 176 |
| Phase 3 C to F | about 130 | under 5 | about 40 | about 176 |

The figures after Phase 0 are estimates. A realistic ceiling is about 75% validated; the rest is
Phase 4. The assurance register moves separately: a capability leaves `partial` only with a
deployed receipt, a positive control and a soak.

## What would change this plan

- A probe in Phase 2 that cannot fire: the detector is fixed before any new work.
- Rule noise in Phase 3 A on this machine's own developer activity: the burst thresholds are
  measured against a week of real events before the rules are scored.
- Resource cost: every new job states its measured CPU and time before it is scheduled.
