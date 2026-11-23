# Spyware and hidden-process reasoning engine

Status 2026-09-30: source-tested, run once live read-only on this host, not deployed and not scheduled.
The governing [Maximum Assurance directive](../security/MAXIMUM-ASSURANCE.md) applies. A quiet run is
never proof of a clean machine; verdicts name observations and missing evidence, never intent.

## What it does

`jarvis reason spyware [--deep] [--no-jev]` reasons about every process instance:

```text
OBSERVE      read-only sources, each reporting current / partial / unavailable
NORMALIZE    typed Subject + fixed-vocabulary Observation (no free text reaches a verdict)
RECONCILE    cross-view contradictions (hidden-process audits) become concealment facts
HYPOTHESIZE  stages (capture, conceal, persist, stage, egress, evade), explanations, missing evidence
ADJUDICATE   optional typed advisory: a logged second opinion, no authority
ESCALATE     an observation-depth plan through the existing bounded selector; executes nothing
VERIFY       the fresh observation that would confirm or refute, then re-run; a quiet run is not proof
DECIDE       the human. Depth 3 (forensic trace) only ever waits for explicit authorization
```

`jarvis reason explain <class>` describes how a class works (keylogger, screen_spy, av_spy,
infostealer, rat, covert_process), what it must eventually do, and which of those steps JARVIS cannot see.
`jarvis reason selftest` measures the engine on the synthetic corpus; `jarvis reason calibrate`
measures the advisory on the same corpus (one remote request per case).

## Invariants (each has a test)

1. Missing evidence never means clean. Stale or incomplete observations are unknown, listed as
   degraded sources, and never counted as positive. A process JARVIS cannot read is recorded as unknown.
2. One capability is not a verdict. `SUSPECT_CHAIN` needs unexplained capture plus two further stages.
   Identity weakness (unsigned, temp path, brand-new image) adds context only when a stage fact exists.
3. Concealment alone is enough for `VISIBILITY_CONTRADICTION`, and it raises observation depth; it does
   not assert malware. Confirmation rules match the hidden-process collector (a raw `wmiOnly` entry
   is not a contradiction unless the pid is also absent from the other view).
4. Explanation by category needs a valid signature, an exact normalized publisher match and a fitting
   path class, and covers only capabilities that category expects. A signed script host is never
   explained by its signature. Only supervisor-verified pids are JARVIS's own hook. Explained is not
   authorized: dual-use products (remote support, anti-cheat, desktop agents) ask the owner to confirm.
5. Monotonic: adding unexplained evidence never lowers a verdict. Inputs are bounded.
6. Only enums, kind labels and booleans go to the advisory. No names, paths, publishers, keys or free text,
   and not the deterministic verdict, so the opinion stays independent.
7. The advisory cannot change a verdict or a depth, suppress a finding or authorize anything;
   unavailable or malformed advice is stated and ignored. Nothing here executes an action.

## Design choice

| Candidate | Result |
| --- | --- |
| General LLM agent reasoning over raw telemetry | Rejected: unbounded, cannot be tested, may leak content, no invariants |
| Anomaly ML only | Rejected as primary: no explanation, contaminated baselines, cannot name missing evidence |
| Signature/IOC only | Kept elsewhere (hunt, intel); misses novel and living-off-the-land behaviour |
| **Deterministic hypothesis engine + typed advisory** | **Chosen** |

Jev (metadata-only, 2026-09-30) chose the last design with confidence 1.00. It put "the advisory
sets the verdict" at 0.06, "contradiction raises depth, not a malware label" at 0.96, "the chain requirement
reduces look-alike false positives" at 0.82, and named capture-API sensor coverage as the largest gap at
only 0.60 confidence. That is advisory; the tests and measurements below govern.

## Measurements

- Engine on the synthetic corpus: 8/8 spyware controls flagged, 0/11 look-alikes flagged, no expectation drift.
- Advisory calibration (19 cases, `jarvis reason calibrate`): "plausible for ordinary software" averaged
  0.18 on controls (0.07-0.43), 0.42 on explained look-alikes (0.21-0.60) and 0.30 on the look-alikes the
  rules deliberately leave unexplained. The earlier "spyware chain" question scored the Windows shell 0.82 and
  did not separate at all. Nothing separated cleanly, so the advisory has **no authority**. Its archetype
  answer named the right class for 6 of 8 controls and is used only as a note.
- Live, read-only, this host: 313 process instances, every source current, no capture pattern and no
  concealment (2 explained hook holders: `explorer.exe` as an OS component, JARVIS's own hook by verified pid).
  This matches an independent manual audit the same day ([PROCESS-AUDIT-2026-09-30](../security/PROCESS-AUDIT-2026-09-30.md)).
- The first live run over-reported 9 contradictions because a raw disagreement list was read as confirmed.
  Fixed by mirroring the collector's rule and pinned by a test.

## What it cannot see

Not connected: polling keyloggers (Windows does not log `GetAsyncKeyState`), BitBlt/DXGI screen capture,
clipboard listeners, who called `SendInput`, local staging writes, beacon timing, kernel-level hiding.
Consent-store history says a capability was used, not what was done with it. A valid signature proves
a publisher identity, not benign behaviour. No live positive control was run, and none should be run
against the protected user's data: registering a real hook records a genuine finding. Use the Forge.

## Reconsider when

- A corpus or live false-positive appears that the category table cannot express (extend the table
  or add per-owner approvals bound to a hash, not a name).
- The advisory separates controls from explained look-alikes on a corpus large enough to justify a
  bounded role, measured with `jarvis reason calibrate`.
- A supported kernel sensor exists: then contradictions can be corroborated below user mode.
- Idle cost matters: the run is on demand (about 25 s with `--deep`); scheduling needs a measured budget first.

## Sources

Windows: `spy_evidence.ps1` (identity, Authenticode, window state, capture-consent history, autostart,
external connections), the elevated broker's Win32k hook inventory, the hidden-process cross-views.
Linux: `/proc` and `/sys` metadata only (capture devices, image state, egress), no command lines or paths retained.

## Isolated positive-control plan (next validation gate)

Jev and the measurements agree the largest remaining gap is that nothing real has exercised the sensors.
These scenarios need a disposable Windows VM and a disposable WSL distribution with no personal data,
no real accounts and no route to the protected host. Safety tier `isolated_emulation`; never run live
against this machine. Each scenario records telemetry expected, the verdict expected, the maximum
detection latency and the recovery, and a miss becomes a permanent regression case in
`jarvis/core/reasoning/corpus.py`.

| Emulation (benign payload, real mechanism) | Expected evidence | Expected verdict | Max latency |
| --- | --- | --- | --- |
| Low-level keyboard hook registered by an unsigned test binary | Win32k audit row, hook type 13 | `UNEXPLAINED_CAPABILITY` alone; `SUSPECT_CHAIN` with autostart plus outbound loopback-to-VM connection | next audit refresh |
| Same binary polling `GetAsyncKeyState` in a loop | none (documented blind spot) | `NO_SIGNAL` with the blind mechanism listed | n/a: must stay honest |
| Microphone open by a test executable outside any product path | consent-store row for that path | `UNEXPLAINED_CAPABILITY` | next collection |
| Process unlinked or hidden by a test driver (VM only) | cross-view contradiction | `VISIBILITY_CONTRADICTION` | one deep scan |
| Linux process reading an evdev device, then deleting its own image | `/dev/input` fd, deleted image | `VISIBILITY_CONTRADICTION`, depth 3 awaits authorization | one scan |
| Signed remote-support tool installed by the test harness | valid signature, injection, screen | `EXPECTED_DUAL_USE`, never a chain | one scan |

Detection latency is measured from the emulation start to the report, on the VM, with idle CPU, RAM and
disk-write cost of a run recorded. Until these exist, the register keeps this capability `partial` and
without validated containment.

## Linux lab: built and running (2026-09-30)

`jarvis/lab/vmlab.py` + `jarvis/lab/spyware_controls.py` + `jarvis/lab/guest/` implement the Linux half.

**Isolation** (each point has a test in `tests/test_vmlab.py`): one disposable QEMU/KVM guest inside a
locked-down Docker container — `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`,
non-root, `--read-only` root filesystem, only `/dev/kvm` passed through, a copy-on-write overlay over a
read-only base image whose SHA-256 is checked against Ubuntu's GPG-signed `SHA256SUMS` before every run
and re-verified after. The guest's own NIC is `restrict=on` (reaches nothing outside the guest). No shared
folders, no audio/video passthrough. The container and its run directory are removed on every exit path,
including helper failure and timeout, and disposal is verified, not assumed.

**Authority**: the host never executes emulator code. A small tar (the exact `spy_linux.py` under test,
plus the emulators and a runner) is attached as a read-only virtio block device and extracted inside the
guest by its own cloud-init `runcmd`, which also marks the guest `/etc/jarvis-arena-sandbox` first
(`jarvis/lab/isolation.py`'s existing sandbox marker). The guest's result is delivered back over the serial
console as base64 + a SHA-256 digest between fixed markers; `parse_serial()` rejects anything oversized,
non-base64, hash-mismatched, or shaped wrong, and the caller diffs `files_sha256` against what was actually
shipped so a guest running different code is reported, never trusted.

**Politeness**: `blockers()` refuses to start under CPU pressure (`/proc/pressure/cpu` avg60 > 40% by
default), low available memory or low disk, and unknown load blocks rather than assuming idle. The
container runs at low CPU-share weight and a pid limit.

**Controls** (`jarvis/lab/spyware_controls.py`): 7 Linux scenarios — a process running from a deleted file,
one executed from a memfd, three that hold a capture-capable device (keyboard event, microphone PCM,
`/dev/uinput`) with and without a deleted image, and a clean-process false-positive guard. Each states its
expected fact kinds, expected verdict, max latency and recovery (`terminate the emulator; guest discarded`).
`evaluate()` scores real guest evidence through the actual `jarvis.core.reasoning.engine` — not a
re-implementation — so a control only "detects" when the same code path used in production reaches the
right verdict with every expected fact present. A control that names a device the guest doesn't offer is
`skipped`, never silently passed.

**What the guest actually offers** (measured, this environment): QEMU's virtio-input and virtio-sound
devices give a keyboard event device and `/dev/uinput`; no capture-mode PCM device is present in this
minimal cloud image, so the microphone-capture control (`L05`) reports `skipped`, honestly, rather than a
false pass.

**A real bug the first attempt caught**: the initial `-drive ...,if=virtio,format=raw,readonly=on,serial=`
syntax is invalid — QEMU's `raw` format driver does not accept a `serial` option at that layer. Fixed to
the explicit `-drive id=...,if=none,... / -device virtio-blk-pci,drive=...,serial=...` form and confirmed
live before rerunning the orchestrated flow.

**A real false positive the lab caught, on the clean guest itself**: the first two full runs both flagged
the guest's own `systemd-logind` — a legitimate daemon, not an emulated control — as `UNEXPLAINED_CAPABILITY`
for holding a keyboard event device. That is exactly logind's documented job (`logind.conf`'s
`HandlePowerKey`/`HandleLidSwitch*` watch the power and lid-switch input devices), and it happened because
the Linux evidence path had no equivalent of the Windows category-explanation system (Linux has no
Authenticode signature to anchor identity to). Fixed with a narrow, justified addition —
`knowledge.LINUX_OS_COMPONENTS`, a reviewed name-to-specific-capability map, gated on `path_class == "os"`
(the kernel-verified `readlink()` target, not a self-reported name) — covering exactly `systemd-logind` →
`cap.keyboard.evdev` and nothing wider. A test pins that every name in that map is also in
`vocab.LINUX_SYSTEM_NAMES` (the same anchor masquerade detection uses), so the two can't silently diverge.
Confirmed live on the third run: the clean-guest baseline flagged nothing.

**Verified live, four independent runs** (`jarvis reason controls linux --json`), all fully reproducible:

| Run | detected | skipped | clean_ok | max latency | clean-guest false positives |
| --- | --- | --- | --- | --- | --- |
| 1 (pre logind-fix) | 5/6 testable | 1 (no sound device) | 1/1 | 61 ms | 1 (`systemd-logind`) |
| 2 (pre logind-fix) | 5/6 testable | 1 | 1/1 | 62 ms | 1 (`systemd-logind`) |
| 3 (post logind-fix) | 5/6 testable | 1 | 1/1 | 26 ms | **0** |
| 4 (post decoding-fix, below) | 5/6 testable | 1 | 1/1 | 122 ms | **0** |

Every run: all 4 testable `VISIBILITY_CONTRADICTION`/`UNEXPLAINED_CAPABILITY` controls detected with every
expected fact present, the depth-3 case (`L04`, a deleted keyboard-reading image) correctly produced
`needs_human: true` and never auto-escalated further, the clean-process guard stayed `NO_SIGNAL`, and
isolation held: container removed, run directory removed, base image checksum unchanged. `L05` (microphone)
is honestly `skipped` because this minimal cloud image offers no capture-mode PCM device — recorded as a
coverage gap, not folded into the pass count.

**A second real bug, caught by the project's own hygiene tests, not the lab**: the full suite (1854 tests)
first ran with 2 failures — `tests/test_decoding.py`, which statically scans every collector for
`open()`/`subprocess.Popen(text=True)` calls missing `errors="replace"` (a single non-UTF-8 byte from
untrusted input otherwise crashes the reader; this exact pattern took a production collector down on
2026-09-07, per that test's own docstring). It correctly caught 3 sites in the new guest code
(`lab/guest/linux_run.py:62,122,132`, `lab/vmlab.py:184`) — none of the 127 tests scoped to files I'd
touched happened to include that project-wide static-analysis test. Fixed at all 4 sites, confirmed with
`ast`-level syntax checks, the targeted tests, a 4th live guest run (table above, unaffected), and a final
full-suite rerun.

## Windows lab: designed, blocked on one owner action

Windows Sandbox is **not installed** on this host (`WindowsSandbox.exe` and `wsb.exe` are both absent).
Enabling it needs an elevated command (`DISM /online /enable-feature /featurename:Containers-DisposableClientVM
/all` or the equivalent optional-feature toggle) and likely a reboot — something only the owner can do.
This build (26200, 24H2+) supports the `wsb.exe` CLI (`start --config`, `exec --run-as System|ExistingLogin`,
`share`, `stop`), which is how the host would drive it without ever touching the interactive session.

**Emulator design, deliberately narrow.** A first attempt to write the hook/key-polling/screen-capture
emulator as raw Win32 P/Invoke source (`SetWindowsHookEx` + `GetAsyncKeyState` + `BitBlt`, even as inert,
commented, harmless stubs) was stopped by a safety classifier mid-generation: that source shape pattern-matches
real keylogger and screen-spy implementation code regardless of stated intent, and is not being retried, in
any rewording. The design changes accordingly to use only **already-signed, already-existing software**,
never code I author that implements a capture mechanism:

- **Hook control (W01/W02)**: install AutoHotkey (signed, already a documented known-sender in
  `jarvis/collectors/host/inputwatch/forensics.py`'s `_KNOWN_SENDERS`) and run a two-line script —
  `#UseHook` (a standard, documented AHK directive) plus one no-op hotkey. AHK's own compiled engine
  registers the low-level hook; nothing I write touches a key event.
- **Masquerade control (W03)**: copy an existing signed Windows binary (e.g. `timeout.exe`) to a temp path
  under the name `svchost.exe` and run it. A file copy and rename, no new code.
- **Known-blind controls (W04 polling, W05 BitBlt)**: left as asserted gaps backed by the existing measured
  finding (`docs/security/WIN32K-INPUT-AUDIT` note, measured 2026-09-23: `GetAsyncKeyState` is not logged),
  not re-implemented as live emulation. Closing this pair would itself require writing the exact capture
  code the classifier already declined; if it's ever done, it should be reviewed deliberately and separately,
  not folded into an automated lab run.
- **Clean control (W06)**: run an ordinary signed binary and expect silence.

**Next owner action**: run the elevated one-time setup (feature enable + reboot). After that,
`jarvis reason controls windows` (not yet built) would drive `wsb.exe` the same way `vmlab.py` drives QEMU:
same isolation invariants (a `.wsb` config with `<Networking>Disable</Networking>`, no mapped folders,
`<ProtectedClient>Enable</ProtectedClient>`), same untrusted-output parsing, same governor.
