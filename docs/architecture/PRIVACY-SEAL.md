# Privacy seal: microphone, camera and the peripheral consent surface

Written 2026-10-21. Owner request: "seal off completely intrusions through the
mic and the rest of a laptop's vulnerabilities". The Maximum Assurance
directive forbids claiming complete coverage, so this records what is sealed,
how it is enforced, how drift is seen, and what stays open.

## What JARVIS already observed before this change

- `controls` (5 min): the Windows capability ledger with a stop time of zero
  (an app holding the mic/camera/screen-capture grant right now), device
  arrival and removal.
- `spy` (90 min): every ledger entry with start and stop times, unsigned
  autostarts, hooks, WSLg checks.
- `audio` (5 min): Core Audio endpoints, six role defaults, render sessions
  and a beep sampler. Capture sessions were collected but never reported.

None of these read or enforced the *access posture*: the global and
desktop-app consent values, machine-level overrides, Group Policy forcing, or
device state. A spyware author who flips a toggle back on was invisible, and
the owner had no reversible way to close the surface from JARVIS.

## Design chosen

1. A read-only collector `privacy` (`jarvis/collectors/host/privacyseal.py`,
   `jarvis/platform/win/privacy_seal.ps1`, 5 min, Windows-only) reads the
   consent store for microphone, webcam, location and both screen-capture
   capabilities in the user and machine hives, the AppPrivacy policy values,
   present camera and Bluetooth devices, and the MMDevices capture endpoint
   states (masked to the low nibble; loopback endpoints such as Stereo Mix
   named).
2. An owner-declared **seal** stored in the JARVIS store. `jarvis privacy
   seal` writes Deny to the user-hive global and desktop-app values for the
   microphone and camera through a separate write-only script that accepts
   only an allowlisted capability and Allow/Deny from stdin, reads the values
   back, and records the previous values as the rollback. `jarvis privacy
   unseal` restores exactly those values. The daemon never calls the write
   script.
3. Drift detection: while sealed, any sealed value that reads back as not
   Deny, a policy value forcing Allow, or a ledger entry whose start time is
   after the seal, is a high finding. A capture session with process identity
   in `audio` is medium normally and high while sealed. A setting flip between
   samples while unsealed is medium and never attributed.

Alternatives weighed: (a) folding the posture read into `controls`; rejected
because a seal drift must survive a failing device inventory and be its own
collector health signal. (b) Disabling the devices (Disable-PnpDevice);
rejected for now because it needs the elevated broker, and a disabled device
also blinds the ledger and the session evidence. It remains the right next
rung for an owner who wants hardware-level closure. (c) A time-bounded auto
unseal from the daemon; rejected because it would give the daemon write
authority over the consent store.

## Invariants

- The daemon path is read-only on Windows; only the owner CLI writes, after
  explicit confirmation, and every write is read back and recorded with its
  rollback before success is reported.
- Nothing from the registry is interpolated into a command line; the write
  payload travels on stdin and is validated against a fixed allowlist on both
  sides.
- Unreadable sources are reported as visibility loss, never as clean, and the
  previous evidence is kept.
- Drift is reported as unattributed; the collector never claims who changed a
  value.
- Severity: posture the owner has not sealed is low (informational) and does
  not move the score; a broken seal or capture during a seal is high.
- Emergency communication: sealing is explained before it happens (calls lose
  the microphone), is reversible with one command, and is never automatic.

## Blind spots, stated

- The consent gate is enforced by Windows user-mode services. A program using
  kernel streaming directly, a driver, or an administrator rewriting the
  registry is not stopped; the last is seen as drift within five minutes.
- Sysmon on this host records no ConsentStore registry writes, so drift has no
  writer attribution yet.
- WSL has no consent store; the Linux side is covered only by `spy`.
- A hardware kill switch or firmware disable is stronger than any of this.
- Not live-verified at the time of writing: the seal's effect on a real
  capture attempt. The read path was validated against the live host.

## Measured 2026-10-21

- Live read-only run from the checkout: 2.5 s, no errors, 14 capture endpoint
  rows (two Stereo Mix loopback endpoints active), 1 camera, 1 Bluetooth
  adapter, consent ledgers of 20 (microphone), 12 (camera), 25 (location)
  entries. Host posture: microphone and camera Allow for global and desktop
  apps in the user hive; HKLM location Deny; no AppPrivacy policy; build 26200.
- 20 unit tests in `tests/test_privacyseal.py` cover drift, use after seal
  (once for a finished use, every pass for a held grant), policy override,
  flips between samples, invalid and partial snapshots, readback mismatch
  failing closed, CLI refusing off a terminal, and the audio collector's
  capture-session severity under a seal.
- Jev (jev-1.13.0) advisory, metadata only: chose the collector-plus-CLI design
  (1.0), judged low severity for an unsealed open posture 0.66 yes, high for a
  ledger entry after the seal 0.72 yes, staying unverified until a live capture
  attempt is observed 0.65 yes, and ranked repeat noise as the risk most
  deserving a deterministic test (0.52). The once-only report of a finished use
  and its test were added in response. Jev has no authority over any of this.

## Still open

- Apply the seal on the live host and observe a real capture attempt fail
  (owner decision: it mutes calls until unseal). Until then the capability
  stays `unverified` in assurance.py.
- Writer attribution for consent-store drift needs a Sysmon registry rule for
  the ConsentStore key family.
- Device-level closure through the elevated broker.
