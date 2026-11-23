# Memory defense: what JARVIS checks against in-memory attacks

Written 2026-10-21 after the owner asked for protection against memory attacks.

## Already in place before this change

- **Memory scan** (`memscan`, elevated broker): executable private memory no
  file backs, hooked ntdll syscall stubs, per-process CFG/ACG/CET, and in this
  checkout (unreleased) whole PE images in private memory (reflective loading,
  manual mapping, in-memory .NET assemblies).
- **Sysmon rules**: remote thread creation (8), LSASS access with the granted
  mask split into memory-read versus query-only (10), process tampering (25),
  unsigned image loads and side-loads (7).
- **Posture**: VBS, Memory Integrity, Credential Guard, LSA protection, key
  ASR rules including LSASS credential theft and vulnerable drivers.
- **Evasion**: driver blocklist, abused-driver list, attempts to blind defenses.

## Added

A `memory defense` posture section reading the system-wide exploit mitigation
defaults (DEP, SEHOP, bottom-up/high-entropy/mandatory ASLR, CFG, user shadow
stacks), kernel shadow stacks, WDigest plaintext retention and the LSA UEFI
lock. OFF is medium or high; the Windows default is a low "pin" with the exact
command; an unreadable value is visibility, never off. ASR rules in audit or
warn mode are now reported separately from rules that block.

Live values 2026-10-21: DEP, SEHOP and CFG at default; ASLR fully on; user
and kernel shadow stacks off; LSA protection and Credential Guard on; WDigest
unset; three ASR rules audit-only, eight not configured. The section ran from
the checkout against the live host in 14 s and produced only low findings.

Jev (jev-1.13.0, metadata only): chose the posture section over extending the
memory scan (1.0); agreed low for defaults (0.70) and for the system-wide
shadow-stack default given memscan's per-process medium (0.75). It judged the
broker-ordering risk unlikely (0.26); the code says otherwise
(`jarvis/platform/broker.py` `result()` refuses a drifted script), so the
ordering warning in the pending-actions guide stands. Jev has no authority.

## Not covered

- A mitigation reported ON is configuration, not proof the CPU enforces it;
  CET capability is not read.
- No exploit has been run against this host; nothing here is measured
  prevention.
- Polling keyloggers, direct kernel-streaming capture and kernel-mode implants
  below the sensors remain blind spots recorded elsewhere.
