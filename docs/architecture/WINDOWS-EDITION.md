# ARGUS-INSTINCT for Windows: the native edition (2026-11-03)

Owner decision, 2026-11-03: build the native Windows engine into the signed pipeline before the
ARGUS-INSTINCT release, so a Windows PC without WSL gets a working product, not a front end
without an engine. Status: **built, never run on a Windows machine yet**. The first evidence
will be the `windows-install-test` job of a release dry run (below). `native_host_portability`
stays `unverified` until that run and a soak exist.

## What a person downloads

| Computer | Download | What it installs |
|---|---|---|
| Windows 10/11 PC (no WSL needed) | `ARGUS-INSTINCT-Setup-windows-x64.exe` | Per-user engine + desktop app, a per-user service task, Start menu entry. No administrator. |
| Same, manual or scripted | `argus-instinct-windows-x64.zip` | The same engine; `engine\argus-instinct.exe native install` |
| Windows with the engine already in WSL | `argus-desktop-windows-x64.exe` | The desktop app only, talking to the WSL engine |
| Linux server, VM or container host | `argus-server_<v>_amd64.deb` or `argus-server-linux-x86_64.tar.gz` | The native server engine (systemd) |
| Linux desktop | `argus-desktop_<v>_amd64.deb` (+ the server package for the engine) | Desktop app |

The engine adapts to the computer it runs on: `platform/host.py` decides the observable
domains (Windows, WSL, Linux), `platform/facts.py` the Linux facts (distribution, init,
containers, BTF...), and `service/schedule.applicable` lists everything that does not apply
as "not on this host: ..." instead of running it or calling it healthy.
`welcome` (no argument) prints the first-run statement for the detected kind:
`windows`, `desktop` (WSL) or `server`.

## Invariants

1. **Binary only.** No `.py`, `.pyc`, `.ps1` or `.cs` in any download; the content gate
   (release/policy.json, deny by default) refuses scripts, source, home-folder and CI paths,
   and anything not on the artifact's allow list. The Setup is opened with 7z and gated too.
2. **Compiled payloads win.** The PowerShell payloads are compiled into the engine
   (`argus/core/_payloads.py`, generated at build time). `core/paths.py` prefers the compiled
   copy over any file of the same name, so a script planted beside the program cannot
   replace one; a payload the edition lacks still throws, so a collector reports itself
   unavailable rather than clean.
3. **Byte-exact, per release.** Payloads that something runs as a file (the service task,
   the broker, the input hook) are written byte for byte, through a temp file and a rename,
   into `%LOCALAPPDATA%\Argus\Payload\<set digest>`; two releases never share a folder. An
   unwritable profile never stops an import; that one collector reports unavailable.
4. **The audit sees the real script.** The control audit fingerprints the compiled copy
   (`paths.shipped_script`), so the installed supervisor is not reported as changed.
5. **Exact process identity.** The service loop (`argus-native-service.ps1 -Engine`) only
   adopts or stops a process whose executable path is exactly the configured engine and
   whose command line runs `serve`.
6. **No elevation, one install.** `native install` registers a per-user task (RunLevel
   Limited) and changes no Windows setting; it refuses when another ARGUS daemon answers on
   the default port (for example the WSL edition) and the Setup refuses beside an old
   2026.10 Argus install.
7. **Pairing stays private.** The desktop token is written owner-only into the app's config
   folder, never printed or put on a command line; a valid token is kept on reinstall;
   uninstall revokes only that client. The port goes into a `port` file beside it.
8. **Uninstall keeps evidence.** Task, program, payload folder, uninstall entry, Start menu
   entry and token are removed; `~\.argus` (history, baselines, acknowledgements) stays
   until the person deletes it, and the uninstaller says so.
9. **Built from what was recorded.** The Setup is made only from an engine zip and desktop
   exe whose version, commit and SHA-256 match their build records; each CI job verifies
   the previous job's digests before using its output.

## Designs compared

| Design | Verdict |
|---|---|
| **Compiled engine, payloads compiled in, per-user Setup (chosen)** | Same code as every edition; meets "binary only"; no elevation; uses the tested service loop; one CI job adds the clean-machine evidence. |
| Ship the `.ps1` payloads as text in the download | Simplest, but breaks the owner's binary-only rule and lets a file on disk override a payload. Rejected. |
| Rewrite the service loop in Python inside the engine | Removes the last `.ps1` on disk, but duplicates a supervised, audited, fingerprinted component that already has a restart budget and identity checks. Not now; reconsider with Authenticode signing. |
| Bundle an embedded Python + bytecode (the 2026.10 Argus zip) | Bytecode decompiles to near source; that build leaked source once. Rejected. |
| Tauri sidecar (the desktop app starts the engine) | Ties protection to the window being open; the service would stop when the app closes. Rejected. |

## Not in this edition (said in the app and in `welcome`)

- The elevated event sensor (`windows-sensor`): its installer compiles C# on the target from
  a checked source hash in an elevated shell; shipping a prebuilt sensor changes that
  elevated path and gets its own review.
- The elevated broker and the keyboard-hook watcher task.
- Authenticode signing: SmartScreen warns and ASR prevalence rules (as on the owner's PC)
  block the unsigned Setup until a code-signing certificate exists.

## Evidence plan

1. `release-test/*` dry run: `engine-windows` (Nuitka, smoke incl. a compiled payload run
   through PowerShell and the program's own verification), `windows-setup` (gate via 7z),
   `windows-install-test` on a clean windows-2025 runner: silent install, task and health,
   applicability readback (Linux-only audits listed as not applicable), a positive control
   (a planted per-user Run-key entry absent before, found while planted, gone after),
   silent uninstall and a leftovers check.
2. A real Windows 11 VM without WSL: install from the published Setup, a day's soak with
   CPU/RAM and collector receipts, update over the top, uninstall.
3. Only then can `native_host_portability` move from `unverified`.

## What would make us reconsider

Code signing (then ship signed `.ps1` and a Python-free supervisor), a measured payload
write failure rate on real profiles, a need for elevation-only detections in the default
edition, or the clean-machine run showing the engine cannot hold its CPU/RAM budget.
