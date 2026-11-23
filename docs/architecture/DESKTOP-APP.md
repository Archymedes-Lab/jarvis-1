# JARVIS as a desktop app: architecture

Status: proposal 2026-09-16; shell built 2026-09-25 (v1, showed the daemon's page);
v2 with its own bundled interface built 2026-10-22/23 (see the last section).

The goal: JARVIS always open on the desktop, telling you what it sees as it
sees it, with everything the CLI and dashboard can do.

## The rule that shapes everything

**The app is a client, never the monitor.** `jarvis serve` keeps collecting,
responding and emailing whether or not a window is open, and closing the app
must never blind the machine. Anything the app alone can do is a feature that
disappears the moment you quit it — so the app renders state, and the daemon
owns it.

That also decides where work happens: no collector, no rule and no response
action moves into the UI process.

## What "always open" needs, beyond the current page

The dashboard already exists as a local web page served by the daemon. A
desktop shell adds only the things a browser tab cannot do:

| capability | why it needs a shell |
|---|---|
| Tray icon with the live score and worst finding | a tab cannot live in the tray |
| Native notifications for criticals and outages | browser notifications need a focused origin and are easy to lose |
| Start with the session, single instance, restore last view | a tab does not survive a reboot |
| Global hotkey ("what changed?") | needs an OS-level hook |
| Window that cannot be navigated away | the shell pins one origin |

## The shell: Tauri (decided 2026-09-16)

**Tauri 2** (Rust shell, uses the system WebView2 on Windows).
A ~5 MB binary, one process tree, no bundled browser, and a small dependency
set — which matters for a tool whose own audits flag unsigned binaries,
unexpected autostart entries and supply-chain risk. JARVIS shipping hundreds
of npm packages to display its own findings is the kind of thing JARVIS
reports on.

**Electron** was the alternative, and would have been a reasonable choice for
its richer native API surface and familiar toolchain. If it is ever picked up
instead, these are the terms:

- a bundled Chromium per install (~150 MB) and a large npm dependency tree —
  pin with a lockfile, vendor it, and review updates like any other supply
  chain;
- `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, and the
  page's existing CSP kept as-is: the renderer shows a local page and needs no
  Node;
- no auto-updater phoning home — JARVIS updates by `git pull` like the rest;
- ASAR integrity on, so the app's own files are fingerprinted the way JARVIS
  fingerprints its scheduled-task scripts.

Either way the UI is the same web app, so the choice stays reversible. A
stopgap costing almost nothing until the shell exists: install the existing
dashboard as a PWA (Edge "Install this site as an app"), which already gives a
window, a taskbar entry and autostart, and answers some of the shell-shaped
questions before one is written.

## Live insight instead of polling

The page polls `/api/state` every 5 seconds today. For an always-open window
that is both wasteful and slow to tell you something urgent. Add one endpoint:

- **`GET /api/stream`** — Server-Sent Events from the daemon: score changes,
  new findings above a threshold, collector state changes, defense-ledger
  entries, protocol state. SSE over the existing `http.server`, no new
  dependency, and the app falls back to polling when the stream drops.
- The app keeps a local cache so a restart redraws instantly, exactly as the
  page does from SQLite today.

## What the app shows

1. **The greeting**, as the dashboard chat now opens: blind collectors first,
   score and trend, what needs you, today's protocol and its question.
2. **Protocols** as a checklist: steps, the Yes/No question, `brief check`
   as a button, and progress toward the projected score.
3. **Findings** with the existing triage grouping (you act / you confirm /
   JARVIS handles), filters and evidence.
4. **Ask JARVIS** — the same read-only assistant, with the local model for
   open questions.
5. **Defense ledger** — what JARVIS did and the undo for each.
6. **Tray**: score, worst open finding, "run all", "open dashboard".

## The mutation boundary stays where it is

The app may: ask, acknowledge with a reason, answer protocol questions, run a
collector, approve or undo a *proposed* action — each one an explicit click
that calls the existing local API, which keeps its host and same-origin checks.

The app may not: change config, run arbitrary commands, or act on model output.
As with messaging, text from the local model has no route to any of these.

## Packaging and trust

- Built from this checkout, unsigned to begin with — and therefore visible to
  JARVIS's own "recently written unsigned executable" rule, which is the
  correct outcome for a binary you built yourself. Sign it when convenient.
- Autostart via a scheduled task registered the way `JARVIS input hook` is, so
  the control audit verifies it by definition and fingerprint instead of
  trusting a name.
- The window binds nothing: it talks to `127.0.0.1:8787`, which stays
  loopback-only.

## Phases

1. **Stopgap:** install the dashboard as a PWA, add the tray-shaped needs to
   the list of what is actually missing.
2. **Stream:** `/api/stream` plus an SSE client in the page — the biggest
   single improvement, and it benefits the browser too.
3. **Shell:** the Tauri window, tray, notifications, autostart and
   single instance.
4. **Native touches:** global hotkey, jump list / quick actions, per-finding
   deep links.

## Open questions

- Windows only, or the WSL side too (a Linux build would need a separate
  shell)?
- Should the app show the keystroke-monitor state as a tray colour, given it
  is the one component that can be blind while everything else looks fine?

## v2: the app has its own interface (2026-10-22/23)

Owner request: move the interface to a desktop framework with a very clean design
system. v1 pointed the Tauri window at the daemon's web page; v2 bundles its own.

### Stack

| Layer | Choice | Why |
| --- | --- | --- |
| Shell | Tauri 2.12.5 (Rust, WebView2) | already chosen; ~MB binary, no bundled browser |
| Interface | Svelte 5.57 + Vite 8.3 | compiles to plain JS; no runtime framework |
| Styling | Tailwind CSS 4.3.3 (`@tailwindcss/vite`) | tokens in `@theme`, components in `@layer` |
| Primitives | bits-ui 2.19.5 | headless, accessible dialog, select, toggle group, tooltip, command palette; styled only by our system |
| Icons | @lucide/svelte 1.54.0 | per-icon imports |
| Type | Inter 4.1 variable (OFL), bundled | optical sizing gives the display cut for headings |

Every JS and crate version is pinned exactly. Libraries are pinned to the newest release at
least two weeks old at the time of choosing.

### Design system (desktop/ui/src/app.css)

- Geist-style scales: neutral grey 100 to 1000 where each step has one job (100 to 300
  backgrounds, 400 to 600 borders, 700 to 800 fills, 900 secondary text, 1000 primary text),
  and blue, red, amber and green scales on the same steps.
- Perceptual colour (OKLCH), as Linear's theme system: equal steps look equal in every hue
  and in both themes; greys carry a faint cool cast; one accent.
- Type scale named like Geist (`text-heading-32` ... `text-copy-13`), tracking tightening with
  size. Apple's layering: sidebar and toolbar are a quieter frame around the content; only
  the floating toolbar uses a translucent material.
- Light, dark and automatic themes; the choice is per machine (localStorage).

### Trust boundary

The interface is a page from `tauri://localhost`, cross-origin to the daemon on purpose.

- It reaches JARVIS only through seven Rust commands (desktop/src/api.rs): daemon state,
  daemon status, run a collector, answer a question, ask, score coach, fix decision.
  `build.rs` declares exactly these; `capabilities/main.json` grants them plus event
  listening to the main window and nothing else (no HTTP, file, shell or window API).
- Each command validates its arguments against the daemon's own formats (job names, question
  ids, `fx-` ids, yes/no) and makes one bounded loopback request (8 MB body limit, header
  limits, no chunked encoding, timeouts). Tests cover hostile responses.
- The API token is the one the daemon gives its own page as a cookie; Rust holds it and the
  page never sees it. A refused token is refreshed once (the daemon issues a new one per start).
- The app may approve, retry or reject a fix proposal. Authorising a patch is deliberately not
  offered: that stays a terminal (or dashboard) step.
- Content policy: `default-src 'self'`, `connect-src ipc: http://ipc.localhost`, no objects,
  no frames, no forms; the window may only show the bundled interface.

### Build

```
cd desktop/ui && bun install && bun run check && bun test src/lib && bun run build
cd desktop && cargo test -j 2            # Linux, debug
desktop/scripts/build-windows.sh            # Windows binary, cross-built in WSL (below)
```

A release binary must be built with `--features custom-protocol` (what `tauri build` adds
implicitly). Without it Tauri compiles in development mode whatever the optimisation level,
so `main.rs` refuses to compile a release that lacks it.

Build at low priority and two jobs on this machine: on 2026-10-23 a parallel release build
plus a development server ran while the VM was already saturated, the daemon went silent and
was restarted three times, and the VM restarted at 00:32.

### Verification (2026-10-23)

- Rust: 28 tests pass, including the client against a fake daemon on a real socket (stalled
  peer times out, hang-up mid-headers, oversized body refused before reading, nothing
  listening, Host and token headers exactly as intended).
- Interface: svelte-check clean, 7 model tests, production build 78 KB JS and 8 KB CSS
  (compressed) plus the font.
- Production bundle screenshot under the app's exact content policy with a mocked IPC, every
  view in both themes. The only refused declaration is bits-ui's command-list height variable
  (`style-src-attr`), which the palette does not use; the policy stays without
  `'unsafe-inline'`.
- Capability audit from the generated schemas: one local capability on the main window with
  the seven commands and event listen/unlisten; the app manifest defines exactly those seven;
  no plugin, window, webview, path or menu permission is granted to the page.
- Jev (metadata only): dependency set acceptable 0.86; boundary sound 0.62; inline styles
  0.54 (then removed); first check capability audit (done) then hostile daemon (done).
- Windows release binary: done the same day by cross-compiling (see Windows readiness). Two restarts during builds on 2026-10-23 (00:32
  guest shutdown during a parallel release build and dev server; 00:48 a full Windows reset,
  Kernel-Power 41, the same signature as the week's unexplained resets) mean the heavy build
  waits for an idle machine.

## Windows readiness (2026-10-23)

### Measured: this machine cannot build Rust natively on Windows

Defender's ASR rule 01443614 ("block executables unless they meet a prevalence, age or
trusted-list criterion") is in block mode. A one-file probe crate built with the Windows cargo
failed at its first build script: `build-script-build.exe` "Access is denied", Defender event
1121 for that rule (2026-10-23 22:37 UTC). Tauri's dependency tree runs dozens of build
scripts, so the earlier "robocopy, then `cargo build` on Windows" instructions could never
have worked here. The same rule blocked the native sensor (39 blocks of freshly built
executables are in the Defender log since April).

Options compared:

| Option | Build-time exposure | Verdict |
| --- | --- | --- |
| Native Windows build with an ASR exclusion for the build folder | an exclusion on a user-writable folder: any low-prevalence program dropped there runs | rejected |
| Native build in an admin-only folder, elevated | 400 crates' build scripts run as administrator | rejected |
| **Cross-compile in WSL** (build scripts run as Linux programs) | none on Windows; only the finished binary needs admitting | **chosen** |
| cargo-xwin (downloads the MSVC CRT and SDK) | none, but a download and a licence acceptance | unnecessary: the same libraries are already installed on C: |

### Build: `desktop/scripts/build-windows.sh`

Uses only what is on the machine: rustc's `x86_64-pc-windows-msvc` std (added with `rustup
target add`, removed with `rustup target remove`), `rust-lld` as the linker, clang as
clang-cl and llvm-rc/llvm-lib from LLVM 18, and the libraries and headers of the installed
Visual Studio Build Tools (MSVC 14.44) and Windows SDK 10.0.26100, linked space-free under
`~/.cache/jarvis-xwin`.

1. Idle gate: one-minute load at most 0.5 per CPU, at least 3000 MB available, 8 GB free on
   C:. Otherwise it refuses (exit 2); `--force` overrides and the receipt records it.
   `--check-only` runs the gates and the toolchain probe and stops.
2. Refuses a stale interface (`ui/dist` older than `ui/src`): cargo embeds `ui/dist` as is.
3. `cargo build --release --locked -j 2 --target x86_64-pc-windows-msvc --features
   custom-protocol` at nice 19 and idle I/O. Available memory is sampled every 5 s; three
   samples in a row under 700 MB stop the build (exit 3).
4. Hands the binary, icon and `build-receipt.json` (SHA-256, size, minutes, toolchain, commit
   and uncommitted file count, readings, lowest available memory, forced) to
   `%LOCALAPPDATA%\JarvisDesktopBuild`.

### Measured on Windows (2026-10-23, build 3f340bb2…5d)

- 3.9 MB x64 GUI-subsystem executable with manifest, icon and version resources; imports only
  Windows system DLLs (no VC runtime or WebView2 loader DLL to ship). Built in 7.9 min at
  nice 19, two jobs; lowest available memory 3038 MB.
- Launched unelevated from `%LOCALAPPDATA%\JarvisDesktopBuild`: **not** blocked by the ASR rule
  (no event 1121), window "JARVIS" visible, one WebView2 child, an established pulse connection
  127.0.0.1 → 127.0.0.1:8787, and the Overview rendered live state (score, criticals, areas,
  review queue). Why the binary passed where build scripts and the sensor were blocked is not
  known; the rule may still block a later build, so the installer checks for it on launch.

### Install: `desktop/scripts/windows/install.ps1`

Current user, refuses an elevated shell, no network. Installs only a binary whose hash matches
its build receipt, then:

| What | Where | Why |
| --- | --- | --- |
| binary (hash-checked copy) | `%LOCALAPPDATA%\Programs\JARVIS\jarvis-desktop.exe` | the notification plugin uses the app's AUMID only outside `target\release` |
| AUMID registration | `HKCU\Software\Classes\AppUserModelId\local.jarvis.desktop` | Windows shows toasts from an unpackaged app only for a registered AUMID |
| Start menu shortcut | `Programs\JARVIS.lnk` | launcher |
| scheduled task `JARVIS desktop` | at logon, current user, interactive, limited, no time limit | starts in the tray (`--hidden`) |

It reads every item back (hash, registry, shortcut, task action, arguments, run level, owner),
writes `install-receipt.json`, fails if any read-back differs, launches the app and fails if
Defender logs a block for it or it is not running 5 s later. `-NoAutostart`, `-NoLaunch`,
`-Uninstall` (verifies nothing is left) and `-Purge` (also the WebView2 profile in
`%LOCALAPPDATA%\local.jarvis.desktop`). Removing the app never touches `jarvis serve`.

If Defender does block a build: the remedy accepted for the native sensor is one ASR-only
exclusion for one exact path in an administrator-only folder (`C:\Program Files\Jarvis\Desktop`),
malware scanning unchanged. That is an owner decision and is not scripted here.

What JARVIS reports about it, deliberately unsuppressed: the control audit lists
`JARVIS desktop` as an undeclared scheduled task (low), and the binary is a recently written
unsigned executable. Declaring the task in `jarvis/platform/provenance/persistence.py` needs a
task kind that fingerprints an executable rather than a PowerShell script, with the fingerprint
from a reviewed build shipped in a sealed release: a follow-up.

Run, after `bun run build` and `desktop/scripts/build-windows.sh` in WSL, from a normal PowerShell:

```
powershell -NoProfile -ExecutionPolicy Bypass -File \\wsl.localhost\Ubuntu\home\chris\jarvis\desktop\scripts\windows\install.ps1
```

WebView2 is not bundled (`webviewInstallMode: skip`): Windows 11 ships it, and it was present
here (155.0) on 2026-10-23.

## Update notice and "What Argus can see"

**Update notice.** The app tells a person when a newer release is published; it never installs one. The app
itself still makes no network request. It asks the service (`GET /api/update`, behind the same token as every
data route), and the service reads the public `manifest.json` from the release site
(`jarvis/service/selfupdate.py`; not `collectors/host/updates.py`, which lists outdated *other* software).
That is one plain GET with no identifier, no version and no cookie, cached six hours, and a failure is a quiet
"could not check". `ARGUS_UPDATE_CHECK=0` turns it off. The app compares the answer with the release it was
built as (`ARGUS_RELEASE`, set by `release/build_desktop.py`; a development build is "dev" and is never told
to update). The sidebar shows a notice and Settings > Updates shows both versions; the button opens a fixed
download page (`desktop/src/update.rs`), never an address taken from the service. Versions order by date, then
by the number of the release that day (`-0` and no suffix are both the first), as `release/versioning.py` does.
A binary built before this has no stamped version and cannot show the notice.

**What Argus can see** (the Coverage screen). One summary card (techniques, the proven / expected / blind spot /
got-worse split, hours watched), clickable attack stages, and a technique list that puts what needs a look first.
