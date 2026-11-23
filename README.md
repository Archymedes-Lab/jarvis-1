# JARVIS-1

The engine behind Argus (ARGUS-1, ARGUS-INSTINCT). The first version is [jarvis-origin](https://github.com/Archymedes-Lab/jarvis-origin).


Source-available preparation: project-owned material in this distribution uses
**PolyForm-Noncommercial-1.0.0**, with separate commercial permission for uses
outside its permitted purposes. This is **not an open-source license**. The
standard terms permit use by government institutions and listed nonprofit
organizations. Earlier AGPL grants remain valid; this change cannot remove
rights from earlier recipients.
See [licensing](LICENSING.md), [commercial permission](COMMERCIAL.md),
[governance](GOVERNANCE.md), [trademark policy](TRADEMARKS.md),
[security reporting](SECURITY.md) and [evaluations](docs/open-source/EVALUATIONS.md).
Publication and commercial-rights review remain in the
[readiness report](docs/open-source/READINESS-2026-11-17.md).

Monitors what runs on this machine — both the WSL2 Linux side and the Windows
host — and audits the ways something could take or keep control of it.

Pure Python 3 standard library. No dependencies, no agent, and no network calls
unless you ask for one — `--enrich`, the `intel` feeds, or email alerts once you
have put a Resend key in the config.

## Start here

The [Maximum Assurance governing directive](docs/security/MAXIMUM-ASSURANCE.md)
applies to the complete system. `/api/health` exposes a conservative `assurance`
register of implemented foundations and remaining blind spots; healthy collectors
do not prove absence of compromise or completion of the directive.

The [Defender Engine architecture and feature roadmap](docs/architecture/DEFENDER-ENGINE.md)
describes JARVIS's evolution toward native protection, durable incident memory,
data and identity defense, constrained response, and verified recovery. It
separates implemented foundations from proposed capabilities.

```bash
cd ~/jarvis
./install.sh --service   # run it 24/7, dashboard at http://127.0.0.1:8787
jarvis investigate       # or a one-off report in the terminal
```

## Cofounders: start here

For a cofounder or contributor on their own computer (Windows 11 with WSL2, or Linux).
The product is **ARGUS-INSTINCT**: its code lives here in
[Archymedes-Lab/argus-1](https://github.com/Archymedes-Lab/argus-1) and its site in
[Archymedes-Lab/argusinstinct](https://github.com/Archymedes-Lab/argusinstinct) (argusinstinct.xyz); the other
repositories are listed in [CONTRIBUTING.md](CONTRIBUTING.md#where-we-work).
How we work together (branches, reviews, agents, CI budget) is in [CONTRIBUTING.md](CONTRIBUTING.md).

**1. Get the code and check your setup** (inside WSL on Windows):

```bash
git clone https://github.com/Archymedes-Lab/argus-1.git ~/jarvis && cd ~/jarvis
git remote rename origin org
scripts/dev/bootstrap.sh        # tools, GitHub access, releaser key, git hooks, then the fast tests
```

**2. Use it to protect your own computer.** Pick one:

| You want | Do this |
|---|---|
| The product as customers get it | Install **Argus Desktop** from the site (Windows) and paste your licence key in **Licence**. Nothing from the checkout runs. |
| JARVIS from the checkout, running 24/7 | `./quickstart.sh` (systemd service, dashboard at http://127.0.0.1:8787, one UAC prompt for Windows hardening; `--no-windows` to skip it). See [QUICKSTART.md](QUICKSTART.md). |
| A one-off look, nothing installed | `python3 -m jarvis investigate` |

**3. Activate your licence.** Your key (`ARGUS-DSK-…`) is a complimentary grant handed to you directly, never by email
from the shop. In the desktop app: **Licence → paste → Activate**. From the checkout: `python3 -m jarvis licence activate ARGUS-DSK-…`,
then `python3 -m jarvis licence status`. To move it to another computer: `licence deactivate` on the old one first.
Detection never depends on the licence; it unlocks only the premium review report ([Licences and payments](#licences-and-payments-argus)).

**4. Everyday commands**, once it is running:

```bash
jarvis coverage        # is JARVIS itself running, current and not blind? (check this first)
jarvis investigate     # everything in one report
jarvis spy             # mic/camera use, keyloggers, screen capture
jarvis outstanding     # what was flagged and never resolved
jarvis defend          # proposed containment actions: approve or undo
jarvis ask "why is my CPU busy?"   # answers from current JARVIS data (local Ollama for open questions)
```

The full list is under [The commands](#the-commands). Phone alerts and approvals: choose **Pair a phone** in the dashboard
or the desktop app ([ARGUS-NOTIFY.md](docs/architecture/ARGUS-NOTIFY.md)).

**5. Develop.** Branch from `org/main` in its own worktree, one per agent or task:

```bash
git fetch org && git worktree add ~/.cache/wt/feat-x -b feat/x org/main && cd ~/.cache/wt/feat-x
python3 scripts/dev/fasttest.py           # changed tests only, scratch HOME, seconds
scripts/dev/static_gate.sh                # ruff, mypy, property and model checks
git push -u org feat/x && gh pr create    # pre-push hook runs the quick gate first; CI runs everything
```

Maintainers merge on green CI; external contributions need maintainer review. Trust anchors follow the owner review policy
([CODEOWNERS](.github/CODEOWNERS)). Agents read [AGENTS.md](AGENTS.md): on your machine they must not run the
owner-machine deploy steps it describes.

**6. Release.** Any one listed releaser signs: push to `release-test/<name>`, wait for the green **Release build**, then
`bash release/publish_dry_run.sh <run id>` on the machine holding your signing key ([Releasing](#releasing)).

## Releasing

Releases are built by CI only, never on a laptop. The current method: push
the commit to a `release-test/*` branch of Argus-1, wait for the **Release
build** run to go green (about 15-20 minutes), then on the releaser's machine:

```sh
bash release/publish_dry_run.sh <run id>
```

It gates and signs the run's release folder, publishes it to
www.archymedes.xyz and reads the live site back. The full rules, the tagged
release flow and rollback: [docs/guides/RELEASING.md](docs/guides/RELEASING.md).

## Fuzz testing

`tests/fuzz/` throws malformed and hostile input at the parsers an attacker can
reach: the release content gate, version tags, SSH and login logs, Linux Sysmon
and Windows event records, the software-update parsers, and the local API's
request and token handling. Each target runs in its own process with a temporary
HOME and a hard kill, so a hang still leaves a reproducer; nothing reads your data
or talks to the running service.

```sh
python3 -m tests.fuzz.run --budget-seconds 60      # all targets; --list, --target NAME
```

A run fails only on findings not yet listed in `tests/fuzz/known.json`.

**First results (2026-11-04, 21 targets, ~13 CPU-minutes):** 15 findings, 11
fixed with regression tests (`tests/test_fuzz_findings.py`), 4 open. Full write-up:
`tests/test_fuzz_findings.py` (regression tests for every finding).

| id | finding | severity | status |
|----|---------|----------|--------|
| FZ-04 | a local, unprivileged process can write a fake sshd "Accepted publickey" line to the journal and it counts as login evidence, teaching the baseline an attacker's network and key | high | fixed (non-root lines counted and reported, never evidence) |
| FZ-01 | a crafted `.deb` (negative member size) makes the release gate loop forever | medium | fixed |
| FZ-02 | a `.deb` with two data members: the gate checked the last, `dpkg` installs the first | medium | fixed |
| FZ-03 | a chosen SSH username (`bob from 203.0.113.9`) framed an innocent address in the login log | medium | fixed |
| FZ-06 | one malformed Linux Sysmon line dropped every event in its window; a 56 KB line took 7 s | medium | fixed |
| FZ-11 | an archive nested inside a release archive is not scanned | medium | open |
| FZ-12 | a "binary" artifact that is really a zip of denied files passes the gate | medium | open |
| FZ-13 | `Docs/`, `SRC/`, `x.PY.` are not denied, though Windows treats them as `docs`, `src`, `x.py` | low-medium | open |
| FZ-14 | no total memory cap while the gate unpacks a download | low-medium | open |
| FZ-07, FZ-08 | one odd `sshd_config` line stopped the SSH audit; one odd winget program name hid every later update | low-medium | fixed |
| FZ-05, FZ-09, FZ-10, FZ-15 | a release tag with a trailing newline accepted; crashes on a non-ASCII token digest, unexpected `brew` JSON, a `null` journal line | low | fixed |

No finding in the zip reader, byte scanning, brute-force attribution, Windows
event XML, `authorized_keys` parsing or token comparison. Not yet covered: the
signature checker, the NSIS installer, Rust, PowerShell and the phone relay.

## The dashboard

`jarvis serve` runs a scheduler and a local web page. It is plain
`http.server` + SQLite + one self-contained HTML file — no framework, no build
step, no CDN, and no dependency beyond the Python standard library. For a
security tool that is the point: every dependency is code you have to trust, and
this one is meant to tell you when something untrustworthy is running.

Three things shaped the design:

- **Collectors have wildly different costs.** Reading `/proc` takes 20ms; a
  PowerShell audit takes 10–60s because crossing the WSL interop boundary
  dominates everything else. So each job runs on its own interval — processes
  every 60s, firewall every 15min, spyware and autostart hourly.
- **Jobs never run concurrently.** A single worker runs them one at a time; two
  simultaneous `powershell.exe` launches are slower than running them back to
  back and fight over the same interop pipe.
- **The page never waits for a scan.** Every request is served from the last
  stored snapshot, so the dashboard is instant even mid-audit, and a restart
  redraws immediately from SQLite instead of showing a blank page.

The listener binds `127.0.0.1` with no option to change it. A page listing your
firewall gaps and running processes is exactly what an attacker would like to
read.

### Running 24/7

`./install.sh --service` installs a systemd **user** service with
`Restart=always`. Two WSL-specific gotchas that the installer calls out:

1. **Linger.** Without it, systemd tears down your user manager when your last
   shell exits — closing your terminal would stop the daemon.
   ```bash
   sudo loginctl enable-linger $USER
   ```
2. **WSL itself.** WSL only runs while Windows keeps it running. Run
   `./install.sh --windows` for the one-time PowerShell command that registers a
   hidden logon task to start WSL; systemd and linger take it from there.

### Learning and protecting daily Windows apps

`scripts/harden/secure-daily-apps.ps1` counts top-level application launches so security work
can follow actual use instead of a guessed software list. Its privacy boundary
is narrow: executable name, executable path and launch time only — never command
lines, window titles, URLs, documents or input. Chromium child processes are
deduplicated, and all data remains under `%LOCALAPPDATA%\Jarvis\AppGuard`.

Run from Windows PowerShell:

```powershell
.\scripts\harden\secure-daily-apps.ps1 -Install                 # learn, report only
.\scripts\harden\secure-daily-apps.ps1 -Install -AutoHarden     # harden after 7 learning days
.\scripts\harden\secure-daily-apps.ps1 -Report                  # counts + publisher signatures
.\scripts\harden\secure-daily-apps.ps1 -Harden                  # harden learned browsers now
.\scripts\harden\secure-daily-apps.ps1 -Undo                    # restore prior browser policies
.\scripts\harden\secure-daily-apps.ps1 -Remove                  # remove task; preserve usage data
```

An app becomes "essential" after at least three launches on two separate days
(configurable at install). Every essential executable gets an Authenticode
publisher check. Recognized browsers get reversible, user-overridable safe
defaults: standard Safe Browsing/SmartScreen, password-leak detection where
supported, and balanced HTTPS-only navigation. Unknown software is reported but
never modified merely because it was opened often.

Hardening is applied only after the executable has a valid expected publisher
signature; a lookalike named `chrome.exe` is reported, not trusted. `-Report`
also writes `browser-protection.json`. Registry values mean *configured*, not
necessarily *enforced*: confirm them in `chrome://policy`, `edge://policy`,
`brave://policy`, or Firefox `about:policies`. The elevated
`scripts/harden/harden-windows.ps1` supplies the system-wide internet edge beneath browsers:
Defender download/script/PUA/network blocking, enabled firewalls with
default-deny inbound, and non-bypassable Windows/Edge SmartScreen.

## The commands

| command | question it answers |
|---|---|
| `scan` | What is running right now, and is any of it new? |
| `hidden` | Is anything hiding from the normal process listings? |
| `boot` | What ran at startup — including windows that flash open and close? |
| `spy` | Is anything monitoring me? Who used the mic/camera, and when? |
| `firewall` | Who can reach in, and who actually did? |
| `control` | What could take control of this machine, and are the defenses on? |
| `asep` | What else can auto-start code — beyond Run keys? |
| `investigate` | All of the above, in one report. |
| `intrusion` | How would this machine have been broken into — and was it? |
| `evasion` | Is anything in a position to lie to the checks above? |
| `coverage` | Is this system itself running, current, and not blind? |
| `intel` | What is being used against machines like this one, right now? |
| `feeds` | Bulk indicator feeds — hundreds of thousands of live records, free. |
| `hunt` | Is any of it actually here? |
| `gaps` | What is current attacker tradecraft that nothing here checks? |
| `implant` | Can anything read my traffic, or reach past the firewall? |
| `backdoor` | What grants a way back in — keys, sudo, units, accounts? |
| `posture` | Are the defenses that would have stopped this switched on? |
| `netwatch` | What has the network been doing, and did anything tamper with it? |
| `inputwatch` | Did anything type or move the cursor that was not a human? |
| `sysmon` | What happened between two sampling passes? |
| `secrets` | Which credentials are sitting in plaintext on this disk? |
| `bruteforce` | Is anything guessing passwords — failed-auth spikes, lockouts? |
| `sniffing` | Is anything capturing traffic — promiscuous NICs, raw sockets, pcap drivers? |
| `webshell` | Is there a command dispatcher sitting in a web server's document root? |
| `toolchain` | What runs because I opened an editor, a repo or a shell? |
| `outstanding` | What was I told about that I never resolved — and what came back? |
| `auditd` | Is Linux syscall interception installed and actually recording? |
| `sysmon-linux` | eBPF syscall events (execve, connect, ptrace, file writes) with rules. |
| `serve` | Run everything continuously behind a local dashboard. |
| `alert` | Email me when a collector stops recording or something critical fires. |
| `ask` | Answer from current JARVIS data; use local Ollama for open questions. |
| `brief` | JARVIS's step-by-step protocols for securing this machine, verified by fresh scans. |
| `defend` | Show, approve or undo evidence-backed containment actions. |
| `incidents` | What has been observed, what became unobservable, and what returned? |
| `inspect` | Hash and scan a file or capture process context into an evidence case. |

```bash
jarvis baseline          # learn the current state as known-good (do this once)
jarvis scan              # what drifted, what looks wrong, who it talks to
jarvis scan --enrich     # ...and reverse-DNS the public IPs
jarvis watch -i 120      # keep scanning, print only medium-and-worse
jarvis hidden            # cross-view scan (--deep sweeps the full pid range)
jarvis boot              # reconstruct startup from the event logs
jarvis spy               # monitoring software, capability use, input devices
jarvis evasion           # kernel integrity, hidden streams, shortcuts, dead drops
jarvis firewall          # posture, inbound rules, inbound connections, logons
jarvis control -v        # persistence / remote access / defenses
jarvis peers --scope public   # every external IP seen, and which process reached it
jarvis events --since 24      # alert history
jarvis procs --approved 0     # fingerprints not yet approved
jarvis approve <fp> --note "my build script"
jarvis status
jarvis ask "what needs me?"
jarvis ask "how do I raise my score?"   # the score coach: areas, projected gains, acks, blind spots
jarvis ask "model status"     # is the local Ollama endpoint actually there?
jarvis fix                    # review human-gated maintenance proposals
jarvis brief                  # the protocol JARVIS raises now; `brief list`, `brief yes|no`, `brief check`
jarvis defend
jarvis inspect 'C:\Users\me\Downloads\suspicious.exe'

jarvis intel --set-key <exa-key>   # once
jarvis intel                      # refresh the least-recently-updated topic
jarvis intel --all                # refresh the whole corpus
jarvis intel --show               # what the knowledge base holds
jarvis intel --revet              # re-judge stored indicators after a rules change
jarvis hunt                       # match every indicator against this machine
jarvis gaps -v                    # techniques in current intel that nothing checks
```

Add `--host wsl` or `--host win` to either side alone; the default is both.
Every audit command takes `--severity`, `-v` and `--json`.

### Human-gated repair drafting

`jarvis fix approve ID` authorizes investigation, not a system change. JARVIS
asks the loopback Ollama model for a bounded JSON directive, validates its file
scope, invariants and test commands, then gives that directive to OpenCode as
untrusted context for a patch draft. The complete directive, prompt, tool output,
failure reason and decision history stay with the proposal. Review the result
with `jarvis fix show ID`, then separately run `jarvis fix authorize ID` before
`jarvis fix apply ID`. Apply still refuses a dirty tree, runs the required test
suite and rolls the patch back on failure. Email replies cannot authorize either
gate, and neither model can apply or deploy changes.

## Finding hidden processes

No single process list is trusted, because anything with enough privilege can
lie to the API behind it. `jarvis hidden` collects several enumerations that
reach the kernel by different routes and diffs them:

*Linux* — libc `readdir`, the raw `getdents64` syscall via ctypes (which an
`LD_PRELOAD` rootkit cannot filter), a direct `stat()` sweep of the pid range,
and socket inodes that no visible process claims. It also checks for bind-mounts
over `/proc/<pid>`, which hide a process with no code injection at all.

Two of these views do not go through procfs at all, which matters because a
single rootkit that filters procfs defeats every view that does:

- **The signal path.** `kill(pid, 0)` delivers nothing but resolves the pid
  through the kernel's pid hash table. A pid that accepts a signal while having
  no `/proc` entry is hidden below the filesystem layer.
- **The scheduler.** `/proc/sched_debug` is generated from the runqueues rather
  than the process tree, so a task can be scheduled and still be missing from
  the listing. (Absent on kernels built without `CONFIG_SCHED_DEBUG` — including
  WSL's — in which case the missing view is reported rather than passed.)

It also looks for the machinery itself: **pinned eBPF maps named for
concealment** (`hidden_pids`, `hidden_names`, `hidden_inodes`), which is where a
modern eBPF rootkit keeps the list of what it is hiding — so the finding tells
you to `bpftool map dump` it and recover exactly what was concealed — and
**io_uring**, which performs file, socket and process operations through a
shared ring buffer instead of syscalls, making it invisible to syscall-based
tooling. Processes holding a ring are listed, and whether the kernel permits it
at all is reported.

Beyond process listings it looks for the machinery hiding them:

- **Bind probing.** A rootkit that filters `/proc/net/tcp` still cannot make the
  kernel hand out a port that is genuinely bound. Asking to bind each port and
  being refused `EADDRINUSE` while no visible socket claims it means something
  is listening that does not want to be seen.
- **Kernel modules.** A classic LKM rootkit unlinks itself from `/proc/modules`,
  but the `/sys/module/<name>` directory it created on load usually survives.
- **eBPF.** This is now the preferred way to build a Linux rootkit — it loads on
  any modern kernel without matching headers and can filter what other tools
  see. Loaded programs and the processes holding eBPF file descriptors are
  inventoried; tracing-class program types are called out. Legitimate users
  exist (systemd, Docker, observability agents), so this is a list to review.
- **ftrace hooks.** How many rootkits patch syscalls without ever touching the
  syscall table.
- **Injected and fileless code.** `LD_PRELOAD` in a live process environment, an
  executable mapping marked `(deleted)`, or a `memfd:` executable mapping —
  code running with no honest file behind it.

*Windows* — `Win32_Process` (WMI), `Get-Process` (the process API), `tasklist`,
and the pids owning TCP connections. Userland hooks routinely patch one of these
and miss the others. But all four walk the same kernel list —
`ActiveProcessLinks` — so all four fall to one DKOM unlink. Four more views
reach process objects by other routes:

- **The handle table.** `OpenProcess` resolves through `PspCidTable`, a
  different structure entirely. Unlinking an `EPROCESS` from
  `ActiveProcessLinks` does not remove it from here, so a pid that opens while
  appearing in no enumeration is the signature of that attack. The sweep runs in
  C# because 16k P/Invoke calls from PowerShell would take minutes.
- **The thread list**, **the performance counters**, and **the service
  controller** — each reached through its own provider chain.

Two things make this usable rather than noisy, and both were found by running
it:

1. **A pid that opens is not necessarily a running process.** When a process
   exits, its kernel object — and its pid — stay valid for as long as anything
   holds a handle to it, so `OpenProcess` keeps succeeding on something already
   gone. Checking `GetExitCodeProcess` for `STILL_ACTIVE` removes ~27 phantom
   detections on an ordinary desktop.
2. **`ERROR_ACCESS_DENIED` is not proof of existence.** It is returned both by
   protected processes and by pids that cannot be qualified at all. Those are
   reported as a *gap in coverage* — with the advice to re-run elevated — rather
   than as critical findings, because guessing there is guesswork dressed up as
   an alert.

Every candidate from every view is then re-tested against a fresh enumeration
and re-probed for life, so a process that merely started or exited mid-scan is
never called a rootkit. `jarvis asep` adds **masquerade detection** (a `svchost.exe`
outside System32 is not svchost) and **parentage analysis** (Office or a browser
spawning a script host, WMI spawning a shell, `lsass` having children at all).

Disagreement between views is re-verified before it is reported, so a process
that merely started or exited mid-scan is not called a rootkit. Threads are
excluded: `/proc/<tid>` stats fine for every thread while `readdir` lists only
thread-group leaders, and treating that as hiding produces nothing but noise.

## Knowing what to look for

Every other check in this repo encodes what was worth looking for on the day it
was written. Attacker tradecraft moves; a static detector quietly ages into a
detector of last year's problems. `intel` keeps a knowledge base of current
published research, `hunt` compares it against this machine, and `gaps` reports
what current tradecraft nothing here can see.

The knowledge comes from Exa's search API, restricted to a list of publishers
that do primary host-based research. Each result is passed back through the
same API with a JSON schema attached, so what returns is structured artefacts —
paths, hashes, domains, registry keys, ATT&CK technique ids — rather than
article text to parse. The API key lives in `~/.jarvis/config.json` at mode
0600, never in the repository.

### Why none of it is trusted

This is the only part of JARVIS that takes input from the internet, and it does
so in a security tool whose entire value is being right about what is running.
Two things are wrong with the input by construction: the articles are written by
strangers, and the extraction is done by a language model that fills empty
fields with plausible filler.

That is not hypothetical. One real article in testing produced `evil.com`,
`192.168.1.100`, `gdb`, `strace`, a bare `/tmp/`, and two "SHA-256" values that
turned out to be the digests of the empty string. Every one of those is
syntactically perfect. Loaded straight into a detector on a developer's
workstation, that single article would have flagged the debugger on every use
and pinned a permanent alert on a directory that is supposed to contain files.

So `vet.py` sits between the feed and the database, and it is deliberately the
dumbest code in the project — no network, no model, no learning. It drops
digests of empty input, non-public addresses, reserved example domains, kernel
symbols filed as process names, stock PAM modules, path fragments like `/proc`
that exist on every machine, and anything holding a redaction marker. On the
first real corpus run it rejected roughly a quarter of all candidates.

Two invariants hold no matter what the feed says:

- **Intel may only ever add suspicion.** Nothing fetched can approve a process,
  clear a finding, or lower a severity. The worst a poisoned feed can achieve is
  wasting your attention; it can never create a blind spot.
- **Nothing fetched is ever executed.** Indicators are compared as data — never
  interpolated into a shell, never used to build a command.

When the rules get tighter, `jarvis intel --revet` re-judges everything already
stored, so the knowledge base is never stuck at the quality of the rules that
were in force the day it was fetched.

### Turning knowledge into a check

`hunt` only compares against state JARVIS already collects, so it is cheap
enough to run every half hour:

| indicator | checked against | severity on match |
|---|---|---|
| SHA-256 | digests of executables in the baseline, cached by size and mtime | critical |
| domain / IPv4 | the recorded peer table, including reverse DNS | critical |
| absolute path | the filesystem, skipping anything a package owns | high |
| filename | only the directories such a payload must live in to work | high |
| process name | exact matches in the process baseline | high |

Two second-guards keep the false-positive rate down: a path that `dpkg` owns is
never reported, because a package putting a file where it belongs is not an
intrusion, and a directory is never reported as a dropped file.

The filename check exists because the best indicator from the first real run —
`pam_security.so`, a PAM backdoor named in six separate writeups — arrived with
no path at all. Hunting bare filenames across a whole filesystem would be slow
and noisy, so it looks only where such a payload has to be to function: the PAM
module paths, the loader paths, the systemd unit directories, the world-writable
drops.

### Gaps: pointing the tool at its own blind spots

ATT&CK technique ids cannot be "found" on a host, so they are used differently.
`gaps` compares the techniques current research is discussing against the
techniques JARVIS's collectors actually cover, and reports the difference,
weighted by how many independent writeups raised each one. A technique three
teams wrote about this year is a better use of an afternoon than one mentioned
once.

This is the counterpart to `coverage`. `coverage` asks whether JARVIS is
running; `gaps` asks whether it is looking at the right things — and answers
with a work queue rather than a warning.

### Cost

Searches are metered. One topic refresh is roughly five cents; the full corpus
is under forty. The daemon refreshes one topic at a time on a six-hour timer, so
the corpus rotates itself over about two days. A daily budget, default `$0.50`
and settable as `daily_budget` in `~/.jarvis/config.json`, is enforced before
each query rather than reported after it — a metered API on a 24/7 timer is
otherwise a standing invitation to a surprise bill.


## Volume: the bulk feeds

Search buys *tradecraft* — the path a rootkit drops, the unit file it installs.
It is a poor way to buy *coverage*: a writeup names a handful of hashes, and
paying a metered API per document to accumulate tens of thousands of them costs
real money for data that is already published free.

So `feeds` carries the volume and `intel` carries the narrative:

| | source | gives |
|---|---|---|
| `intel` | Exa over ~60 research publishers | paths, filenames, techniques, persistence |
| `feeds` | 15 public feeds, no authentication | hashes, domains, addresses, ranges, CVEs |

The feeds are abuse.ch (ThreatFox, MalwareBazaar, URLhaus, Feodo), CISA KEV,
Spamhaus DROP, OpenPhish, Emerging Threats, blocklist.de, CINS, Binary Defense,
IPsum, and the MITRE ATT&CK catalogue. Together they hold **just under 400,000
live indicators**, refreshed on each publisher's own cadence — ThreatFox and
URLhaus update continuously, CISA KEV when exploitation starts.

Feed data is better than an extraction from prose: curated, attributed,
confirmed malicious. It still goes through the same `vet.py` gate, because a
feed can carry a private address or a defanged placeholder too, and because the
"intel may only add suspicion" invariant has to hold for every source without
exception.

Everything ages. `feeds --prune` retires feed indicators no publisher has
listed for 90 days, because C2 infrastructure is rented and recycled and an
address that fell off every list three months ago is more likely to be someone
else's server now. Writeup-derived indicators are never pruned: a sample's hash
is true forever.

### Staying fast at that size

Holding 400,000 records is easy. Querying them on a 30-minute timer without the
machine noticing is the part that needed design.

The first version loaded every indicator into Python dictionaries and compared
in a loop. At sixteen thousand records that was invisible; at four hundred
thousand it would have read a hundred megabytes into memory to answer a
question SQLite can answer from an index. `hunt` is now written as indexed
joins against the `(kind, norm)` unique index, with three consequences:

- addresses match in a single join
- reverse-DNS names walk only their own parent domains — a handful of index
  probes each, regardless of how many domains are stored
- file hashes probe the index per file rather than loading every digest

Network ranges are the exception, because a CIDR cannot be indexed by value, so
they are bucketed by first octet and a peer is only tested against the handful
of networks that could contain it.

The database runs in WAL mode so the dashboard reads while feeds write. Bulk
inserts go in 20,000-row chunks.

The result is that a hunt across 397,000 indicators takes **0.4 seconds** —
the same as it took across 16,000.

## Interception, boundary bypass, and trust

`implant` looks for what a *targeted* implant does that commodity malware
usually does not bother with: the quiet changes that let an operator read
traffic and reach in past the firewall.

- **interception** — a root certificate the operator controls, a proxy or PAC
  URL, a rewritten hosts file, a DNS override. None of these are malware. All
  of them make TLS readable.
- **boundary** — `netsh interface portproxy` forwards traffic straight through
  the host **with no firewall rule to show for it**, which is why the firewall
  audit cannot see it. Filtering-platform callouts sit below the firewall UI
  entirely.
- **trust** — an unsigned driver, a PAM module no package owns, a preloaded
  object. These do not hide the implant; they make the system vouch for it.

Worth saying plainly: true Pegasus indicators are iOS and Android artefacts and
nothing here can find them — that is a phone forensics job for Amnesty's MVT.
What this finds is the desktop equivalent class, and it reports mechanism
rather than attribution.

## Backdoors

`backdoor` reads the mechanisms that grant access and asks whether what they
grant is what you intended: SSH authorised keys and `sshd_config`, systemd
**user** services (which need no root at all), XDG autostart entries, appended
shell profiles, `NOPASSWD` sudo grants, setuid binaries no package owns, second
UID-0 accounts, and — on Windows — OpenSSH authorised keys, accounts hidden
from the sign-in screen, and a debugger set on `sethc.exe` or `utilman.exe`,
which yields a SYSTEM shell from the logon screen with no credential.

Most of these need a human to confirm, because the tool cannot know which SSH
key is yours. So each finding shows the actual evidence — the key comment, the
sudoers line, the appended command — not just the filename.

## The developer trust surface

Every other collector here watches something the operating system knows about: a
process, a service, a socket, a run key. `toolchain` watches the layer above all
of it, which none of them can see — a JSON file that a trusted binary reads and
obeys.

The mechanisms are all documented features working exactly as designed:

| mechanism | what it actually is |
|---|---|
| MCP server entry | a command line an editor spawns on launch, unattended |
| agent hook | a shell command bound to a tool event |
| editor extension | unsandboxed Node with your tokens, SSH agent and filesystem |
| git hook | a script `git commit` runs for you |
| executable `.pth` line | Python that runs on *every* interpreter start |

What makes them a security surface is where the file lives. Cloning a repository
is not supposed to be a privileged act and opening a folder is not supposed to be
one either, but a `.mcp.json`, a `.claude/settings.json` hook or a `.git/hooks/`
script inside that repository makes both of them exactly that. So repo-scoped
configuration is scored above user-scoped configuration everywhere in this
module: user scope is a decision you made once, repo scope is a decision someone
else made for you.

Two things follow from how these get abused in practice:

**Inventory alone is worthless.** A backdoored extension is a *version change* on
something you installed legitimately last week — the package is already trusted
and only its contents are new. So the baseline of what was here on the previous
run is the detection, not the list. Same for MCP servers: the 2026 Cursor finding
was not a malicious config, it was a benign config approved once and swapped
afterwards, because approval was recorded and the command was re-read at every
launch. A changed definition is therefore `critical` here, not informational.

**Content decides severity, not presence.** A `.mcp.json` is normal. A `.mcp.json`
whose command is `bash -c 'curl … | sh'` is an incident, and the difference is one
string. Inline `node -e` gets its own tier between the two, because it is how a
great many honest hooks read their stdin and also what makes a dishonest one
invisible in a diff.

One check has no equivalent elsewhere in the codebase: agent instruction files —
`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, skill files — are scanned for zero-width
and bidirectional-override characters. Those render as nothing to you and as text
to a model, which is the documented way to put an instruction in a file that a
human reviewer cannot see.

The bounds are stated rather than hidden: the `$HOME` walk stops at four levels
deep and 200 repositories, and if it stops early it says so as a `visibility`
finding, because a scan that quietly stopped looking is indistinguishable from
one that looked and found nothing.

```bash
jarvis toolchain -v
```

## What was reported and never resolved

Every collector answers "what is true right now?". None of them could answer
"what did this system tell me about that I never actually dealt with?"

The reason is structural. `alert.py` keeps a live state map so it can decide
what to mail next, and it **deletes** an entry the moment the finding stops
being reported. That is right for sending and useless for accountability: a HIGH
could be mailed, ignored for three weeks, then quietly clear itself — because
the collector that raised it started failing, say — and leave no trace that it
had ever existed. Worse, a finding that was genuinely fixed and then came back
looked exactly like one seen for the first time, which throws away the most
diagnostic fact available: *it came back*.

`alert_ledger` is append-and-update, never delete. Rows are marked cleared, not
removed, so a reappearance is recognisable as one. Four states:

| state | meaning |
|---|---|
| `recurring` | cleared before, reported again since — the fix did not hold |
| `outstanding` | mailed, still reported, never cleared |
| `stale` | mailed, and the job that raised it has not run since |
| `resolved` | cleared, and stayed cleared |

`stale` is the one that matters most and is easiest to miss. An open finding
whose collector has not run since it was mailed has not survived a re-check — it
has merely not been contradicted. Silence from a dead collector is not a clean
result, and this is where that distinction gets made rather than assumed.

Age is reported in days, not as a boolean, because "unresolved" does not mean
the same thing after an hour and after a month. Each severity gets a deadline —
critical 2 days, high 7, medium 21, low 45 — and only a finding past its own
deadline is raised.

Two deliberate constraints:

**The ledger never pages.** Its category is in `_NOPAGE_CATEGORIES` for a
structural reason rather than a stylistic one: an unresolved HIGH would generate
a ledger HIGH, which would be mailed, which would be recorded in the ledger as
another unresolved alert, which would page. The backlog belongs somewhere you
read deliberately, not somewhere it is pushed at you.

**The import is honest about what it could not recover.** The ledger was added
after alerting had been running for weeks, so it imports `alert_state` once — 41
open alerts on the machine it was written on. That map stores the key,
timestamps, count, severity and job, but never the finding's `detail`, so
imported rows say so instead of inventing one. It also stored no host, and
guessing produced confident nonsense (Windows paths labelled `wsl`), so imported
rows carry no host until the next genuine send fills it in. Entries still inside
the persistence gate — queued but never actually mailed — are skipped, because
the ledger records what was *sent*.

```bash
jarvis outstanding          # the backlog, worst and oldest first
jarvis outstanding --all    # including what has been resolved
```

## Posture: what should be switched on

`posture` asks whether the defenses that would have stopped an intrusion are
enabled, and names the setting to change when they are not.

It covers Defender (real-time, tamper protection, PUA, network protection,
signature age, exclusions), ASR rules, Secure Boot, TPM, VBS and Memory
Integrity, Credential Guard, LSA protection, BitLocker, UAC, autologon, local
administrators, SMBv1, RDP, WinRM, SmartScreen, and PowerShell logging.

Four of those — BitLocker, TPM, Defender's exclusion list and optional features
— return nothing at all without administrator rights, and *nothing* is
indistinguishable from *clean* unless something asks properly. `--elevate`
re-runs the same collector behind a UAC prompt and reads them for real. It
matters: on this machine the unelevated run reported Secure Boot and BitLocker
as "could not be read", and the elevated run showed Secure Boot **off** and the
system drive **unencrypted**. A cancelled prompt is reported as an error, never
as an empty result.

**On activation**, since it is the question everyone asks: an unactivated
Windows is not an insecure Windows. Activation gates personalisation, not
security — Defender still runs, Windows Update still delivers security patches,
the firewall still works. What carries risk is the *method*: a script piped
from the internet into an elevated shell is a total-trust event regardless of
what it does afterwards. So activation state is reported as information, and
the activation method is treated as the thing worth thinking about.

## Network history

`netwatch` samples network state every two minutes and keeps every sample, not
just the interesting ones. The useful network questions are all about the past
— when did the link drop, did the adapter go down on its own, has this network
always been on this hardware — and none of them can be answered by looking now.
Storage is a few hundred bytes a minute; the alternative is discovering that
the one moment you needed is the one you did not keep.

What the transitions mean:

| transition | reading |
|---|---|
| adapter disabled | nothing disables a working adapter by accident |
| link lost | ordinary alone — the point is what else happened at that moment |
| same SSID, new BSSID | roaming, unless the BSSID is one never seen before |
| encryption weakened | a network that was WPA3 yesterday is not the same network |
| gateway MAC changed | traffic now leaves through different hardware — ARP spoofing |

It also folds in Windows' own WLAN log, so the history predates the monitor.

One caveat the audit reports on itself: `netsh` needs Location permission to
reveal SSID, BSSID and cipher. Without it, evil-twin and downgrade detection
cannot run — adapter state, gateway MAC, DNS and the connect/disconnect log
still do. The audit says so rather than reporting a clean result it could not
actually check.


## Input that no human produced

Windows tags every keyboard and mouse event that did not come from real
hardware. `LLKHF_INJECTED` marks anything delivered through `SendInput` or
`keybd_event`; `LLKHF_LOWER_IL_INJECTED` additionally marks input injected by a
process at a lower integrity level than the window receiving it, which is the
shape of one program driving another's UI. Those flags are visible only from
inside a low-level hook, so `inputwatch` manages a small resident helper that
installs one.

Three costs, all real, all worth stating before you turn it on.

**It is an agent.** Everything else here samples state and exits. This runs
resident, and if it dies the record stops — so it emits a heartbeat, because
otherwise "no injected input" and "not watching" look identical. A heartbeat
alone is not enough either: a hook installed in Windows session 0 pulses
forever and sees no keyboard, so the heartbeat carries its session and a hook
outside your desktop is stopped and restarted rather than reported healthy.

**Its restart path is one mechanism, not luck.** `inputwatch` registers a
scheduled task (`JARVIS input hook`) that runs only while you are logged on, so
it always starts in the desktop session whoever triggers it, and Windows starts
it at logon and refuses a second instance. Between logons the 45-second
watchdog is what notices a dead hook and starts the task again: measured
recovery after killing the helper was 120 seconds. (Windows' own
restart-on-failure does not apply — the launcher exits once the hook is
running, so the task counts as completed.) The task's definition and the
staged script's fingerprint are what the control audit verifies, so an edited
task or script becomes a critical persistence finding instead of a trusted
name. Starting through WSL interop remains only as a fallback, and JARVIS
refuses to start a helper beside an existing one.

**It does not record what you type.** A low-level keyboard hook sees every
keystroke, and one that stored key values would be a keylogger writing your
passwords to a SQLite file — on a disk this project's own posture audit
confirmed is unencrypted. Real keystrokes are counted and nothing else.
Injected events store a coarse class (`enter`, `character`, `navigation`), the
flags, and the focused window. Enough to say *something typed Enter into your
terminal at 03:14*; not enough to reconstruct a sentence.

Real typing is retained only as one aggregate SQLite row per minute: total
key-downs, cadence buckets, and counts for the `=/+`, `/?`, and `./>` physical
key families. There is no order, shift state or surrounding text, so a password
cannot be reconstructed. The daemon uses those 90 days of bounded history as a
personal baseline and reports volume spikes, machine-fast cadence, or unusual
concentration on those punctuation keys. Injected presses of the same keys are
stored as coarse classes and remain high-signal events.

**Injected does not mean malicious.** Password-manager auto-type, AutoHotkey,
on-screen keyboards, RDP, screen sharing and some IDE features all inject
legitimately, and the flag says nothing about *which* process did it — the
foreground window is only a weak correlate. This reports evidence with the
context to judge it, not a verdict.

### Why the cursor feels slow

Every low-level hook sits in a chain, and each one delays every event until it
returns. That is the mechanism behind "the mouse is slower than it used to be":
a keylogger, screen recorder or overlay doing work on the input thread shows up
as milliseconds on every movement.

So the hook measures it rather than guessing — the delta between when Windows
generated an event and when this hook received it, reported as average, peak,
and the share of events over 50 ms. JARVIS's own hook is in that chain and
contributes part of the figure, which is why the finding says so and tells you
to stop it and re-measure.

It also reads `LowLevelHooksTimeout`. Windows silently removes a hook that
takes longer than that to return, default 300 ms, so software wanting to keep a
slow hook alive has a motive to raise it. An unexplained increase is a finding.

### Keeping the hook up

The helper is Windows-side and does not survive a reboot, a WSL restart or
being killed — and anything that wants to drive this machine unseen has a
direct motive to kill it. So the daemon runs an `input_hook` watchdog every
45 seconds:

- **Liveness is the heartbeat, not the PID.** A hung hook still has a PID and a
  forged pid file still names one. Past 90 s without a heartbeat the watchdog
  crosses the interop boundary once to tell "process gone" (restart now) from
  "process alive, drain delayed by a slow collector" (wait); past ~210 s an
  alive-but-silent helper is treated as a removed hook and cycled.
- **Restarts back off exponentially** (20 s to 10 min) keyed to consecutive
  failures, so a crash loop cannot become a `powershell.exe` spawn loop.
- **Repeated failure is itself a finding.** More than four restarts in six
  hours is reported `high`: a security monitor that keeps dying is a detection,
  not an operational annoyance. Eight consecutive failed restarts is `critical`.
- **The helper script is content-pinned.** A change to the trusted source is
  surfaced; a staged copy that does not match it aborts the restart rather than
  launching something unexpected.

The healthy path is local-only — drain the output file, check the heartbeat
age — so running it every 45 s costs about 25 ms and no interop round trip.

## Alerts: being told when it stops

The dashboard is only useful when you are looking at it. `jarvis alert` adds an
outbound path for the findings that matter when you are not — a collector that
crashed, a monitor that stopped recording, anything `critical`.

It is off until you configure it, and it is the one component besides `intel`
that reaches the network on its own. It sends through [Resend](https://resend.com)
over HTTPS, standard library only. Put this in `~/.jarvis/config.json` (kept
`0600`):

```json
{
  "resend_api_key": "re_...",
  "alert_from": "JARVIS <jarvis@yourdomain.com>",
  "alert_to": "you@example.com",
  "alert_min_severity": "high",
  "alert_digest_interval": 3600,
  "report_hour": 9,
  "auto_remediate": true,
  "report_daily_enabled": false,
  "alert_on_clear": false,
  "alert_hourly_cap": 12,
  "advisory_model": "gpt-5.6-luna",
  "openai_api_key": "sk-...",
  "intel_topics_per_run": 2,
  "intel_results_per_query": 6,
  "intel_lookback_days": 365,
  "daily_budget": 2.0
}
```

`alert_from` must be a sender Resend has verified for your domain; `alert_to`
takes a string or a list. The key may also come from `$JARVIS_RESEND_KEY`, and
it is only ever sent in the `Authorization` header of the one request to
`api.resend.com` — never logged, never in the body.

Every finding has a stable key. Ordinary high findings must be observed twice
and are then queued in an hourly change digest. New critical findings and
monitoring outages notify immediately. Unchanged findings escalate once at each
age threshold: critical at 1h/6h/24h, high at 1d/3d/7d, medium at 3d/7d/14d,
and collector outages at 15m/1h/6h. There are no periodic STILL emails.
Resolution comes from the owning collector's successful result. Delivery failures
retain queued changes for retry; hourly caps defer delivery without discarding it.
Monitoring outages bypass the severity filter. Ordinary mail uses
`alert_hourly_cap` (default 12); urgent changes have a separate ceiling of 60.

The daily health email carries today's protocol in full — the readiness
question, every manual step (Secure Boot in the firmware, Memory Integrity,
turning on BitLocker and where to keep the recovery key), the command
alternative, the caution, and what is queued behind it — so the instructions
are in the mail rather than behind a command. A monitor that is down, the
keystroke hook included, is recorded as a failed observation, so the score,
coverage, the dashboard greeting and the outage email all show it.

Change digests and the daily health email open with a line in JARVIS's own
voice. With `"email_voice": true` the local Ollama model writes it
(`email_voice_model`, default `llama3.2:3b`; the 1B model invented events in
testing); otherwise a built-in line is used. Only that line comes from the
model. The subject, counts, findings, severities and commands stay
deterministic. Before use, the line is checked: no commands, links, lists or
questions, no number the facts do not contain, no restated severity, no score
direction that contradicts the trend, and no claim that JARVIS acted. Any line
that fails, times out or finds the model busy is replaced by the built-in one,
so mail is never held up by the model.

With `"plan_voice": true` the daily health email also gets one model-written
paragraph on where the score gains most (which area, which named task, how
many points the projection says it is worth). It obeys the same checks as the
opener, plus a no-claims-of-action rule: the model proposes, the human
disposes. The protocol's hand-written steps follow it unchanged, and the
paragraph falls back to a deterministic line whenever the model is off, busy
or wrong.

The daemon also checks on the model itself: a `model` job pings Ollama every
half hour — one loopback GET (through the Windows bridge on NAT installs),
never a generation — and records a low-severity visibility finding when the
endpoint is down or misconfigured, so a dead model is a known state rather
than something noticed the next time an answer fails. `jarvis ask "model
status"` runs the same check on demand.

The dashboard's spoken briefing (🔊 voice, or `v`) works the same way. The
local model writes only the opening line (`dashboard_voice_model`, falling back
to `email_voice_model`, then `llama3.2:3b`; set `"dashboard_voice": false` to
use built-in lines only). The browser then speaks the score, live alerts, the
next step and collector health from its own code. The model sees only the
score, grade, trend and whether work is waiting, never finding titles or
counts: given those, it invented intruders ("a sneaky visitor") and read
counts as score gains. On top of the email checks, spoken lines may not guess
at attackers, promise help or sound grudging. While a live alert is showing,
the model is skipped for a fixed line. A line is reused for ten minutes while
the facts are unchanged, and the page speaks without it after 20 seconds.

Independently of change alerts, `jarvis serve` sends a daily posture advisory
after `report_hour` in the host's local timezone, checking eligibility every five
minutes. It uses the same configured Resend recipient and reports which
collectors are current, stale, failing, or missing; ranks active findings by
severity; attaches a concrete safe next action where one is known; names
visibility gaps and design limits; and lists explicit clean/protected checks.
Volatile process command lines and peer details remain local rather than being
copied into routine email.

The HTML report is deterministic by default. For an additional evidence-bound
AI assessment, add paid OpenAI API credits and configure `advisory_model` plus
`openai_api_key` (or provide `JARVIS_OPENAI_KEY` to the service). JARVIS uses
the Responses API with storage disabled and sends only redacted findings—never
credential values or raw process command lines. If credits, model access, or
the API are unavailable, the report says so and the deterministic report still
sends. Exa breadth is separately bounded by `intel_topics_per_run`,
`intel_results_per_query`, `intel_lookback_days`, and the hard `daily_budget`.
Complete security cannot be guaranteed; each report distinguishes verified
controls from recommendations and blind spots.

```bash
jarvis alert            # show configuration and any active alerts
jarvis alert --test     # send a test message to the configured recipients
```

**On screen scraping**: the modern capture APIs go through the capability
access manager and `spy` already reports them, including whether a capture
border was shown. Legacy GDI scraping — `BitBlt` against the screen DC — leaves
no such record and a sampling monitor cannot see it. That is a genuine blind
spot rather than a covered one, and it is listed as such rather than papered
over.

## Brute force — counted from the logs

Password guessing (T1110) is one of the most-cited techniques in the corpus and
one of the few runtime behaviours that leaves a durable artefact: failed-auth
records. `bruteforce` counts them.

- **Linux** — sshd and PAM lines from the journal, or `/var/log/auth.log` if
  there is no journal. Failures are grouped by source: a spike from one address,
  or a spread across many usernames (spraying), is the finding. Failed `sudo`
  authentications are counted separately.
- **Windows** — Security event 4625 (failed logon) over 24h and 4740 (account
  lockout) over a week, in one query. Reading that log needs Administrator or
  *Event Log Readers*; if the query is denied, or auditing is off, that is
  reported as "unknown", not "clean".

It is a counting exercise, not interception, so it cannot see a slow low-volume
guess that stays under the threshold — and it says so.

## Closing the gaps `gaps` names

`jarvis gaps` measures itself against the ATT&CK techniques in the current
intel corpus. Three collectors were added to close its highest-signal misses:

- **`sniffing`** (T1040) — a promiscuous physical NIC, a process holding an
  AF_PACKET / raw socket, or a pcap driver (Npcap/WinPcap) being installed at
  all. Bridge and container interfaces are promiscuous by design and are noted,
  not alarmed.
- **`webshell`** (T1505.003) — only when a web server is actually listening:
  walks its document root for recently written server-side scripts whose
  contents read as a command dispatcher (an exec primitive beside a request
  variable, an `eval` of decoded input, an ASP page that shells out).
- **`auditd`** — reports whether Linux has syscall interception at all. On WSL2
  auditd cannot run (the kernel rejects the audit daemon), which the collector
  now says explicitly.
- **`sysmon-linux`** — the WSL2-viable alternative: Microsoft's **Sysmon for
  Linux** hooks execve, connect, ptrace, raw disk reads and file create/delete
  through eBPF and emits Windows-Sysmon-schema events to the journal. This
  reads them incrementally and applies Linux-adapted rules — a shell spawned by
  the web server, execution from a world-writable directory, a download-and-run
  command line, a write to `authorized_keys` / cron / a systemd unit, one
  process reading another's memory, a deleted log file, a recon burst — and
  correlates observed destinations against the indicator corpus. Install steps
  are in `jarvis/collectors/telemetry/sysmon_linux.py`; `sysmon/config.xml` is a tightened policy
  that turns on the network, memory-access and persistence-write events those
  rules need without a volume blow-up, and the collector flags it if they are
  missing. Under heavy event load the journal rotates events out in hours —
  faster than a suspended VM's downtime — so the collector also reports when a
  window rotated away before it was read; `systemd/journald-sysmon.conf` is an
  opt-in drop-in that buys ~2 days of retention. Once it is recording, `gaps`
  counts the behavioural techniques covered.

BITS transfer jobs (T1197) folded into `intrusion`, and several techniques that
existing modules already answered (`secrets` → T1552, `intrusion` → T1539 /
T1555.003, `sysmon` → T1003.001) were wired into the coverage map they were
missing from.

## Sysmon: the ceiling this design otherwise has

`coverage` reports its own limit honestly: *sampling, not interception —
anything that starts and exits between two passes is never seen.* That is why
`T1003` (OS credential dumping), the most-raised technique in the whole
intelligence corpus, was marked unclosable. Catching a process opening LSASS
means being told when it happens, not asking afterwards.

Sysmon is a kernel driver that does exactly that. With it installed, `sysmon`
reads process access (event 10), remote threads (8), image tampering (25),
unsigned image loads (7), DNS queries (22) and process starts with hashes (1).

The last two are worth more than their own findings. A DNS query is a name to
check against the 53,000 domains in the corpus, and a process start carries a
SHA-256 to check against 252,000 sample digests — so the knowledge base stops
being something matched against *current* state and becomes something matched
against everything that happened while nobody was looking.

Reading the channel needs membership in `Event Log Readers`, or elevation.
When that is missing the module says so and says how to fix it, because a log
that cannot be read produces exactly the same silence as a machine with nothing
wrong. That distinction is the whole reason `coverage.py` exists.

## Detecting how machines actually get broken into now

`jarvis intrusion` targets current initial-access tradecraft rather than
classic malware, because the modern shape is a thing that runs **once** and
leaves no persistent process for a behavioural rule to catch:

- **ClickFix.** A fake CAPTCHA copies a command to your clipboard and tells you
  to press Win+R and paste it — reportedly the largest single initial-access
  technique in circulation. It leaves a perfect fingerprint: Windows records
  everything typed into the Run dialog in `RunMRU`. That key is read and every
  entry matched against download-and-execute shapes.
- **Infostealers.** They harvest browser cookies, session tokens and saved
  passwords, then exit. Detection here is the residue: PowerShell console
  history, recently written unsigned executables in staging directories, and
  browser extensions.
- **Session theft.** Stolen cookies are replayed directly, so the password and
  the second factor never come into it. Extensions are inventoried and rated on
  whether they can read every page and whether they came from outside the store.
- **Defender's own history.** The cheapest question to ask and the one most
  often skipped: has the antivirus already found something and been ignored?
  Detections that were *not* remediated are raised to critical.

## Checking whether anything can lie to the other checks

Every collector above reads the machine from userland, so each one is only as
honest as the layer beneath it. `jarvis evasion` asks the prior question — is
anything in a position to lie? — by targeting the techniques that specifically
defeat userland inspection:

- **BYOVD (bring your own vulnerable driver).** Load a genuinely signed but
  vulnerable driver, exploit it to run code in the kernel, and switch the
  defences off from underneath. Nothing above the kernel can see the result, so
  the useful signal is the *precondition*: whether Memory Integrity (HVCI) and
  the vulnerable-driver blocklist are on, and whether any loaded driver sits
  somewhere it shouldn't. Severity follows **writability**, not novelty — real
  vendors (anti-cheat, virtualisation, backup) do ship drivers outside
  `System32\drivers`, but a driver under `AppData` or `Temp` did not arrive
  through an installer that already had admin, and that is how BYOVD stages.
  Drivers with public kernel read/write exploits are named outright.
- **NTFS alternate data streams.** A second stream on an ordinary file doesn't
  appear in a directory listing, doesn't change the visible file size, and runs
  perfectly well. Staging directories are enumerated for any stream that isn't
  `Zone.Identifier` — the mark-of-the-web, which is on nearly every download and
  is the reason a naive ADS check is all false positives.
- **LNK abuse.** A shortcut that displays one thing and runs another remains one
  of the most durable initial-access vectors there is. Shortcuts in Startup,
  Desktop and Downloads are checked for a script-host target, arguments that
  fetch or decode code, and an icon borrowed from a binary other than the
  target.
- **Dead-drop C2.** Commands and stolen data increasingly move through Telegram,
  Discord webhooks, paste sites and tunnel providers, so egress is ordinary
  HTTPS to a reputable host and neither a firewall rule nor an IP reputation
  feed objects. The DNS client cache is the cheapest honest view of destinations
  *by name*, which is the only level at which this is visible at all.
- **Invisible Unicode.** Zero-width and bidirectional-override characters in a
  command line make displayed text differ from executed text. Run keys, RunMRU
  and shortcut arguments are checked; there is no legitimate reason for these
  characters to appear in any of them.

## Auditing the monitor itself

`jarvis coverage` answers the question that decides what every other module's
silence is worth: *can this system currently see?*

The failure it exists to prevent has already happened here once. The daemon ran
for hours reporting every Windows collector as healthy while the interop socket
was dead — each job had a timestamp, each timestamp looked recent, and every one
of them was a stale snapshot being re-read. **A clean report and no report look
identical unless something is specifically checking.** So:

- a collector that has never produced a result is reported as *missing*, not
  clean;
- a result older than twice its own interval is *stale*, and stale is a failure;
- a check that could not run says so where its result would have been;
- degraded coverage names what specifically is invisible because of it — not
  "running unprivileged" but *which* checks that costs.

It also verifies the continuity chain end to end (service active, enabled,
linger on) and restates the limits that no amount of work here removes: this
samples rather than intercepts, it has no kernel component, and WSL is not a
security boundary.

## Screen, microphone and camera

Windows keeps a consent ledger for far more than the microphone and camera, and
the entries that matter most for surveillance were the ones nobody reads:
`graphicsCaptureProgrammatic` and `graphicsCaptureWithoutBorder` (screen
capture, the second without the recording border being shown),
`userNotificationListener` (reads every notification you receive),
`appDiagnostics` (reads other processes' state), `humanInterfaceDevice` and
`gazeInput`. Every capability Windows tracks is now read, each one with the
timestamps of every app that used it and whether it is in use *right now*.

Reading all of them means reading a lot of uninteresting ones — sixteen apps
check Wi-Fi state — so capabilities are tiered by what they actually expose.
Surveillance-relevant ones are reported per app and escalate if used in the last
24 hours; routine ones collapse to a single counted line, so the camera entry is
never buried under connectivity checks.

**The WSL side has no consent ledger at all**, and this is the gap WSLg opens:
every process in the distro gets an X11 display, a Wayland socket and a
PulseAudio server. X11 has no isolation between clients — anything that can open
`:0` can screenshot the whole desktop and read every keystroke sent to any
window, with no prompt and no record anywhere. So processes are mapped to the
display and audio sockets they hold open (via `/proc/net/unix` inode matching),
and the exposure itself is reported whether or not anyone is currently using it.

## Security of the dashboard itself

Binding to `127.0.0.1` is **not** sufficient on its own. A page you visit can
point a hostname it controls at `127.0.0.1` (DNS rebinding); the browser then
treats it as same-origin with the dashboard and can read every response — which
for this tool is a complete map of the machine's firewall gaps, processes and
external peers. So:

- the `Host` header is validated against an allowlist, which is what actually
  defeats rebinding;
- `/api/run` is POST-only and rejects cross-site requests via `Sec-Fetch-Site`;
- a strict CSP forbids the page from loading anything external.

## Finding commodity spyware

The sophisticated end of this needs a kernel driver to catch. The unsophisticated
end — which is most of it — leaves traces that `jarvis spy` reads directly:

- **The capability ledger.** Windows records which application used the
  microphone, camera or location and exactly when, in
  `CapabilityAccessManager\ConsentStore`. Anything recording you through the
  normal APIs appears here, with timestamps.
- **Autostart signatures.** Monitoring tools must survive reboot, and almost
  none are signed by a recognizable publisher. Every autostart binary gets an
  Authenticode check; unsigned *and* in a user-writable directory is the shape
  that matters. Shortcuts are followed to their target first, since a `.lnk`
  carries no signature of its own.
- **Input devices.** Anything that can change your volume or type for you is
  either an HID consumer-control device or software holding an input hook. Both
  are enumerated, deduplicated per physical device.
- **The keyboard stack itself.** A keylogger that wants every keystroke
  regardless of focus has a small number of durable options, and each leaves an
  artifact: a **class filter driver** layered above `kbdclass` (which sees
  scancodes before any application does — the stock value is exactly
  `kbdclass`, so anything else is a discovery), a **lower** filter driver
  (closer to the hardware than anything else in the stack, and almost never
  legitimately occupied), a kernel **Scancode Map**, or an **IFEO debugger on an
  accessibility binary** like `sethc.exe`, which runs as SYSTEM from the logon
  screen before anyone signs in. Hardware is covered from the other side: an
  inline USB keylogger has to enumerate as a keyboard in order to pass
  keystrokes through, so both the currently-present keyboards and the machine's
  full USB enumeration history are checked — the latter catches a device that
  was attached once and taken away.

`jarvis asep` covers the persistence surface past Run keys, which is where
anything trying to stay quiet actually lives: `AppInit_DLLs` and Image File
Execution Options debuggers (which inject into *other* processes rather than
starting one of their own), the Winlogon chain, Active Setup, per-user COM
hijacks, LSA packages, print monitors, netsh helpers, time providers, Explorer
extensions, the screensaver, and the `sethc.exe` / `utilman.exe` accessibility
backdoor that runs as SYSTEM from the logon screen before anyone signs in. It
also reads **UserAssist**, Windows' own record of which GUI programs were
launched and how often.

The rule throughout is to flag the **path, not the presence**. Every one of
these extension points is populated on a healthy machine — per-user COM
registrations are how OneDrive and Teams work. What matters is a registration
whose target sits in a world-writable directory, points at a scripting host, or
doesn't exist at all (an empty slot anything could fill).

## Why windows flash open and close at startup

A console window that appears for a fraction of a second is a process with a
console attached that exited immediately — `cmd.exe /c`, `wscript`, a `.bat`, or
PowerShell without `-WindowStyle Hidden`. Interval sampling will never reliably
catch one, so `jarvis boot` does not try. It reconstructs the event afterwards
from Task Scheduler's operational log, the autostart inventory filtered to
entries that *would* show a window, and the Application log. Cross-referencing
those usually names the culprit outright.

If the task-history log is empty, enable it once in Task Scheduler → View →
Show All Tasks History, and the next boot will be fully reconstructable.

## How it decides something is unauthorized

Two independent signals combine into one severity, which is what keeps a
baseline system from either screaming at every software update or going quiet
when something hides behind an approved name:

1. **Drift** — the process fingerprint (executable + normalized command line +
   user) is not in the approved baseline. A new invocation of `/usr/bin/tail`
   is logged quietly; a new binary running out of a home or temp directory is
   not.
2. **Traits** — what the process looks like regardless of the baseline:
   encoded command lines, `curl | sh` pipelines, execution from world-writable
   directories, a deleted executable still running, a name that doesn't match
   its binary, listening on all interfaces, egress to public IPs.

A trait on an approved process still gets flagged.

## Licences and payments (Argus)

Protection never needs a licence: detection, collectors, alerts, evidence and on-demand checks run the same with or
without one (`tests/test_licence_never_gates_core.py`). A licence unlocks the premium content only, today the full
review report.

**Buying.** Argus is sold through Stripe Checkout at `https://pay.archymedes.xyz/buy/argus-server` ($50 per server
per year, one server) and `/buy/argus-desktop` ($79 per year, one computer), with Stripe Managed Payments (Stripe is
the merchant of record). The checkout and licence service is the Cloudflare Worker in `hosted/licence-cloudflare`.
In the desktop app and in the web dashboard, **Pricing → Buy for this computer** opens that checkout (a claim
this computer started) and the computer activates by itself when the payment goes through; nothing to type. There
is no local payment configuration: no install reads a Stripe key (`tests/test_no_seller_payment_key.py`). Bought on the website, the thank-you page shows the key (with Copy) and it is emailed.

**Activating.** In the desktop app, **Licence** has a paste box that checks the key as you type. On a server (the
public build names the command `argus`):

```
argus licence activate ARGUS-SRV-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX   # case, spaces and dashes do not matter
argus licence buy server        # or: buy here, and this machine activates by itself
argus licence login             # headless: approve a short code on the web instead
argus licence status            # offline: plan, renews/ends, offline lease, this machine
argus licence deactivate        # free this machine's seat, to move the licence
argus licence refresh           # renew now (it also renews by itself when the lease has under 7 days left)
argus licence auto-renew off    # turn that one automatic call off
```

A licence is a 30-day certificate signed with Ed25519 and bound to this machine and to a per-install device key. It
is checked offline; an edited or copied licence file is refused (a modified program is another matter; see below). Renewal is one HTTPS call to `pay.archymedes.xyz`,
signed by the device key. To move a licence, see where it is active, get the key again or manage billing, use
`https://pay.archymedes.xyz/manage` (sign in with the purchase email); a lost key is resent from `/recover`. The
licence service stores only hashes of keys, emails and machine ids. No seller secret reaches a customer machine.

**What it cannot do.** A check on the customer's own machine can be bypassed by modifying the program: this is
licensing meant to discourage casual key sharing, not DRM. The only part a modified client cannot get is content the server
delivers (`/content/<pack>`; a sample pack today). Design and its limits: `docs/LICENSING-ARCHITECTURE.md`.

Owner setup and support: `docs/BILLING.md` (plans, keys, runbooks) and `docs/STRIPE-HANDOFF.md` (Stripe objects,
restricted keys, webhook). Prices and Stripe lookup keys come from the shared price book in the archymedes-gtm
repository (`catalog/stripe.ts`).

## What it does not do

- It is **not** a kernel-level EDR. It samples on an interval, so a process
  that starts and exits between passes is missed. For gap-free Linux execution
  logging, pair it with `auditd`.
- Without an **elevated PowerShell**, Windows Defender exclusions and some
  service details are unreadable — the audit tells you when this happens rather
  than reporting a clean result it can't actually see.
- WSL is not a security boundary. Anything in WSL can read and write `/mnt/c`,
  and the Windows side can see into WSL. Treat findings on either host as
  findings about one machine.
- Presence of a remote-access agent (TeamViewer, AnyDesk, RMM tooling) is
  reported because it grants control — not because it is necessarily malicious.

## Files

The package is layered; a module imports only from its own layer or the ones
above it in this table (`tests/test_layers.py` enforces it). See
`docs/architecture/TARGET.md` for the rules.

| path | purpose |
|---|---|
| `jarvis/core/` | SQLite store, retention policy, indicator vetting, shared paths and helpers |
| `jarvis/platform/` | `/proc` walker (`linux.py`), WSL interop and the PowerShell runner (`windows.py`), `win/*.ps1` payloads, Windows sensor ingest (`native/`) |
| `jarvis/collectors/process/` | scan orchestration, trait scoring, hidden processes, memory, evasion, resource pressure |
| `jarvis/collectors/telemetry/` | Sysmon, Sysmon for Linux, auditd |
| `jarvis/collectors/persistence/` | autostarts, startup reconstruction, control surfaces, implants, backdoors |
| `jarvis/collectors/network/` | firewall, network state, internet-facing apps, packet capture, web shells |
| `jarvis/collectors/identity/` | failed-auth spikes, plaintext secrets, impersonation |
| `jarvis/collectors/host/` | posture, spyware, injected input, intrusion artefacts, developer toolchain, devices, capture/tracking pixels |
| `jarvis/intel/` | threat-intel research, bulk feeds, the indicator hunt and coverage gaps |
| `jarvis/response/` | alerting, digests and advisory (`reporting/`), remediation, the alert ledger, evidence cases, startup tracing |
| `jarvis/service/` | job table, job runner, scheduler, self-audit and watchdogs |
| `jarvis/web/` | localhost dashboard server and `static/dashboard.html` |
| `jarvis/cli/` | command-line interface |
| `scripts/harden/` | Linux and Windows hardening |
| `scripts/repair/` | targeted repair and remediation scripts, repair-helper installer |
| `scripts/maintenance/` | re-wrapping the installed Windows monitor tasks |
| `jarvis-wake-watchdog.ps1`, `jarvis-health-monitor.ps1`, `jarvis-reviver.ps1`, `jarvis-connectivity-guard.ps1`, `jarvis-elevated-broker.ps1` | Windows supervisor tasks, each file named after the scheduled task it installs; they stay at the root because installed copies sync from this path ([naming and migration](docs/guides/WINDOWS-SUPERVISOR-NAMES.md)) |
| `systemd/`, `sysmon/` | units, drop-ins, sudoers rules, Sysmon for Linux policy |
| `docs/guides/`, `docs/reports/` | operating guides and dated investigation reports |

State lives in `~/.jarvis/jarvis.db`.

### Privileged repairs and independent Windows monitoring

`jarvis repair status` verifies the Linux monitor, Sysmon, journal, and Windows
mount. `jarvis repair all` repairs unhealthy components; individual actions are
`monitor`, `telemetry`, `journal`, and `mount`. Install the root-owned helper with
`sudo bash scripts/repair/install-repair-helper.sh`. Its sudo rules permit only these fixed
actions; Windows administrator operations still require Windows elevation.

`jarvis-health-monitor.ps1` runs from `%LOCALAPPDATA%\Jarvis\HealthMonitor` as a native
Windows scheduled task, independent of WSL. It checks scheduler progress every
minute, confirms outages across two probes, and sends toast/email notifications
with one-time 1h/6h/24h escalation and recovery notification. Its `mail.json`
contains the existing sender/recipient and a Windows-user DPAPI-encrypted key.
Installation requires staging that credential and running the script with
`-Install`; `-ProbeOnly` checks health without sending notifications.
