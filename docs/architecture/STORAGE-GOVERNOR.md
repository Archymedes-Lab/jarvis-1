# Storage governor: keeping the machine from filling its only disk

Written 2026-10-23 after the second disk-full crash of WSL in twelve days.

## The problem, measured

One NVMe, one volume. There is nowhere else to put anything.

| Item | Measured 2026-10-23 | Behaviour |
|---|---|---|
| C: (the only volume) | 474.3 GB, 0.1 GB free at 00:40, 2.7 GB free at 00:55 | everything below lives here |
| WSL disk image `ext4.vhdx` | 246 GB on disk, 223 GB used inside the guest | grows with every guest write, never shrinks by itself |
| WSL swap `swap.vhdx` | 8 GB, fixed path | fixed size since 2026-10-11, cannot fail to grow |
| Windows page file | automatic, 12.4 GB allocated, 5.9 GB in use | grows under memory pressure; cannot grow on a full drive |
| Host RAM | 16 GB, 326 MB free at 00:50 | WSL VM holds up to 8 GB of it |
| Reclaimable inside the guest, owner's caches | uv 26 GB, go-build 5.8 GB, Playwright 2.3 GB, Puppeteer 1.3 GB | nobody prunes them |
| Reclaimable inside the guest, Docker | 7 GB (images 4.3, stopped containers 1.4, build cache 1.1) | nobody prunes it |
| JARVIS's own data | store 0.78 GB, event history 1.1 GB sealed, release stages 1.7 GB, journal 0.38 GB | retention exists for history and the store; stages accumulate |
| rsyslog copies of the Sysmon journal | 9.2 GB under /var/log (syslog 4.1 GB and still growing, syslog.1 4.0 GB, rotated archives); 2,941 of 3,000 sampled lines are Sysmon events | nothing reads them; JARVIS reads the journal |

What happened both times (2026-10-11 and 2026-10-23 at 00:29): the drive
reached 0.1 GB free; the guest's writes failed; journald logged "Under
memory pressure" and then stopped; processes died on I/O errors (five
Chromium crash dumps in one second); the WSL relay stopped accepting; every
`wsl.exe` call from Windows returned 0x8007274c; the keepalive client lost
the VM; WSL relaunched it, and the first relaunch failed to start init
within 10 s because the host had 326 MB free. JARVIS, Docker, Sysmon and the
sessions in flight all went down with the VM. No Hyper-V reset event, no
kernel panic file: the VM did not crash, it suffocated.

Freeing space inside the guest does not help by itself. The image is a
dynamically expanding VHD: deleting 40 GB inside Linux leaves the file at
246 GB on C: until the blocks are returned, which needs either sparse mode
(WSL releases discarded blocks on the fly) or an explicit compaction with the
VM stopped.

## Invariants the design must keep

1. The system drive always keeps enough headroom for the page file and the
   WSL image to grow through one bad hour. Headroom is a number, not a
   feeling: 8 GB high, 2 GB critical, measured every run.
2. JARVIS never deletes the owner's data. It measures, names the command,
   and deletes only what JARVIS itself created for the purpose of being
   deleted (its own superseded release stages, its own ballast file) within
   written budgets.
3. Automatic intervention is bounded and visible: the only automatic act is
   releasing the ballast file when the drive is below the critical line, and
   that act is a critical finding that pages the owner.
4. Evidence survives pressure: the store and the sealed event history are
   never pruned by this governor; their own retention keeps them bounded,
   and the governor only reports their size.
5. The governor's own cost is bounded: one PowerShell read a run for the
   host side, `du`-free measurement on the guest side (directory walks are
   sampled with a time budget, never unbounded), no network.
6. Failure is explicit: a measurement that cannot be taken is a visibility
   finding, never a silent "fine".

## Three layers

### Layer 1: capacity (owner, one-time)

The image must stop being a one-way valve.

- Sparse mode on the distro image so blocks freed inside Linux return to
  Windows as they are discarded. Done with the VM stopped:
  `wsl --shutdown` then `wsl --manage Ubuntu --set-sparse true`. After the
  next start, `sudo fstrim -av` once returns everything already freed. The
  cost: sparse images fragment and WSL's own documentation warns of
  corruption risk when the host disk fills while a sparse write is in
  flight, which is exactly why layer 2 keeps headroom.
- Alternatively, no sparse mode and a scheduled compaction: `wsl --shutdown`,
  then `diskpart` with `select vdisk file=<ext4.vhdx>`, `attach vdisk readonly`,
  `compact vdisk`, `detach vdisk`. Needs an administrator and a stopped VM,
  so it is a maintenance act, not a steady state. The governor reports when
  the image exceeds the in-guest usage by more than 20 GB so the owner knows
  compaction is due.
- A fixed-size page file (initial = maximum, 8 GB) so the commit limit stops
  moving and the page file can never be the thing that fails on a full drive.
- The one-time reclaim that pays for the next months: the owner's package
  caches and Docker leftovers, about 42 GB, each with its command in the
  closure sheet.

### Layer 2: headroom (JARVIS, continuous)

A `storage` collector every 30 minutes:

- Host side (one PowerShell read): system-drive free and total, `ext4.vhdx`
  size, swap and page file sizes and the page-file policy (automatic or
  fixed), whether a ballast file exists and its size.
- Guest side: filesystem used from `statvfs` (not `du`), the sizes of the
  known reclaimables with a bounded walk (`~/.cache/uv`, `~/.cache/go-build`,
  Playwright, Puppeteer, `~/.cache/jarvis-release-staging`,
  `/var/log/journal`), Docker's `system df` figures when the socket answers,
  and JARVIS's own stores from their known paths.
- Findings:
  - critical "system drive nearly full" under 2 GB, high under 8 GB, with
    the measured chain and the reclaim commands;
  - a growth rate from a bounded history of free-space samples (last 24 h,
    at least 2 h apart) and the days left to the critical line; high under
    2 days, medium under 7. Jev's design review named this the missing
    piece (0.85), so the owner is warned in days, not at the line;
  - medium "syslog copies of the Sysmon journal" when /var/log holds more
    than 4 GB of them, with the rsyslog drop-in that stops the copy;
  - high "WSL image is N GB larger than what it holds" when
    `vhdx − used` > 20 GB: compaction or sparse mode is due;
  - medium "page file is automatic" while it is, because an automatic page
    file on a nearly full drive is one of the two growth paths;
  - low inventory of the reclaimables with their commands, so the owner can
    act before the critical line;
  - visibility findings when the host read or a guest walk failed.
- Its own housekeeping, within budget: release stages beyond the three
  newest that are neither deployed nor the live base are removed (JARVIS
  created them; the deployed copies live in `/opt/jarvis/releases`).

### Layer 3: ballast (bounded automatic rescue)

A ballast file is space reserved in advance so that it can be given back in
an emergency: `fsutil file createnew %LOCALAPPDATA%\Jarvis\ballast.bin 4294967296`
(4 GB, no administrator needed, created once by the owner or by
`jarvis storage ballast --create`).

When the collector measures the system drive below the critical line while
the ballast exists, it deletes the ballast, which immediately gives the page
file and the image 4 GB to live on, records the act in the event log, and
raises a critical finding that pages the owner. It does nothing else
automatically. It never recreates the ballast on its own: recreating it on
a drive that is still short would just consume the headroom it bought.

Why this and not an automatic cache purge: the caches are the owner's, their
value is the owner's to judge, and a purge that runs when the drive is already
failing may itself fail. The ballast is a pre-paid, pre-approved deletion of
a file that exists for no other reason.

## Rejected designs

- Move the image to another disk: there is no other disk.
- Automatic `docker system prune` or `uv cache clean`: deletes the owner's
  data on JARVIS's judgment; refused by invariant 2.
- Shrink `.wslconfig` memory further to relieve the page file: the daemon
  and Docker already live in 8 GB with two agent sessions; the problem is the
  disk, not the VM's share of RAM.
- systemd-oomd or a user.slice memory ceiling: a real memory lever, but this
  distro ships no oomd binary and a ceiling on user.slice is the owner's
  policy on their own interactive work; it was offered and declined on
  2026-10-23. It is not a disk fix.

## What would cause reconsideration

A second volume appearing (then the image moves there and layers 2 and 3
shrink to a report). A WSL release that compacts the image on its own. The
ballast being released more than once a month, which would mean the
headroom budget, not the ballast, is wrong.

## Advisory review (Jev, 2026-10-23, metadata only)

Releasing a pre-reserved ballast as the single automatic act: bounded and
consistent with the invariants, 0.93. Sparse mode with the 2/8 GB guard
versus scheduled compaction only: 0.51, a coin toss, so both are offered and
the owner picks; the guard is the same either way. Headroom pair 2 GB / 8 GB
chosen over 5/15, 10/30 and 1/4 with 0.92. Missing piece: a growth rate
(0.85), now built in. Jev cannot approve the design; the tests and the live
read on this host are what establish it.

## Rescue order for 2026-10-23

0. Stop the duplicate log first, it is the fastest 9 GB inside the image:
   `sudo install -Dm644 systemd/rsyslog-sysmon.conf /etc/rsyslog.d/10-jarvis-sysmon.conf`,
   `sudo systemctl restart rsyslog`, `sudo rm -f /var/log/syslog.[0-9]*`,
   then `sudo truncate -s 0 /var/log/syslog` (the live file is 98 % Sysmon
   copies; the journal keeps the evidence).

1. Inside WSL, the owner's choice, about 42 GB: `uv cache clean`,
   `go clean -cache`, `docker system prune` (`-a` for unused images too),
   remove `~/.cache/ms-playwright` and `~/.cache/puppeteer` if unused.
2. From Windows: `wsl --shutdown`, `wsl --manage Ubuntu --set-sparse true`,
   start the distro, `sudo fstrim -av`. Read `ext4.vhdx` back; it should drop
   by roughly what step 1 freed.
3. Fix the page file at 8 GB (System > Advanced > Performance > Virtual memory).
4. Create the ballast: `fsutil file createnew %LOCALAPPDATA%\Jarvis\ballast.bin 4294967296`.
5. Deploy the release that carries the `storage` collector and read its first
   snapshot: system-drive free, image overhang, page-file policy, ballast present.
