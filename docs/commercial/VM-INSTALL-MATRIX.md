# Clean-machine install matrix: ARGUS-1 server edition

Status: **harness built; runs in progress** (2026-11-02). This is the first blocker to the paid observed server
review (PMF-2026-11.md, Phase 5) and QC blocker 2 (`docs/security/QC-ARGUS-1-2026-10-27.md`).
Nothing in `jarvis/core/assurance.py` moves until a row below has a measured result.

## What exists today, and the gap

| Piece | What it does | Gap for this matrix |
|---|---|---|
| `release/install_test.sh` (CI job) | Native tarball and `.deb` from the CI build: install, service active as `argus`, health answers, native CLI runs, verification report ok, no Python in `/opt/argus`, 90 s with no traceback, then uninstall/purge leaves nothing | Runs only on the GitHub runner (Ubuntu), and Actions is blocked by billing. No upgrade, no footprint, no Debian |
| `~/archymedes-site/scripts/argus/vmtest.py` + `vmtest_guest.py` | Disposable Ubuntu 24.04 KVM guest through `jarvis/lab/vmlab.py` (network-less container, copy-on-write overlay, base image verified unchanged). Plants 16 scenario checks; samples RSS, cgroup memory, CPU; removes and purges | Last run (2026-10-30, 16/16) used the **old site-built Python `.deb`** (`argus-server_2026.10.30_all.deb`), not the signed native release. `vmlab.IMAGE_NAME` is hardcoded to Ubuntu noble. No upgrade step. Observation is 10 minutes, not an hour |
| Signed release `v2026.10.30-2` (GitHub, Argus-1) | `argus-server-linux-x86_64.tar.gz`, `argus-server_2026.10.30.2_amd64.deb`, `SHA256SUMS` + `.sig`, SBOM | **Never installed on any VM.** It also lacks `argus review` (on `feat/pmf-ready`) and the #12 alert fixes |

Baseline to compare against (2026-10-30 run, old Python `.deb`, 1 vCPU / 1.5 GB guest):
install 10.8 s, first API answer 11.1 s, daemon RSS 72 MB, cgroup 175 MB, state on disk 5 MB,
0 tracebacks, remove and purge clean. These are **not** figures for the native release.

## Targets

The native program needs glibc 2.28+ (pinned `manylinux_2_28` build, `release/build_server.py`).

| # | Distro | Why | Image | Harness status |
|---|---|---|---|---|
| T1 | Ubuntu 24.04 LTS | Most common small-agency VPS image | `noble-server-cloudimg-amd64.img` (already in the lab, SHA256SUMS checked) | Ready |
| T2 | Debian 12 | Second most common VPS image; required by PMF Phase 5 | `debian-12-genericcloud-amd64.qcow2` + Debian `SHA512SUMS` | Needs `vmlab` image parameter (see Harness changes) |
| T3 | Ubuntu 22.04 LTS | Still widespread on older droplets | `jammy-server-cloudimg-amd64.img` | Same change as T2 |
| T4 | Rocky/Alma 9 | Tarball only (no RPM); tells us whether RHEL-family clients can be offered a review | GenericCloud qcow2 + `CHECKSUM` | Same change; `pkgverify` limit already says "never run on an RPM system" |
| T5 | One real VPS the owner controls | Internet background noise, real systemd and cloud-init, real reboot | Owner provides; not disposable | Owner decision 5. Run last, only after T1 and T2 pass |

T1 and T2 are the gate for the first paid review. T3 and T4 widen the offer; they do not block it.

## Scenarios per target

Each cell is run once per package (`tarball`, `deb`; T4 tarball only) on a fresh overlay.

| ID | Scenario | Pass when |
|---|---|---|
| S1 | Verify, then install from the published files | `SHA256SUMS.sig` verifies against `release/allowed_signers`; checksum matches; installer exits 0 |
| S2 | First run | `argus.service` active as `argus`; `/api/health` answers `ARGUS`; `argus welcome server` prints; no Python in `/opt/argus` |
| S3 | Planted scenario | The 16 `vmtest_guest.py` checks pass with no secret value shown (port the guest to call the native `argus` CLI) |
| S4 | Idle footprint | After 60 minutes of idle observation: RSS, cgroup memory, CPU seconds per hour, disk under `/var/lib/argus`, 0 restarts, 0 tracebacks |
| S5 | Observed review | `sudo -u argus -H argus review --days 1` writes an owner-only file; every section has a state; no secret value in the file |
| S6 | Reboot | Service is active again after `reboot`; the heartbeat and scheduler receipts resume; review shows no false "observed" for the gap |
| S7 | Upgrade | Install `v2026.10.30-2`, run 10 minutes, upgrade to the candidate; baseline and history kept; unit active; no duplicate account |
| S8 | Remove | `apt remove` / `uninstall.sh`: unit, `/opt/argus`, CLI gone; history kept |
| S9 | Purge | `apt purge` / `uninstall.sh --purge`: `/var/lib/argus`, `/etc/argus`, `argus` account gone; base image unchanged after the run |

TTHW (time to first finding, devex-review) is measured in S1 to S3: from download start to the first
finding shown by `argus investigate`.

## Measurements recorded per cell

`distro`, `kernel`, `glibc`, `systemd`, `package`, `release version and digest`, `install_s`,
`api_first_answer_s`, `tthw_s`, `rss_mb`, `cgroup_mb`, `cpu_s_per_h`, `disk_state_mb`, `restarts`,
`tracebacks`, `scenario_passed/16`, `review_states`, `secret_shown`, `upgrade_ok`, `remove_ok`,
`purge_ok`, `base_image_unchanged`, `host_load_before`. Output: `vmtest-<distro>-<package>.json`
next to the release files, kept with the release evidence.

Footprint budget to accept (owner may change): idle RSS under 150 MB, idle cgroup memory under
300 MB, idle CPU under 60 s per hour on 1 vCPU, state under 50 MB after an hour. A miss is
recorded, not hidden; the review offer then states the measured figure.

## Harness (built 2026-11-02, owner-approved)

Lives in this repository, versioned with the release it checks:

| File | Role |
|---|---|
| `jarvis/lab/vmlab.py` | `IMAGES` registry (file, checksum list, sha256/sha512) and `Config.image`; unknown or mismatched image fails closed; `Config.allow_reboot` (off by default) drops `-no-reboot` without touching isolation |
| `release/vmtest/fetch_image.py` | Downloads an image to a `.part` file, checks it, then renames. Ubuntu lists must carry a gpg signature by the pinned Canonical cloud-image key (lab-only keyring); Debian signs nothing, so its image comes from the fixed dated build `20261026-2643` and is recorded **https-only** |
| `release/vmtest/vmtest.py` | One cell per run: verifies the release signature (pinned releaser) and package digest before any guest starts, builds the payload, boots the guest, checks the result hash and the harness hash, writes `vmtest-<distro>-<package>-<time>.json` with a per-scenario summary against the budget |
| `release/vmtest/guest.py` | Phase 1: S1, S7 (if `--upgrade-from`), S2, S3 (16 planted checks, neutral `vmuser`), S4, S5, then one reboot. Phase 2 (one-shot unit that marks itself started first): S6, S8, S9 |
| `tests/test_vmtest.py` | 35 tests: refusals (unsigned, unpinned, mismatched, unlisted, unknown image), fail-closed fetch, cleanup on helper failure, timeout and Ctrl-C, verdict rules. Mutation checks: 5 of 6 deliberate breaks caught; the sixth (S1) is covered by a duplicate comparison |

Image trust, measured 2026-11-02: Ubuntu 24.04 list signature verified (signer
`D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`; it had only been hash-checked before); Debian 12
hash verified, **https-only**.

Run a cell (serially, never two at once):

    python3 release/vmtest/fetch_image.py debian-12            # once per image
    python3 release/vmtest/vmtest.py --release DIR --distro ubuntu-24.04 --package tarball

`v2026.10.30-2` is the only signed release, so S7 (upgrade) reports "not run" until a newer
signed release exists. That release has no `argus review`, so S5 also reports "not run".

Jev (jev-1.14.0, advisory, `scripts/reviews/vm_matrix_advisory.py`): Debian https-only with
the label acceptable 0.83; top remaining gap "not yet run end to end" 0.35 (low confidence,
Debian trust 0.32 close behind); smoke run before the hour-long runs 0.61.

## Smoke runs, 2026-11-02 (Ubuntu 24.04, tarball, signed `v2026.10.30-2`, 2-minute idle)

First installs of the signed native release on any VM. Measured, short windows only:

| Run | S1 | S2 | S3 | S4 | S5 | S6 | S7 | S8 | S9 | Isolation |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 (09:19Z) | pass | pass | 2/16 | within budget | not in release | fail | not run | pass | pass | ok |
| 2 (11:44Z) | pass | fail | **16/16** | over CPU | not in release | fail | not run | pass | pass | ok |
| 3 | killed by a Windows host crash during S4 | | | | | | | | | orphans swept |

What the failures were (all harness bugs, fixed after each run, none in the product so far):
- Runs 1 and 2: the release requires a credential on every API route; the guest read
  `/api/state` without one, saw no jobs, and so failed S3 (run 1) and could not see receipts
  after the reboot (S6). The guest now sends the token on every request.
- Run 2 S2: the health check then sent the token too; the authenticated body does not carry
  the `"ARGUS"` service name the check looks for. The check is now anonymous, as an outside
  probe (and `release/install_test.sh`) sees it.
- Run 2 S6: `/api/state` still listed no jobs after the reboot, cause not yet known. S6 now
  also reads the newest run receipt straight from the store (read-only) and records the API
  shape and the journal for this boot.
- Run 2 S4 "over CPU" (366 s/h) is a 2-minute window right after the planted scenario, not
  idle. Only the 60-minute run decides S4.

Measured so far: install 36.5 s (run 2), first API answer 37.6 s, RSS at most 120 MB,
cgroup at most 194 MB, state 5 MB, no tracebacks, removal and purge clean, 16/16 planted
checks, no secret value in findings.

**Host stability (owner decision before more runs).** Windows restarted uncleanly three
times on 2026-11-02 (Kernel-Power 41, no bug check recorded): before 12:15, at 12:14 and about
13:54 local. The 13:54 one ended smoke run 3; the two earlier ones had no VM running. Nested
KVM adds load to a host that already hard-resets, so the hour-long cells wait for the owner's
go-ahead, or move to another machine or a real VPS. `vmtest.py` now sweeps run folders a
killed run leaves behind (only run-id folders, older than an hour, with no container).

## Run order and host limits

Run serially, one guest at a time, never while the host is loaded (memory
`wake-jarvis-shutdowns`: parallel load degrades WSL interop and triggers `wsl --shutdown`).
`vmlab` already refuses under CPU or memory pressure. Rough cost: about 75 minutes per cell
(60 minutes idle), so T1 and T2 with both packages is about 5 hours of serial guest time.

1. Candidate release: a signed release that includes `feat/pmf-ready` (`argus review`) and #12.
   Blocked on Actions billing. Until then, T1/T2 can run against `v2026.10.30-2` for S1-S4 and
   S6-S9, which already answers whether the native binary installs cleanly.
2. T1 tarball, T1 deb, T2 tarball, T2 deb.
3. Record results; update `native_host_portability` and the server capabilities in
   `assurance.py` only with the measured rows and their limits.
4. T5 on the owner's VPS, then T3 and T4 if the offer widens.

Jev (jev-1.14.0, advisory): run the existing signed native release on Ubuntu 24.04 and Debian 12
now rather than wait for the candidate (0.90, confidence 0.85); a real VPS first 0.01.

## Owner decisions this needs

- Approve the harness changes above (they touch the lab isolation code).
- Accept or change the footprint budget.
- Provide or approve a real VPS for T5.
- Fix Actions billing so the candidate release can be built and signed.
