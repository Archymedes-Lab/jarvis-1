# Argus on Linux servers

Status: design 2026-10-24. Owner request: "prepare Argus for Linux servers, make sure it will
protect infra well", plus analysis of incoming packets. Owner decisions (2026-10-24): flows and
a header-only packet sampler (no payloads); validate in a local, non-privileged systemd
container; alert channels webhook, ntfy and syslog besides email; installer and unit changes in
`~/archymedes-site` are staged as a patch, not edited (another session owns that tree).

## Measured starting point (survey 2026-10-24)

Argus's server edition exists (`~/archymedes-site/scripts/argus/server`): an unprivileged `argus`
account with CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH and CAP_SYSLOG, root-owned sealed code that
verifies itself at install, a loopback dashboard, MemoryMax 1G and CPUWeight 50. Its Linux
collectors are real host checks (SSH keys and config, sudoers, accounts, systemd and cron
persistence, brute force, web shells, hidden processes and modules, Docker socket, secrets,
auditd). What stops it protecting a server well:

| # | gap | evidence |
| --- | --- | --- |
| 1 | every established connection to a listening port from a public address is **critical** | `firewall.py` `audit_linux` |
| 2 | firewall posture is "is iptables empty"; nftables, ufw, firewalld never read | same |
| 3 | `netwatch` (Wi-Fi + Windows logs) is PowerShell-only: unavailable on every Linux run | `netwatch/sample.py` |
| 4 | `storage` reports "not watched on the Windows side"; no Linux disk-full watch | `storage.py` `audit` |
| 5 | the `wsl` job runs on any Linux (gated on has_linux, not on_wsl) | `wslguard.py` `audit` |
| 6 | no successful-login, new-source or new-key tracking | `bruteforce.py` counts failures only |
| 7 | package ownership is `dpkg -S` only: on RPM systems every file reads "unowned" | `core/util.py` |
| 8 | one alert channel (Resend email) | `response/alert.py` |
| 9 | no packet- or flow-level visibility at all | survey |
| 10 | plain Linux has never run end to end | `NATIVE-HOSTS.md` |

## Invariants

- **I1 Unknown is not clean.** A source that cannot be read (no capability, no tool, a parse
  failure) is reported as not observed with the reason, never as an absence of findings.
- **I2 Not applicable is not healthy.** A collector with nothing to observe on this machine is
  absent from the schedule with a reason, never run as an empty success.
- **I3 Noise is a protection failure.** Expected service traffic is not a finding; what is
  reported must be actionable. Declared services lower severity only for the declared port and
  protocol, never for anything else on the host.
- **I4 Least privilege, separated.** The daemon gains no capability. Packet capture and firewall
  reading run in separate, minimal units, each with one capability, writing data the daemon
  ingests. Nothing they read can instruct them.
- **I5 Privacy.** No packet payload is stored or sent. The sampler keeps headers only (kernel
  truncation to the header length) and DNS query features, not names. Remote addresses are
  stored for detection with bounded retention.
- **I6 Bounded resources.** Every new sensor has a CPU, memory, disk and packet-rate ceiling,
  counts what it drops, and reports drops as reduced visibility rather than hiding them. The
  server's workload stays first.
- **I7 Evidence continuity.** Sensor windows carry sequence numbers; a gap, a stale sensor or a
  restart is reported as a gap, never silently stitched.
- **I8 Delivery is explicit.** Every configured channel's outcome is recorded; "no channel can
  reach you" stays critical until one can; a failing channel never blocks another.
- **I9 Existing behaviour on the WSL workstation is unchanged** (finding identities, labels,
  schedule), except where this document says so.

## Design

### W1. Honest applicability (gaps 3, 4, 5)

- Add the registry domain `"wsl"` (needs a WSL guest *and* its Windows host) for the `wsl`
  job; move `netwatch` to `"windows"` (it has nothing to observe without Windows). Both are then
  NOT_APPLICABLE on a plain server with a reason (I2). The mechanisms golden test records these
  two declared changes explicitly.
- `storage` gains a Linux branch on KIND=linux: free space and inodes per real mount
  (`os.statvfs`, pseudo and read-only filesystems skipped), growth rate from history, and the
  journal and Argus state sizes. Thresholds as on the workstation (warn low, critical very low).

### W2. Exposure: declared services and a real firewall view (gaps 1, 2)

- `/etc/argus/services.conf` (and `~/.jarvis/services.json` for the workstation): the services
  this server is meant to expose, as `port/proto [source-cidr ...]`. The installer pre-fills it
  from what listens on public addresses at install time, commented, for the owner to confirm.
- Linux firewall audit rewritten:
  - inbound connections are aggregated per local port: declared port → no finding (counted
    in the summary); undeclared port reached from a public address → high; from a private
    address → medium. Never one finding per connection.
  - listeners on wildcard or public addresses that are not declared → medium, high if the
    firewall view says the port is reachable.
  - firewall view from the `argus-netstate` oneshot (below): nftables ruleset as JSON
    (`nft -j list ruleset`), plus `ufw status verbose` / `firewall-cmd --list-all` when present,
    summarised to default input policy and per-port accept rules. Without a fresh netstate
    snapshot the posture is "not observed" (I1), not "no firewall".
  - default input policy accept with an undeclared public listener → high.

### W3. Logins and package integrity (gaps 6, 7)

- New collector `logins` (domain linux, 300 s, cursor on the journal): parses sshd `Accepted`
  lines. A learned set of (user, source network /24 or /64, key fingerprint) with first-seen
  times. Findings: root login over SSH (high), password login when the server otherwise uses
  keys (high), a new key fingerprint for a user (high), a known user from a new network
  (medium), a login from an address that failed brute-force thresholds in the same window
  (critical: a guess that succeeded). The first run learns without paging except the root and
  password cases. Journal cursor stored; a cursor that the journal no longer has is a gap (I7).
- Package ownership: `dpkg -S` or `rpm -qf`, whichever manager owns the system; on neither,
  ownership is "unknown", which never escalates (I1). `pkgverify` (daily, bulk lane, governed):
  `dpkg --verify` / `rpm -Va` on the files that matter (binaries in PATH directories, PAM,
  sshd, sudo, libc, the loader), reporting changed digests of packaged files.

### W4. Alert channels (gap 8)

`alert.deliver(conf, subject, text, html)` replaces direct `send_email` calls and fans out to
every configured channel, independently (I8):

| channel | config | transport |
| --- | --- | --- |
| email | existing Resend keys | unchanged |
| webhook | `webhook_url`, `webhook_secret` | JSON POST over HTTPS, `X-Argus-Signature: sha256=HMAC(secret, body)`, timestamp in the body |
| ntfy | `ntfy_url` (topic URL), optional `ntfy_token` | POST text, `Title` and `Priority` headers |
| syslog | `syslog: true` | one structured line per alert to the local journal (`logger`-compatible socket `/dev/log`), so an existing forwarder ships it |

Success is per channel; `deliver` returns "" when at least one channel delivered and records
each channel's last error; `enabled()` means "at least one channel configured";
`channel_findings` stays critical with none. syslog alone counts as a channel only when a
forwarder is detected (rsyslog/syslog-ng/vector/fluent-bit/promtail running), because a log
line nobody reads reaches no one.

### W5. Incoming packets (gap 9)

Alternatives compared (owner chose flows + header sampler):

| design | sees | privilege | cost | verdict |
| --- | --- | --- | --- | --- |
| conntrack netlink dump | established flows | CAP_NET_ADMIN | low | folded into netstate counters only |
| **AF_PACKET + classic BPF, header-only** | every new inbound TCP SYN, ICMP, UDP to closed ports, DNS headers | CAP_NET_RAW, separate unit | bounded by the kernel filter | **chosen** |
| eBPF / XDP counters | everything, at line rate | CAP_BPF + CAP_PERFMON, toolchain | lowest per packet | later, if the sampler's drops are measured high |
| Suricata / Zeek ingest | signatures, protocol logs | their own | theirs | optional later reader of eve.json |

**`argus-netsensor.service`**: own account `argus-net`, `AmbientCapabilities=CAP_NET_RAW` only,
`RestrictAddressFamilies=AF_PACKET AF_UNIX`, no network egress, `MemoryMax=96M`,
`CPUQuota=10%`, `ProtectSystem=strict`, writes only `/var/lib/argus/net`.

- One AF_PACKET socket per non-loopback interface with a classic BPF program that accepts
  inbound TCP with SYN and not ACK, ICMP and ICMPv6, and UDP, and returns at most the header
  length (kernel truncation: payload never reaches user space, I5). DNS responses' features are
  computed from the truncated header plus question length only.
- Minute windows in memory: per (source, destination port) counts, distinct destination ports
  per source, SYN totals per port, ICMP by type, UDP to ports with no listener, packets and
  kernel drops (`PACKET_STATISTICS`). A token bucket caps processing at a configured packet
  rate; above it, counting continues in the kernel stats and the window is marked sampled.
- Each window is written atomically as one JSON file with a sequence number, sensor boot id and
  drop counts; at most 24 h of windows are kept (bounded disk); top-N per window caps memory.

**`argus-netstate.service`** (oneshot, timer every 5 min): account `argus-net`,
`AmbientCapabilities=CAP_NET_ADMIN` only, fixed commands (`nft -j list ruleset`, `ufw status
verbose`, `firewall-cmd --list-all`, conntrack counters), no arguments from anywhere, output one
JSON snapshot. It reads; it never writes rules.

**Daemon job `netflow`** (fast lane, 60 s, domain linux): ingests windows in sequence order and
judges, with the declared services and current listeners:

| detection | rule (initial, to be tuned on measured traffic) | severity |
| --- | --- | --- |
| port scan | one source hits ≥ 20 distinct closed or undeclared ports in a window | medium; high if it then reaches an open undeclared port |
| horizontal probing of an undeclared service | ≥ 5 sources to one undeclared open port | high |
| SYN flood | SYN rate on a port ≥ 10× its 24 h median and ≥ 500/min | high |
| ICMP sweep / flood | echo requests ≥ 200/min from one source | medium |
| UDP probing | ≥ 20 closed UDP ports from one source | medium |
| DNS tunnelling features | queries with long, high-entropy first labels at a sustained rate | medium |
| sensor gap / drops | missing sequence numbers, stale windows, kernel drops > 1 % | medium (visibility) |

Internet background scanning is constant on a public server; scan findings aggregate per source
network and per window, decay, and page only when they change state (I3). Findings never block
traffic: Argus reports; response actions stay explicit owner commands.

### W6. Packaging (staged patch for `~/archymedes-site/scripts/argus/server`)

install.sh: `--net-sensor` opt-in (creates `argus-net`, installs and enables the two units),
writes `/etc/argus/services.conf` from current public listeners, adds `rpm` handling to
README. Uninstall removes both units and the account.

### W7. Prometheus metrics (2026-10-25)

Owner request 2026-10-25: release the server edition with the desktop app, prioritised by
what DevOps operators ask for. Research (Grafana Labs observability surveys 2025/2026,
practitioner comparisons): complexity and alert noise are the top complaints; about three
quarters of teams invest in Prometheus; an apt-installable package and a small footprint are
expected. Webhook/ntfy/syslog (W4) already covered the alerting ask.

`GET /metrics` (`jarvis/web/metrics.py`) on the existing loopback listener, Host-checked like
every route. Invariants: labels only from fixed sets (severity, scheduled job name), so no
evidence leaves through a scrape and cardinality is bounded by JOBS (I5, I6); a collector that
never reported has `observed 0` and no age or failing sample (I1); an unreadable store is a
503, never zeros (I1); one rendering shared for 15 s, measured 14 ms on an empty store.
Superseded 2026-10-30 (ARGUS-2026-001): every data route, `/metrics` included, now needs a
credential; only `/api/health` and `/api/live` stay open, and anonymously they return
liveness fields only. Prometheus uses a paired client token, which does not rotate on
restart: pair it once (`sudo -u argus -H argus desktop pair --name prometheus --out
/etc/prometheus/argus.token`, then make the file readable by the prometheus user only) and
scrape with

```yaml
scrape_configs:
  - job_name: argus
    static_configs: [{targets: ["127.0.0.1:8787"]}]
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/argus.token
```

The daemon accepts `Authorization: Bearer <token>` as well as `X-JARVIS-Token`. Revoke with
`desktop revoke ID`. The original reasoning for no token (the per-start file rotates) no
longer applies, since client tokens are stable until revoked.

### W8. Packages and the desktop client (2026-10-25)

- `argus-server_<v>_all.deb` (build.py `build_deb`): thin package, dpkg owns
  `/usr/share/argus-server`; postinst runs the verifying installer, so a failing copy keeps the
  previous install. Depends on python3 >= 3.12; older systems use the tarball. One file list
  feeds the tarball and the .deb. Installer re-runs now keep the configured port and an
  enabled network sensor (they used to reset the port to 8787).
- Desktop: `scripts/argus/desktop.py` renames `desktop/` with the same rules as the daemon (so
  token cookie and header match), builds the interface once, builds Linux with cargo (no Tauri
  CLI on the build host) into `argus-desktop_<v>_amd64.deb`, and cross-builds Windows with the
  renamed `build-windows.sh`. The client stays loopback-only; servers are reached through
  `ssh -N -L 8787:127.0.0.1:8787` (Jev 2026-10-25: tunnel 0.99 over a network client).

### W9. Decompression bombs (2026-10-25)

Owner request: protect against zip bombs. Every decompression of data the daemon did not just
write itself now goes through `jarvis/core/inflate.py`, which counts bytes actually produced
(never a size an archive declares) and raises `InflateLimit` (a ValueError, so existing
"unreadable, not observed" handling applies):

| input | before | bound |
| --- | --- | --- |
| threat feeds (`intel/feeds.py`), gzip | `gzip.decompress` unbounded (64 MB download -> tens of GB) | 160 MB inflated (largest measured feed 76 MB) |
| threat feeds, zip | trusted the declared size, read up to 512 MB | first member counted to 160 MB, at most 64 entries |
| event-log segments (`core/eventlog.py`) | `readline()` / `for line in fh` unbounded | header 256 KB, line 1 MB (measured 3 KB, 78 KB) |
| segment verification, evidence vault | `fh.read()` of the whole payload | streamed, 1 GiB plain per segment (measured 324 MB) |

historybook and peerledger were already bounded. A planted segment is reported as unreadable by
`verify`, never silently skipped. Tests: `tests/test_inflate.py` (real bombs, a zip header that
understates its size, peak memory under 8 MB while refusing a 64 MB bomb).

### W10. Off-box heartbeat (2026-10-25)

Research and ORION (2026-10-25, Kendall W 0.81) ranked "alert when the server or Argus goes silent"
first: every channel Argus has runs on the server, so a dead host or daemon pages no one.

`heartbeat` job (fast lane, 60 s): when `heartbeat_url` (https only) is set in the alert config,
one bounded GET per run to a dead-man service the owner chooses (healthchecks.io, Uptime Kuma
push monitor, Better Stack heartbeat, a self-hosted equivalent). Silence there is the alarm.

Invariants: the URL is a secret (tokens live in it): never logged, never in a finding, never on
a command line; one request per run, 10 s timeout, no retries (the next run is the retry); the
ping proves the scheduler's fast lane ran, nothing more; no URL configured is a visible low
finding ("nothing outside this machine notices if it goes silent"), never silence; 5+
consecutive failures is a medium finding (the off-box monitor will alert too); nothing about
the machine is sent (no body, no query parameters added).

Alternatives: the on-box selfcheck timer (restarts the daemon, dies with the host: complement,
not replacement); a mesh of Argus peers watching each other (needs the fleet view, ranked 7th);
email "still alive" digests (no one notices a missing email).

### W11. Patches, reboots and fixable CVEs (2026-10-25)

`patches` job (linux, hourly, local only): pending updates and which are security updates
(`apt-get -s dist-upgrade`, `dnf --cacheonly updateinfo`), age of the package lists, reboot
required (`/run/reboot-required`, running kernel older than the newest installed one). Fixable
CVEs: installed packages compared with the distribution's own security data, downloaded by the
daily `distrovuln` job (bulk lane): Canonical USN OVAL per release (1.3 MB compressed) and
Debian OVAL per release (9.7 MB); parsed as a stream under byte caps, reduced to a compact
index on disk. Owner decision 2026-10-25: local data only, nothing about the server leaves it.
CISA KEV (already a feed) ranks them.

| finding | severity |
| --- | --- |
| a KEV-listed CVE has a fix not installed (per package) | high |
| other fixable CVEs (one aggregate) | medium |
| reboot required for more than a day / running kernel older than installed | medium |
| package lists older than 7 days (updates unknown, not clean) | medium |
| security data or package database unreadable | low, reported as not observed |

Invariants: only "fix exists and is not installed" counts (actionable); unfixed CVEs are not
reported; unknown distro or stale data is stated, never a clean result; Debian matches source
packages and source versions, Ubuntu binary packages, with Debian version ordering; downloads go
through core/inflate.py bounds; nothing is installed or upgraded by Argus. RPM systems get
pending security advisories and needs-restarting only (source-tested, no RHEL/Rocky host here).

### W12. First clean-server install, and the noise it showed (2026-10-25)

Measured: `argus-server_2026.10.25_all.deb` in a disposable Ubuntu 24.04.5 guest (1 vCPU, 1.5 GB,
no network; QEMU/KVM in the unprivileged JARVIS lab container, base image verified unchanged):
`dpkg -i` 17 s, self-verification 11/11 properties, health 200 at 17 s, no tracebacks or journal
errors; daemon RSS 57 MB, service cgroup 160 MB (page cache included); 111 CPU-seconds in 10 min
(first runs of every collector; steady state still to measure); `dpkg -r` clean, history kept.

It also produced 140 findings on a stock server (1 critical, 9 high, 28 medium, 102 low). Real:
22 packages with fixes not installed (openssh, curl, bind9), lists 29 days old, no alert
channel, undeclared ssh, the cloud image's passwordless sudo. Noise, fixed at the source:

| noise | cause | fix |
| --- | --- | --- |
| "kernel functions are hooked via ftrace" high | continuation lines parsed as functions; the kernel's own HID-BPF dispatcher counted as a rootkit hook | parse records; kernel HID-BPF low, other BPF trampolines medium, ftrace callbacks stay high |
| `kworker/...` NEW high | kernel threads scored as new root binaries | kernel threads (no exe, parent kthreadd, [bracketed]) score on traits only |
| 3 collectors "failing" high | absent opt-in sensor counted as a blind spot, then as a failing collector | opt-in not taken is `configuration`; installed-but-stale stays `visibility` |
| out-of-daemon watchdog missing high | the server unit's own WatchdogSec + Restart=always not recognised | systemd supervision is an ok finding |
| 17 "feed failed" mediums | one finding per feed | one finding per cause, naming the feeds (also on the workstation) |
| ~90 unit/cron/alias lows | inventory of package-owned files | units owned by a package or snapd and byte-identical stock cron files are one ok summary; anything else per entry |
| argus.service "custom" medium | the self proof knew only the workstation layout | content proof of the sealed server launcher, account and root-only interpreter |
| world, model | workstation features | `servers=False`: not applicable on a plain Linux server |
| purge left the account | userdel stderr discarded | postrm reports the reason and retries after the service's leftovers |

Workstation identity changes (I9 exceptions): feed failures and enabled-unit inventory now
aggregate, so those finding identities change once.

## Validation

- Unit and property tests for each detection, the BPF program (assembled and run against
  crafted frames through a userspace interpreter of the same instructions), window sequencing,
  gaps, drops, retention, and every channel's failure path (timeouts, 4xx, 5xx, one channel
  down while another delivers).
- End to end in a local **non-privileged** Docker container running systemd (Ubuntu 24.04 and
  Rocky 9): install, verify, baseline, scan from a second container (nmap-style SYN sweep),
  brute force then a successful login, a new key, a disk filling. `systemd-binfmt` and the
  binfmt automount are masked in the image and `/proc/sys/fs/binfmt_misc/WSLInterop` is checked
  before and after every run: privileged systemd containers flushed it on 2026-10-22 and blinded
  every JARVIS PowerShell collector.

Reconsider the sampler for eBPF if measured kernel drops exceed 1 % at the target packet rate;
reconsider adding Suricata ingest when signature-level detection is wanted.
