# Who made that beep (2026-11-03)

## What was measured

The owner heard a soft tone, played twice, like a 1000 Hz, 80 ms test tone. The
sound listener (inputhook.ps1, live since 2026-10-23) had recorded every one of
them. Its four real double tones since 10-29 (10-29 18:34, 11-02 21:07,
11-02 21:56, 11-03 13:39) all have the pure-tone peak of exactly 0.5 that
Beep() tones have. Windows' .wav alert sounds peak at 0.28-0.35. Each tone
played in the shared system-sounds session, and none had a named caller
("none visible"). Each time Windows Terminal was in front and the owner was
typing (idle 0-2 s).

A test on the live listener reproduced the gap. Six tones of 30-80 ms were
recorded as 72-104 ms beeps, and none was named. An 800 Hz, 300 ms tone was
named. The listener's handle-table snapshot starts about 25-50 ms after onset
and takes about 35 ms, so a 50-100 ms Beep() has already closed its handle on
`\Device\Beep` by the time it looks. It also cannot look inside elevated
processes.

The likely source: Windows Terminal had one interactive Windows PowerShell tab
(pid 17760). Its PSReadLine is set to `BellStyle=Audible`, with a 1221 Hz, 50 ms
ding on any key that does nothing. This was not proven at the time; the
detectors below are what prove it.

## Invariants

* **B1 Attribution is evidence.** A caller is named only from direct evidence:
  the listener saw the process holding `\Device\Beep`, or the kernel trace
  recorded the process opening it. The foreground inference is stored in
  separate `likely_*` columns, worded "inferred, not traced", and never fills
  `caller`.
* **B2 Metadata only.** Process id, image path, start time, user and signer.
  Never command lines, window titles, key data or audio content.
* **B3 Bounded cost.**
  * The trace is filtered in the kernel to opens of `\Device\Beep`, its file is
    capped at 4 MB, at most 3 closed files wait, and the inventory holds 24 h
    and at most 500 rows.
  * The inference runs only for unattributed system-sounds tones, at most once
    a second, over at most 64 processes and 4 levels (22-98 ms measured,
    including first-call JIT).
* **B4 No silent blindness.** The trace reports when it is:
  * not installed;
  * failed or drifted;
  * refused, because the kernel did not apply the filter;
  * blind, because its silent canary went missing;
  * logging other files (breaches);
  * incomplete, because files were dropped, unreadable or capped.
* **B5 Least change to the system.** The job runs from the broker's
  admin-only folder. It writes only that folder, and only ever starts and stops
  its own ETW session. The canary opens the device the way Beep() does but sends
  no IOCTL, so nothing plays (checked unelevated: status 0, no sound event).
* **B6 Identity at the time.** A caller is the live process only if it started
  before the open. Otherwise it is Sysmon's creation record for that pid at or
  before the open, otherwise "unresolved". It is never a later process that
  reused the pid.
* **B7 Never deleted unparsed.** Closed trace files are removed only after the
  inventory holding their opens is written.

## Designs compared (kernel attribution)

| | A. Unfiltered create trace | **B. Kernel-filtered trace (chosen)** | C. Resident elevated real-time consumer | D. Poll handles every 40 ms |
|---|---|---|---|---|
| Short tones | Yes | Yes | Yes | Partly (30-50 ms tones still slip) |
| Elevated callers | Yes | Yes | Yes | No |
| Cost | Every file open written to disk | Only Beep-device opens; 4 MB cap; 2 s fail-fast | One always-on elevated process | About one CPU core |
| New elevated surface | Broker job | Broker job | A new resident admin process | None |

Jev was consulted with bounded, metadata-only questions. It is advisory only.
* It chose B with probability 0.98.
* It put the risk that the kernel ignores the payload filter at 0.41, which is
  uncertain. That is why B checks itself (fail-fast and canary) instead of
  trusting the filter.
* It rated the foreground inference useful at 0.70, provided it is always
  labelled as an inference.

## What is verified and what is not

* Verified unelevated on this Windows:
  * the helper compiles;
  * the manifest gives event 12's descriptors, and the payload filter
    (`FileName` IS `\Device\Beep`) builds;
  * the canary opens the device silently;
  * an unelevated start returns "could not start (5)" and does not throw.
* The inference was run on the live process tree. With Windows Terminal in
  front it listed its PowerShell processes. Console hosts, WSL launchers and the
  terminal itself are excluded. A child and grandchild (cmd running ping) are
  both candidates.
* **Not verified:** the elevated session itself, and whether the kernel applies
  the payload filter to this kernel-mode provider. The job proves both on its
  first run after `jarvis broker install`.

## Reconsider if

* The job reports **refused**. Use an event-id-only filter with a
  user-mode real-time consumer (design C), and measure its CPU first.
* The canary goes missing. The field name or operator does not match on this
  build; compare `op` and the manifest.
* Beep-device opens arrive faster than about 1 per second sustained. The
  500-row inventory would then cover less than 24 h; aggregate per process.

## Live acceptance (after the owner deploys and runs `jarvis broker install`)

1. Write a baseline first: `jarvis broker status`, the audio findings, and
   `sound_events` beeps of the last hour.
2. After one broker run, `beeptrace` reports `mode=filtered` with no breaches,
   and `etl_bytes` stays small.
3. After the second run, `canary_checked=true` and `canary_seen=true`.
4. Positive control, from an unelevated PowerShell:
   `[console]::Beep(1221,50); Start-Sleep -m 350; [console]::Beep(1221,50)`.
   After the next broker run, the audio finding names that PowerShell's pid as
   "(Beep() call, kernel trace)".
5. Repeat step 4 from an elevated PowerShell. The listener cannot see it, and
   the trace must name it.
6. Restart the input hook (`jarvis inputwatch --stop && jarvis inputwatch
   --start`). Repeat the double ding with Windows Terminal in front. The row's
   `likely_*` fields list the shell, and the finding reads "inferred, not
   traced".
