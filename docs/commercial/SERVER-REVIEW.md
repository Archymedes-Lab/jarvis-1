# ARGUS-1 observed server review: offer sheet (draft for the owner)

Status: **draft**. Price, legal entity, engagement terms and every outreach message are the
owner's decisions (PMF-2026-11.md, "Owner decisions"). Nothing here has been sent to anyone.
Chosen by CDM over Jev on 2026-11-02 as the explore candidate (`observed_audit`); see
`PMF-2026-11.md` Phase 2.

## What it is, in one sentence

For one week, ARGUS-1 runs on one of your Linux servers, installed together with you, and at
the end you get a report of what it observed and, just as plainly, what it could not see.

## What it is not

- **Not a security audit, penetration test or certification.** It does not say your server is
  or is not compromised. An absence of findings is not proof of safety.
- Not a guarantee of anything: none of ARGUS-1's capabilities has been live-tested yet
  (`jarvis/core/assurance.py`); the report prints each capability's status from that register.
- Not remote access for us. ARGUS-1 sends nothing off the server unless you configure an alert
  channel or heartbeat.

## Who it is for

Small software agencies and dev teams (about 2–30 people) that run Linux servers for themselves
or their clients, often with AI coding agents and CI running code under the team's credentials.
Evidence: Scout (2026-10-29) judged 20 prospect and 10 agency results `paying` tier, and 0 of 9
self-hoster results (`~/sales/data/scout.db`, read-only).

## What happens

| Day | Step | Who |
|---|---|---|
| 0 | 30-minute call: which server, what runs on it, who owns it; you confirm you are allowed to install software on it | you + founder |
| 0 | Install together from the signed release (`.deb` or tarball, signatures checked); `argus welcome server` read aloud | you run the commands; founder watches |
| 1–6 | ARGUS-1 observes. You may look at any time: `argus status`, the dashboard through an SSH tunnel | nobody needs to do anything |
| 7 | `sudo -u argus -H argus review --days 7 --out review.txt` on the server; the file is created readable by the `argus` account only | you |
| 7 | 45-minute walkthrough of the report: each finding, each blind spot, what to do next | you + founder |
| 7+ | Keep it (free server edition) or remove it: `sudo apt remove argus-server` or `sudo /opt/argus/uninstall.sh --purge` | you |

## What the report contains (`argus review`, read-only)

- The window, the host name and a fixed line saying it is not an audit or certification.
- For every area the server edition looks at (SSH policy and keys, logins, exposure, packet
  headers, failed services and certificates, boot chain, keyboard readers, package integrity,
  pending security updates, code dependencies, containers, self-tamper evidence): whether it
  was observed in the window, partly observed, stale or **not observed**, with run counts, the
  last error and the findings (at most 40 per area, secrets redacted, findings about secrets
  shown by title only).
- What it could not see: each capability's register status and the first clause of its limit.
- That scores are not verdicts, and how to remove ARGUS-1.

**Sample to show a prospect:** `docs/commercial/SAMPLE-SERVER-REVIEW.txt`. It is produced by the
real renderer over a fictional server's week (`scripts/reviews/sample_review.py`, deterministic)
and opens with a line saying nothing in it was observed. It shows the honest states a real week
usually has: one area not observed (packet sensor off), one stale (boot chain), one partial
(heartbeat with no URL). Regenerate it whenever the renderer or the register changes.

Jev on the sample (jev-1.14.0, advisory, metadata only; `scripts/reviews/pmf_advisory.py sample`):
helps a lead without misleading 0.43 (uncertain); most off-putting property: the not-verified
status repeated on every area (0.67), then invented findings read as real (0.21), configuration
details withheld as secrets (0.11). Two renderer issues the sample exposed, **not changed** (they
touch the claim and privacy rules and need the owner's call plus tests): the status line repeats
per area and again in the blind-spots list; details of `PasswordAuthentication`/`PermitRootLogin`
findings are withheld because the title contains "password". Also, a stale area prints
"Last run: never" although it has an older stored result. Test the sample on a real lead before
relying on it (PMF Phase 5).

## Where your data stays

On your server. The report is a local file. If you choose to share it with us for the
walkthrough, you decide what to share; we keep no copy after the engagement unless you ask
(**owner to confirm in the engagement terms**).

## Price (owner decision)

Jev suggested 200–500 USD per server for the first three reviews (0.58; advisory only).
Freelance one-server audits start near 199 USD (contra.com listing, 2026-11-02). A deposit
before install tests willingness to pay, which Jev rated the riskiest assumption (0.51).

## Before the first paid review (gates)

1. Clean install, upgrade and removal of the native build measured on fresh Ubuntu 24.04 and
   Debian 12 VMs, with idle CPU and memory (Jev: installing on a customer server first, 0.20).
   Plan: `docs/commercial/VM-INSTALL-MATRIX.md`.
2. A signed release that contains `argus review` (needs GitHub Actions billing fixed).
3. Engagement terms and an invoicing entity (the EULA draft names "Archymedes, Inc.").
4. `security.txt` and a contact address on the site.
