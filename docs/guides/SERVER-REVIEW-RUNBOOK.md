# Runbook: observed server review

For the founder delivering a review (docs/commercial/SERVER-REVIEW.md). Every step is run by
the client on their own server; the founder never needs the client's credentials.

## Install failed

| Symptom | Check | Next step |
|---|---|---|
| `install.sh` refuses: not root | `id -u` | `sudo ./install.sh` |
| Signature does not verify | `ssh-keygen -Y verify` output | Stop. Do not install. Download again from the site and compare with the published key fingerprint; report to the owner |
| Unit does not start | `systemctl status argus`, `journalctl -u argus -n 100` | Note the error class; remove with `sudo /opt/argus/uninstall.sh`; record the distro and version for the clean-VM matrix |
| glibc or systemd too old | the error names the version | Unsupported host: say so, remove, no charge |
| Port already in use | `ss -ltnp \| grep 8787` | `sudo ./install.sh --port 8790` |

## The report says "not observed" for an area

That area produced no run receipt in the window. Do not fill it in by hand. Common causes:
the daemon was stopped (`systemctl status argus`), the job needs the optional network sensor
(`--net-sensor`), or the server slept or rebooted. Say so in the walkthrough; offer to extend
the window (`argus review --days 14`).

## `argus review` refuses

| Message | Meaning |
|---|---|
| `no ARGUS-1 store at …` | Wrong account or the daemon never ran. Run as the daemon's account: `sudo -u argus -H argus review` |
| `ARGUS-1 runs as its own account …` | Same: the command printed the right invocation |
| `not written: … already exists` | Choose a new file name; the tool never overwrites |

## Remove ARGUS-1

- `.deb`: `sudo apt remove argus-server` (add `--purge` to remove its data).
- Tarball: `sudo /opt/argus/uninstall.sh` (keeps history) or `--purge` (deletes `/var/lib/argus`
  and the accounts). Check afterwards: `systemctl status argus` reports the unit not found,
  `id argus` fails after `--purge`.
- Removal on a clean machine has not been validated yet; record what you observe.

## After every review (evidence)

Record, without client data: distro and version, install method, time from download to first
finding (devex TTHW), idle CPU and memory after an hour, areas not observed and why, and the
client's own words about the report. These feed the clean-machine evidence the register needs;
nothing is promoted in `assurance.py` without a measured result.
