Argus server edition
====================

Argus watches a Linux server for the ways something could take or keep control
of it: SSH keys and logins, sudo, accounts, systemd and cron persistence,
hidden processes, web shells, exposure and package integrity. It is one native
program (bin/argus-server) and needs no Python or other runtime.

Licence: project-owned code in this distribution uses
PolyForm-Noncommercial-1.0.0; see LICENSE.txt. It is source-available, not open
source. Commercial uses outside the license's permitted purposes need separate
permission. The standard license permits government and listed nonprofit uses.
Earlier AGPL grants remain valid. Third-party components retain their own terms
in THIRD-PARTY-NOTICES.txt. Check the exact release's terms and source identity.

Before installing, check the download (see the documentation for the commands):
SHA256SUMS lists every file's SHA-256, and SHA256SUMS.sig is the release
signature, made with a release key whose fingerprint is published on the site.

Install, upgrade:   sudo ./install.sh [--port 8790] [--net-sensor] [--no-start]
Uninstall:          sudo /opt/argus/uninstall.sh [--purge]
Status and logs:    systemctl status argus ; journalctl -u argus -f
First run:          argus welcome server   (what it looks at, and its limits)
First report:       argus investigate
Weekly review:      sudo -u argus -H argus review --days 7   (read-only; states blind spots)
Dashboard:          loopback only; ssh -L 8787:127.0.0.1:8787 your-server

Documentation: https://www.archymedes.xyz/en/docs/argus/
