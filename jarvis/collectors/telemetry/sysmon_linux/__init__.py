"""Sysmon for Linux — the eBPF syscall interception WSL2 forces us to.

auditd cannot run on the WSL2 kernel: it rejects the audit daemon over the
netlink socket regardless of privilege. Microsoft's Sysmon for Linux does the
same job through eBPF instead — it hooks execve, connect, ptrace, raw disk
reads and file create/delete, and writes Windows-Sysmon-schema events to the
journal. This reads them incrementally and applies rules adapted to Linux
paths and shapes, the same way `sysmon.py` does for the Windows side.

Install (Ubuntu):

    curl -sSL https://packages.microsoft.com/keys/microsoft.asc \\
      | sudo tee /etc/apt/trusted.gpg.d/microsoft.asc >/dev/null
    echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/$(lsb_release -rs)/prod \\
      $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/microsoft-prod.list
    sudo apt update && sudo apt install -y sysmonforlinux
    sudo sysmon -accepteula -i        # default config; pass a file to tighten

The default config records process events only. A tightened policy that also
captures the NetworkConnect, ProcessAccess and persistence-path FileCreate /
FileDelete events the rules below need — without the volume an unfiltered
FileCreate would add — ships in this repo at `sysmon/config.xml`:

    sudo sysmon -accepteula -i <repo>/sysmon/config.xml   # first install
    sudo sysmon -c          <repo>/sysmon/config.xml       # update in place

`audit()` reports it as a finding if those event types never show up.

Events land in the journal under the `sysmon` identifier. The daemon reads them
as `chris`, so `chris` must be in the `systemd-journal` or `adm` group (usually
already true on Ubuntu); the module falls back to /var/log/syslog otherwise.
"""

from .harness import _SQ_ESCAPE, _payload
from .journal import CHANNEL, _event_utc, _parse, _run, active, state
from .rules import (
    DOWNLOAD_RUN,
    LOG_DELETE_TITLE,
    PERSIST_WRITE_TITLE,
    RAW_ACCESS_TITLE,
    RAW_LEGACY_SUFFIX,
    RAW_UNRESOLVED_TITLE,
    _rules,
)
from .run import SEV_ORDER, _health, _remember, audit, sort_findings
