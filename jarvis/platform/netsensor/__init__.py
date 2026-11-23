"""Network sensors for Linux servers (docs/architecture/ARGUS-SERVER.md W5).

Each runs in its own minimal systemd unit, never inside the daemon:

  netstate  oneshot, CAP_NET_ADMIN only: reads the firewall (fixed commands)
  capture   long-running, CAP_NET_RAW only: header-only inbound packet windows

Both write JSON into the spool directory (spool.py) that the daemon's
collectors read; nothing they read can instruct them.
"""
