"""Credentials sitting in plaintext on this disk.

This checks local storage relevant to `T1552` (unsecured credentials).
Pattern matches do not establish validity or external exposure. Volume
encryption is not inferred from another drive's posture or a historical scan.

The rule that shapes everything below: **a scanner that finds secrets must not
become a place where secrets are kept.** Nothing here stores, logs or prints a
credential. A finding carries the file, the line, what kind of credential it
looks like, and a truncated SHA-256 fingerprint — enough to identify the same
secret across two files or confirm you rotated it, useless to anyone who reads
the report. That is the same reasoning that keeps key values out of
`inputwatch`, and it is the reason no `--show` flag exists.

Three kinds of finding, in descending order of how much they should worry you:

  reachable   a credential in a file other users or the world can read
  tracked     a credential in a file git is tracking, or in a repo with a
              remote — the disk is one thing, a push is another
  present     a credential in plaintext, correctly permissioned

High-entropy strings are checked for entropy rather than pattern alone, because
a config key called `api_key = "changeme"` is not a leak and `AKIA...` is.
"""

from .patterns import _private_blocks, fingerprint, scan_file
from .run import SEV_ORDER, audit, sort_findings, walk
