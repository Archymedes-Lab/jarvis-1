"""Can mode bits prove a file is private to the current user?

POSIX answers with the owner and the group/other bits. Windows does not: its
mode bits are synthesized (every file reads as 0o666 or 0o444) and privacy is
decided by an ACL that is not inspected here. So on Windows the answer is
always "not proven" - a secret is never treated as protected, and a key file is
never trusted, on the strength of bits that enforce nothing.
"""

import os


def owner_only(st):
    """True when `st` (an os.stat result) is owned by this user and closed to
    group and others. Never true where mode bits do not enforce access."""
    getuid = getattr(os, "getuid", None)
    if getuid is None:
        return False
    return st.st_uid == getuid() and not st.st_mode & 0o077
