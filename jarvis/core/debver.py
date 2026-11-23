"""Debian package version ordering (deb-version(7)), as dpkg --compare-versions does it.

A version is [epoch:]upstream[-revision]. Each part compares by alternating
runs: non-digits compare character by character where letters sort before
non-letters and `~` sorts before everything, even the end of the string; digit
runs compare numerically. Used to decide whether an installed package is older
than the version a security advisory fixed, so it must agree with dpkg exactly:
tests/test_debver.py checks it against dpkg's own documented cases.
"""


def _order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if not c:
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _compare_part(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def parse(version):
    """(epoch, upstream, revision) of a Debian version string."""
    v = (version or "").strip()
    epoch = 0
    if ":" in v:
        head, v = v.split(":", 1)
        epoch = int(head) if head.isdigit() else 0
    if "-" in v:
        upstream, revision = v.rsplit("-", 1)
    else:
        upstream, revision = v, ""
    return epoch, upstream, revision


def compare(a, b):
    """Negative, zero or positive as version a sorts before, equal to or after b."""
    ea, ua, ra = parse(a)
    eb, ub, rb = parse(b)
    if ea != eb:
        return ea - eb
    return _compare_part(ua, ub) or _compare_part(ra, rb)


def older(installed, fixed):
    return compare(installed, fixed) < 0
