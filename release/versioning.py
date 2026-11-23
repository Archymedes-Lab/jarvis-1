"""Release version order, by the project's own rule rather than by string.

A release is tagged vYYYY.MM.DD, or vYYYY.MM.DD-N for the Nth one that day (a
tag without a suffix is the first). A dry run published straight to the site
(owner decision 2026-11-03) carries -0 (the 2026-11-03 builds) or -<run number>. So 2026.10.31 < 2026.10.31-2 < 2026.11.01,
and 2026.10.31-10 > 2026.10.31-9, which a string compare gets wrong.

Releases published before tagging existed carry dotted versions such as
2026.10.30 or 2026.10.29.1. Those can be the *live* side of a comparison, so a
candidate is checked against them, but a candidate itself must be a tag version.
"""

import datetime
import re

# ASCII digits only and \Z, not $: "$" also matches before a trailing newline and
# \d matches every Unicode digit, so "v2026.11.04\n" and "v2026.11.0\u0664" were
# accepted as tags (FZ-05). A tag becomes a git ref, a file name and a URL path.
TAG = re.compile(r"^v?(20\d{2})\.(\d{2})\.(\d{2})(?:-(0|[1-9]\d*))?\Z", re.ASCII)
LEGACY = re.compile(r"^(20\d{2})\.(\d{1,2})\.(\d{1,2})(?:\.(\d+))?\Z", re.ASCII)


class VersionError(Exception):
    pass


def _key(m, what, version):
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    try:
        datetime.date(y, mo, d)
    except ValueError:
        raise VersionError(f"{what} {version!r} is not a real date") from None
    n = int(m.group(4)) if m.group(4) else 1
    return (y, mo, d, n)


def candidate_key(version):
    m = TAG.match(version or "")
    if not m:
        raise VersionError(f"candidate {version!r} is not vYYYY.MM.DD or vYYYY.MM.DD-N")
    return _key(m, "candidate", version)


def live_key(version):
    """None when nothing is published; otherwise the ordering key of what is live."""
    if not version:
        return None
    m = TAG.match(version) or LEGACY.match(version)
    if not m:
        raise VersionError(f"the live version {version!r} is not one this tool can order: refusing to guess")
    return _key(m, "live version", version)


def check_ordering(candidate, live, rollback=False):
    """Raise VersionError unless `candidate` may replace `live`.

    A rollback (an explicit, deliberate re-publication of an earlier signed
    release) may be older or equal; it must still be a valid tag version."""
    c = candidate_key(candidate)
    current = live_key(live)
    if current is None or rollback:
        return
    if c <= current:
        raise VersionError(f"candidate {candidate} is not newer than the live release {live}: "
                           "publish a newer version, or pass --rollback to re-publish an earlier signed release")
