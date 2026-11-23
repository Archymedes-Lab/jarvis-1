"""Unwrapping agent-harness shell wrappers so rules judge the command actually run."""

import re

# Claude Code and similar agent harnesses run every command through a fixed
# wrapper: `bash -c 'source <shell-snapshot.sh> ... && eval '<the real
# command>' < /dev/null && pwd -P >| /tmp/claude-<id>-cwd'`. The scaffolding —
# sourcing the snapshot, a builtin-unalias block, the cwd write — is not what
# ran, and matching the content rules against it produced a download-and-run
# false positive whenever the real command was ordinary. Pull the real command
# back out before those rules look at it.
# The wrapper is not one fixed shape. A single-line command ends
# `' < /dev/null && pwd -P >| /tmp/claude-<id>-cwd`; a multi-line one (a
# heredoc, say) has no `< /dev/null` at all and ends at `' && pwd -P >|`.
# Matching only the first shape left roughly a third of harness events falling
# through to raw content matching — measured at 9 of 26 on this machine — and a
# rule that then reads the scaffolding is a rule that reports the scaffolding.
# So accept either terminator, and take the last one on the line rather than
# the first, because the real command may legitimately contain either string.
_HARNESS_MARK = "shell-snapshots/"


_HARNESS_WRAP = re.compile(
    r"shell-snapshots/\S+\.sh\b.*?&&\s*eval\s+'(?P<real>.*)'"
    r"(?:\s*<\s*/dev/null|\s*&&\s*pwd\s+-P\s*>\|)",
    re.S)


# The pieces of scaffolding themselves, for the case where the payload cannot be
# isolated — a truncated journal line, or a wrapper revision not seen yet.
# Stripping them is strictly better than giving up in either direction: the real
# command is still content-matched, and the scaffolding cannot be reported as if
# it were the command.
_HARNESS_PARTS = (
    re.compile(r"^/bin/bash\s+-c\s+", re.S),
    re.compile(r"source\s+\S*shell-snapshots/\S+\.sh\s*2>/dev/null\s*\|\|\s*true"),
    re.compile(r"shopt\s+-u\s+extglob\s*2>/dev/null\s*\|\|\s*true"),
    re.compile(r"\{[^{}]*\\builtin\s+un(alias|set)[^{}]*\}\s*>/dev/null\s*2>&1"
               r"\s*\|\|\s*true", re.S),
    re.compile(r"&&\s*pwd\s+-P\s*>\|\s*/tmp/claude-\S+-cwd\s*$"),
    re.compile(r"<\s*/dev/null\s*$"),
    re.compile(r"^\s*(&&\s*)+"),
)


# The bash escape for an apostrophe inside a single-quoted string.
_SQ_ESCAPE = chr(39) + chr(34) + chr(39) + chr(34) + chr(39)


def _payload(cmd):
    """The command the harness was asked to run, without the harness's own noise.

    Returns the original string unchanged for anything that is not a harness
    invocation, so non-agent command lines are unaffected.
    """
    cmd = cmd or ""
    if _HARNESS_MARK not in cmd:
        return cmd
    m = _HARNESS_WRAP.search(cmd)
    if m:
        real = m.group("real")
    else:
        real = cmd
        for part in _HARNESS_PARTS:
            real = part.sub("", real).strip()
        real = re.sub(r"^eval\s+'", "", real).strip()
    # bash single-quote escaping: an apostrophe inside a '…' string is written
    # as '"'"'. Left in place it splits words and hides what actually ran.
    return real.replace(_SQ_ESCAPE, chr(39)).strip()
