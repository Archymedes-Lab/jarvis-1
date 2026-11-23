"""Handing work to one UAC-elevated PowerShell (V14).

The files an elevated shell needs are first staged where the unprivileged user
can write (their TEMP), because the elevated session may not see the \\\\wsl
share. Nothing staged there runs as is. The elevated shell is started on
inline code (`launcher`, -EncodedCommand) that copies each file into a fresh
administrator-only folder under Program Files, matches it against a SHA-256
fixed before the prompt, and only then runs the entry from that folder
(`inline_command`). A file swapped in between fails the match and nothing
runs; the folder is removed afterwards.

The hashes are taken by the same unprivileged user, so this closes the window
between staging and elevation; it is not an anchor against a modified checkout
(a signed release would be).
"""

import base64
import re

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")
SWITCH = re.compile(r"^-[A-Za-z][A-Za-z0-9]*$")


def _literal(text):
    """A PowerShell single-quoted literal: only ' is special, and it doubles."""
    return "'" + str(text).replace("'", "''") + "'"


def _argument(arg):
    if SWITCH.match(arg):
        return arg                                   # a parameter name, never data
    if arg == "{trusted}":
        return "$t"
    if arg.startswith("{trusted}\\"):
        rest = arg[len("{trusted}\\"):]
        if not all(NAME.match(part) for part in rest.split("\\")):
            raise ValueError(f"unsafe path below the trusted folder: {rest!r}")
        return f"(Join-Path $t {_literal(rest)})"
    return _literal(arg)


def inline_command(stage, files, entry, args):
    """PowerShell for the elevated shell: copy `files` ({name: sha256}) from the
    Windows folder `stage` into a fresh folder under Program Files, refuse on
    any mismatch, run `entry` from there with `args`, then remove the folder.

    `args` are fixed tokens: "-Name" switches pass as parameter names, anything
    else as a literal value; "{trusted}" and "{trusted}\\name" name the checked
    folder and a file in it."""
    for name, digest in files.items():
        if not NAME.match(name):
            raise ValueError(f"unsafe file name: {name!r}")
        if not SHA256.match(digest):
            raise ValueError(f"not a SHA-256 for {name}: {digest!r}")
    if entry not in files:
        raise ValueError(f"the entry {entry!r} must be one of the checked files")
    checks = "".join(
        f"Copy-Item -LiteralPath {_literal(stage + chr(92) + name)} -Destination (Join-Path $t {_literal(name)});"
        f"if((Get-FileHash -LiteralPath (Join-Path $t {_literal(name)}) -Algorithm SHA256).Hash -ne {_literal(digest)})"
        f"{{throw {_literal(f'staged {name} does not match the SHA-256 fixed before elevation; nothing was run')}}};"
        for name, digest in files.items())
    call = " ".join([f"& (Join-Path $t {_literal(entry)})"] + [_argument(a) for a in args])
    return ("$ErrorActionPreference='Stop';"
            "$base=Join-Path $env:ProgramFiles 'Jarvis\\Elevated';"
            "$t=Join-Path $base ([guid]::NewGuid().ToString());"
            "New-Item -ItemType Directory -Force -Path $t | Out-Null;"
            f"try{{{checks}{call} }}"
            "finally{Remove-Item -LiteralPath $t -Recurse -Force -ErrorAction SilentlyContinue;"
            "if(-not (Get-ChildItem -LiteralPath $base -Force -ErrorAction SilentlyContinue))"
            "{Remove-Item -LiteralPath $base -Force -ErrorAction SilentlyContinue}}")


def launcher(inner, hidden=False, after=""):
    """Unelevated PowerShell that starts one elevated shell on `inner` (inline
    code, -EncodedCommand), waits, runs `after` (unelevated), and exits with
    the elevated shell's exit code."""
    encoded = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
    return ("$p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru "
            + ("-WindowStyle Hidden " if hidden else "")
            + "-ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',"
            f"'-EncodedCommand','{encoded}'; {after}{' ' if after else ''}exit $p.ExitCode")


def literal(text):
    """Public form of the PowerShell literal quoting, for callers' own commands."""
    return _literal(text)
