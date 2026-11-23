"""Export a JARVIS commit as Argus: every jarvis/JARVIS/Jarvis renamed.

Argus is the public name of JARVIS. The rename runs over file contents and
paths, keeping each spelling's case (JARVIS_PORT -> ARGUS_PORT, JarvisSensor
-> ArgusSensor); the upper-case name stays upper case because report headings
such as "JARVIS IS HANDLING" are parsed as all-caps. Only committed files are
exported (git archive), so a working tree's uncommitted edits never ship.
"""

import io
import os
import subprocess
import sys
import tarfile
from pathlib import Path


def rename_text(text):
    return text.replace("JARVIS", "ARGUS").replace("Jarvis", "Argus").replace("jarvis", "argus")


def rename_path(rel):
    return rel.replace("jarvis", "argus").replace("Jarvis", "Argus").replace("JARVIS", "ARGUS")


def is_text(data):
    if b"\0" in data[:8192]:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def export(repo, ref, dest, paths=()):
    """Export `ref` of the git checkout `repo` into dest, renamed. Returns the
    short commit id. Exits if any spelling of the old name is left."""
    repo, dest = Path(repo), Path(dest)
    archive = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", ref, *paths],
                             check=True, capture_output=True).stdout
    commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "--short=12", f"{ref}^{{commit}}"],
                            check=True, capture_output=True, text=True).stdout.strip()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            data = tar.extractfile(member).read()
            if is_text(data):
                data = rename_text(data.decode("utf-8")).encode("utf-8")
            out = dest / rename_path(member.name)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
            os.chmod(out, member.mode & 0o777)
    left = [str(f) for f in sorted(dest.rglob("*")) if f.is_file()
            and ("jarvis" in f.relative_to(dest).as_posix().lower()
                 or (is_text(data := f.read_bytes()) and b"jarvis" in data.lower()))]
    if left:
        sys.exit("rename incomplete:\n" + "\n".join(left[:50]))
    return commit
