"""Stage a Windows ARGUS edition from this source tree, next to an installed one.

The installed edition is this source with the package renamed (jarvis -> argus,
JARVIS -> ARGUS, Jarvis -> Argus) and its Linux-only parts trimmed. This script
reproduces the rename so the current source can be tried, and switched in,
without a packaged installer:

    python scripts/stage_argus_edition.py --installed "%LOCALAPPDATA%\\Programs\\Argus\\app" --out "%LOCALAPPDATA%\\Programs\\Argus\\app-new"

It copies the installed app folder (scripts, sensors, prompts) and replaces its
`argus` package with the renamed source. Nothing is switched: the output is a
separate folder, and the installed one is not touched. Rolling a switch back is
renaming the folders back. Data stays in the same place (~/.argus).
"""

import argparse
import os
import shutil
import sys

TEXT = (".py", ".html", ".js", ".css", ".json", ".md", ".txt", ".toml", ".cfg", ".ps1", ".svg")
SKIP_DIRS = {"__pycache__"}
# Copied byte for byte: the built interface and the hash-pinned vendor files.
VERBATIM = (("web", "ui"), ("web", "static", "vendor"))


def rename(text):
    return text.replace("jarvis", "argus").replace("JARVIS", "ARGUS").replace("Jarvis", "Argus")


def copy_package(src, dst):
    count = 0
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        rel = os.path.relpath(root, src)
        out_dir = os.path.join(dst, rel) if rel != "." else dst
        os.makedirs(out_dir, exist_ok=True)
        for name in files:
            if name.endswith((".pyc", ".pyo")):
                continue
            s, d = os.path.join(root, name), os.path.join(out_dir, name)
            parts = tuple(os.path.normpath(rel).split(os.sep))
            verbatim = any(parts[: len(v)] == v for v in VERBATIM)
            if name.lower().endswith(TEXT) and not verbatim:
                with open(s, encoding="utf-8", newline="") as fh:
                    body = fh.read()
                with open(d, "w", encoding="utf-8", newline="") as fh:
                    fh.write(rename(body))
            else:
                shutil.copy2(s, d)
            count += 1
    return count


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--installed", required=True, help="the installed app folder (contains argus/)")
    ap.add_argument("--out", required=True, help="new folder to create (must not exist)")
    ap.add_argument("--source", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "jarvis"))
    args = ap.parse_args(argv)
    installed, out, source = (os.path.abspath(p) for p in (args.installed, args.out, args.source))
    if not os.path.isdir(os.path.join(installed, "argus")):
        sys.exit(f"{installed} does not look like an installed ARGUS app folder")
    if os.path.exists(out):
        sys.exit(f"{out} already exists; refusing to overwrite")
    if not os.path.isfile(os.path.join(source, "__init__.py")):
        sys.exit(f"{source} is not the jarvis package")
    shutil.copytree(installed, out, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.rmtree(os.path.join(out, "argus"))
    n = copy_package(source, os.path.join(out, "argus"))
    print(f"staged {n} files into {out}")


if __name__ == "__main__":
    main()
