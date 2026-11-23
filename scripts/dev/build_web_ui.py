"""Build the desktop interface and copy it where the daemon serves it from.

    python scripts/dev/build_web_ui.py

The same interface runs in the desktop app (bundled by Tauri) and in a browser
at http://127.0.0.1:PORT/ (served from jarvis/web/ui by web/server.py). This
runs the production build in desktop/ui and replaces jarvis/web/ui with it.
Needs bun. The copied files are committed, so a source checkout serves the new
interface without a build step.
"""

import os
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
UI = os.path.join(ROOT, "desktop", "ui")
DIST = os.path.join(UI, "dist")
OUT = os.path.join(ROOT, "jarvis", "web", "ui")


def main():
    bun = shutil.which("bun")
    if not bun:
        sys.exit("bun is required to build the interface (https://bun.sh)")
    subprocess.run([bun, "install", "--frozen-lockfile"], cwd=UI, check=True)
    subprocess.run([bun, "run", "build"], cwd=UI, check=True)
    index = os.path.join(DIST, "index.html")
    if not os.path.isfile(index):
        sys.exit("the build produced no index.html")
    with open(index, encoding="utf-8") as fh:
        html = fh.read()
    if 'src="/' in html or 'href="/' in html:
        sys.exit("index.html uses absolute asset paths; vite base must be './'")
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    shutil.copytree(DIST, OUT)
    count = sum(len(files) for _, _, files in os.walk(OUT))
    print(f"copied {count} files to {os.path.relpath(OUT, ROOT)}")


if __name__ == "__main__":
    main()
