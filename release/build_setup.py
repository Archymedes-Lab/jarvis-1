#!/usr/bin/env python3
"""Build ARGUS-INSTINCT-Setup-windows-x64.exe from the Windows engine and the desktop app.

    python3 release/build_setup.py --engine DIR --desktop DIR --version V --out DIR

DIR arguments are the release jobs' output folders: the engine's holds
argus-instinct-windows-x64.zip and windows-build.json (release/build_windows.py),
the desktop's argus-desktop-windows-x64.exe and its record. Both were checked
against their builds' digests by the workflow before this runs. The Setup
carries exactly the zip's files plus the desktop app, made with makensis
(release/windows/setup.nsi), then goes through the content gate like every
other download (7z opens it).
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_windows  # noqa: E402
import gate  # noqa: E402

SETUP_NAME = "ARGUS-INSTINCT-Setup-windows-x64.exe"
DESKTOP_EXE = "argus-desktop-windows-x64.exe"


def _record(folder, pattern):
    found = [p for p in Path(folder).glob(pattern)]
    if len(found) != 1:
        sys.exit(f"{folder}: expected one {pattern}, found {len(found)}")
    return json.loads(found[0].read_text())


def stage(engine_zip, desktop_exe, dest):
    """Unpack the zip's single top folder into dest and add the desktop app."""
    with zipfile.ZipFile(engine_zip) as z:
        for info in z.infolist():
            name = info.filename
            if name.startswith("/") or ".." in name.split("/") or not name.startswith(build_windows.TOP + "/"):
                sys.exit(f"{engine_zip.name}: unexpected member {name}")
            if name.endswith("/"):
                continue
            target = dest / name[len(build_windows.TOP) + 1:]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(info))
    shutil.copyfile(desktop_exe, dest / "argus-desktop.exe")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--engine", required=True)
    ap.add_argument("--desktop", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--makensis", default=shutil.which("makensis") or "makensis")
    args = ap.parse_args()
    engine_rec = _record(args.engine, "windows-build.json")
    desktop_rec = _record(args.desktop, "*-build.json")
    for rec in (engine_rec, desktop_rec):
        if rec["version"] != args.version:
            sys.exit(f"a build is version {rec['version']}, not {args.version}")
    if engine_rec["commit"][:12] != desktop_rec["commit"][:12]:
        sys.exit(f"engine {engine_rec['commit']} and desktop {desktop_rec['commit']} are different commits")
    engine_zip = Path(args.engine) / build_windows.ZIP_NAME
    desktop_exe = Path(args.desktop) / DESKTOP_EXE
    for path, rec in ((engine_zip, engine_rec), (desktop_exe, desktop_rec)):
        if hashlib.sha256(path.read_bytes()).hexdigest() != rec["files"][path.name]["sha256"]:
            sys.exit(f"{path.name} differs from its build record")
    # Absolute: makensis resolves a relative OutFile against the .nsi's folder, not the cwd.
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="argus-setup-") as tmp:
        src = Path(tmp).resolve() / "src"
        src.mkdir()
        stage(engine_zip, desktop_exe, src)
        cmd = [args.makensis, "-V2", "-INPUTCHARSET", "UTF8",
               f"-DVERSION={args.version}", f"-DFILE_VERSION={build_windows.file_version(args.version)}",
               f"-DSRC={src}", f"-DOUTFILE={out / SETUP_NAME}"]
        icon = HERE.parent / "desktop" / "icons" / "icon.ico"
        if icon.is_file():
            cmd.append(f"-DICON={icon}")
        cmd.append(str(HERE / "windows" / "setup.nsi"))
        subprocess.run(cmd, check=True)
    record = {"edition": "windows-setup", "version": args.version, "commit": engine_rec["commit"],
              "contains": {build_windows.ZIP_NAME: engine_rec["files"][build_windows.ZIP_NAME]["sha256"],
                           DESKTOP_EXE: desktop_rec["files"][DESKTOP_EXE]["sha256"]},
              "files": {SETUP_NAME: {"bytes": (out / SETUP_NAME).stat().st_size,
                                     "sha256": hashlib.sha256((out / SETUP_NAME).read_bytes()).hexdigest()}}}
    (out / "setup-build.json").write_text(json.dumps(record, indent=2) + "\n")
    policy = gate.load_policy()
    problems = gate.check_artifact(out / SETUP_NAME, gate.rule_for(SETUP_NAME, policy), policy)[0]
    for p in problems:
        print("REFUSED  " + p)
    if problems:
        sys.exit(f"the Setup fails the content gate ({len(problems)} problems)")
    print(f"{SETUP_NAME} passes the content gate")


if __name__ == "__main__":
    main()
