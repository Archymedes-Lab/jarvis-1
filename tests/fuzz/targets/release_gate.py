"""release/gate.py, release/versioning.py: code that reads downloaded release bytes.

The gate fails closed on any exception inside check_artifact (an unreadable
container is a refusal), so for the container readers only hangs, slow inputs
and oracle failures are findings; the oracles say what the gate must refuse."""

import io
import lzma
import re
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

from tests.fuzz.engine import ROOT, Target

sys.path.insert(0, str(Path(ROOT) / "release"))
import gate  # noqa: E402
import versioning  # noqa: E402

POLICY = gate.load_policy()


# --- builders for seeds (synthetic, never real release bytes) ----------------------

def tar_bytes(files, compress=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:" + (compress or "")) as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode = len(data), 0o644
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def ar_bytes(members):
    out = b"!<arch>\n"
    for name, data in members:
        out += f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode()
        out += data + (b"\n" if len(data) % 2 else b"")
    return out


def deb_bytes(data_files, extra=()):
    control = lzma.compress(tar_bytes({"./control": b"Package: argus\nVersion: 1\n"}))
    data = lzma.compress(tar_bytes(data_files))
    return ar_bytes([("debian-binary", b"2.0\n"), ("control.tar.xz", control),
                     ("data.tar.xz", data), *extra])


def zip_bytes(files, method=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57


# --- targets ----------------------------------------------------------------------

def run_deb(data):
    gate._deb_members(data)


def run_zip(data):
    gate._zip_members(data)


def run_scan(data):
    # scan_bytes runs outside check_artifact's try for kind "binary": it must not raise.
    gate.scan_bytes("fuzz.bin", data, POLICY)


def run_nested(name):
    """Oracle: a denied member must be refused wherever it sits. Here it is inside
    a zip that is itself a member of an allowed zip artifact (a .whl, .jar, .nupkg,
    a bundled .zip): the gate must still see the denied name."""
    # zipfile truncates member names at NUL bytes and keeps backslashes literal;
    # the gate normalizes backslashes to slashes when it renders the member name.
    rendered = name.split("\x00", 1)[0].replace("\\", "/").strip().strip("/") or "x"
    if not gate.denied_path(rendered, POLICY) or ".." in rendered.split("/") \
            or rendered.startswith("/"):
        return
    inner = zip_bytes({rendered: b"print('hi')\n"})
    rule = {"name": "fuzz.zip", "kind": "zip", "allow": ["app/**/*"], "executables": []}
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "fuzz.zip"
        p.write_bytes(zip_bytes({"app/lib/bundle.zip": inner}))
        problems, _n = gate.check_artifact(p, rule, POLICY)
    assert any(rendered.lower() in p.lower() for p in problems), \
        f"nested archive hides a denied member: {rendered!r} inside app/lib/bundle.zip passes the gate"


ASCII_TAG = re.compile(r"v?20[0-9]{2}\.[0-9]{2}\.[0-9]{2}(?:-(?:0|[1-9][0-9]*))?", re.ASCII)


def run_version(text):
    """Oracle: a candidate accepted by candidate_key is exactly the documented ASCII
    grammar (a tag becomes a git ref, a file name and a URL path)."""
    try:
        versioning.candidate_key(text)
    except versioning.VersionError:
        return
    assert ASCII_TAG.fullmatch(text), f"candidate outside the tag grammar accepted: {text!r}"


def _windows_canonical(path):
    """How Windows (case-insensitive, Win32 path rules) names the extracted file:
    backslashes become slashes, case folded, trailing dots and spaces dropped
    from every segment."""
    return "/".join(seg.rstrip(". ") for seg in path.replace("\\", "/").lower().split("/"))


def run_denied_case(path):
    """Oracle: the Windows zip unpacks on a case-insensitive file system, so a member
    the policy denies under its Windows name must be denied as written."""
    if gate.denied_path(_windows_canonical(path), POLICY) and not gate.denied_path(path, POLICY):
        raise AssertionError(f"denied member passes under another spelling: {path!r} "
                             f"(Windows extracts it as {_windows_canonical(path)!r})")


def _seed_deb():
    return deb_bytes({"./usr/bin/argus": ELF, "./usr/share/doc/argus/copyright": b"MIT\n"})


TARGETS = [
    Target("gate.deb", run_deb, [_seed_deb(), ar_bytes([("debian-binary", b"2.0\n")])], kind="bytes",
           expected=(Exception,), max_len=1 << 16, timeout_s=3.0,
           note="ar/.deb reader; exceptions fail closed, so only hangs/slow count"),
    Target("gate.zip", run_zip, [zip_bytes({"app/argus.exe": b"MZ" + b"\0" * 62, "app/README": b"x"}),
                                 zip_bytes({"a": b"b"}, zipfile.ZIP_STORED)], kind="bytes",
           expected=(Exception,), max_len=1 << 16, timeout_s=3.0),
    Target("gate.scan_bytes", run_scan,
           [ELF + zip_bytes({"src/x.py": b"x"}), b"MZ" + b"\0" * 64 + zip_bytes({"a/b.txt": b"x"}),
            b"/home/runner/work/x", ELF + b"PK\x01\x02" + b"\0" * 60 + b"PK\x05\x06" + b"\0" * 18],
           kind="bytes", tokens=(b"PK\x01\x02", b"PK\x05\x06", b"PK\x06\x06", b"/home/", b"-----BEGIN"),
           max_len=1 << 16, timeout_s=3.0),
    Target("gate.nested_archive", run_nested,
           ["src/main.py", "tests/test_x.py", "app.js.map", "id_rsa", "x/.git/config", "poetry.lock"],
           tokens=(".py", ".map", "/", "src/", ".pem", ".key"), max_len=200,
           note="property: denied members inside a nested archive"),
    Target("gate.denied_path_case", run_denied_case,
           ["app/docs/readme.txt", "app/src/main.dll", "app/tests/x.dll", "app/x.py", "app/.git/config"],
           tokens=("Docs", "SRC", "Tests", ".PY", ".", " ", "Node_Modules", "/"), max_len=120,
           note="property: Windows file-name equivalence of denied members"),
    Target("versioning.candidate", run_version,
           ["v2026.11.04", "v2026.10.31-2", "2026.10.29.1", "v2026.02.30", "v2026.11.04-0"],
           tokens=("\n", "\u0663", "\uff12", "-", "v", "."), max_len=64),
]

