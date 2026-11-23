# Proposal for review: third-party build paths in the Windows runtime

**Status: not applied.** `release/policy.json` is unchanged on `prod-ready`. The
change is staged on branch `policy/windows-third-party-paths` (one commit on top of
`prod-ready`) and needs the two-person review `policy.json` requires. Dry runs
(release-test/*) load the same values through `release/proposals/windows-markers.json`;
a tagged build never does.

## What happened

CI dry run #3 (run 41714844470) built `Argus-Setup.exe`, and the content gate opened
it with 7z and refused 23 members for markers. Every one is a **third-party runtime
binary carrying its maintainers' own build paths**. None is in `argus.exe`, in our
compiled modules, in our data files or in the desktop app (checked with the gate's own
markers against the Nuitka output and the desktop build).

| marker | matched | binaries | whose path it is |
|---|---|---|---|
| `windows-build-path` | `D:\a\1\` | `python3*.dll`, `_ssl.pyd`, `_socket.pyd`, `_ctypes.pyd`, `_sqlite3.pyd`, `_hashlib.pyd`, `_lzma.pyd`, `_bz2.pyd`, `_decimal.pyd`, `_elementtree.pyd`, `_uuid.pyd`, `_wmi.pyd`, `pyexpat.pyd`, `select.pyd`, `unicodedata.pyd`, `sqlite3.dll`, `libcrypto-3.dll`, `libssl-3.dll` | Python project's release pipeline (PDB path in the PE debug directory) |
| `windows-build-path` | `C:\A\_work\`, `D:\a\_work\` | `libcrypto-3.dll`, `libssl-3.dll`, `vcruntime140.dll`, `vcruntime140_1.dll` | OpenSSL / Microsoft build agents |
| `windows-build-path` | `D:\a\cryptography\` | `cryptography/hazmat/bindings/_rust.pyd` | PyCA's CI |
| `windows-home-path` | `C:\Users\runneradmin\` | `cryptography/hazmat/bindings/_rust.pyd` | PyCA's CI runner account |

These cannot be removed without breaking the vendors' Authenticode signatures, and any
standard Windows Python runtime carries them.

## The change (two parts, nothing else)

1. **`windows-build-path` matches our own runner path only.** It was
   `[A-Z]:\\a\\<any name>\\ | [A-Z]:\\actions-runner\\`, written to catch our CI
   (`D:\a\Argus-1\Argus-1\`), but GitHub Actions uses `D:\a\` for every project, so it
   also matched other projects' pipelines. It becomes `[A-Z]:\\a\\Argus-1\\ |
   [A-Z]:\\actions-runner\\`. The Linux policy already makes this choice: its markers name
   our paths, and maintainers' paths (`/github/home/`, `/opt/_internal/`) are not markers
   (commit 8678015).
2. **One digest-pinned exemption** for `cryptography/hazmat/bindings/_rust.pyd`, marker
   `windows-home-path`, SHA-256 `1d4332a447cab13dec8e3a533ad579e0e562b79e40822c931f33769758fc7156`
   (the file inside the hash-pinned `cryptography-50.0.2-cp311-abi3-win_amd64.whl`, read
   from the wheel's own RECORD and equal to the file Nuitka copies into the install). It
   applies to exactly those bytes at exactly that member: the same marker in any other
   file, or in this file changed, is refused. It must be re-pinned on every cryptography update.

`windows-home-path` itself is **not** loosened: a runner home folder remains a leak
(`tests/test_release_gate.py::test_any_home_folder_is_refused` pins `C:\Users\runneradmin\.cargo\x`).
An earlier draft of this proposal treated `runneradmin` as a placeholder name; that
contradicted this test and was dropped.

## What keeps our own code covered

Narrowing a marker must not hide a leak of our own paths. So `release/build_windows.py`
rescans everything that is ours (`argus.exe`, `argus-desktop.exe`, `argus/**`) with the
**committed** policy, never a proposal, and refuses to build on any hit. Tests
(`tests/test_release_proposals.py`) pin both directions: our runner path and self-hosted
runner path are still refused by the narrowed marker, other pipelines' paths are not,
a vendor path inside our own program is still caught, and a real person's home folder is
still refused.

## Rejected options

- Treat `runneradmin` as a placeholder (weakens detection of our own runner home; contradicts an existing test).
- Rewrite the vendors' binaries to remove the paths (invalidates their signatures; makes the runtime unverifiable).
- Hold the Windows installer (remains available if you prefer not to change the policy).

## Separate finding: the published Linux server ships no dashboard files

Not part of this proposal, found while testing it. The published
`argus-server-linux-x86_64.tar.gz` (2026.10.30-2) contains **0** files under
`web/static/` (only `web/styles/*.css`). `build_server.py` collects package data with
`Path.glob("web/static/**")`, which returns only directories up to Python 3.12 (files too
from 3.13), so on the 3.12 build image the dashboard HTML and scripts are silently left
out. The Windows build now collects data in a version-independent way
(`build_windows.data_files`); the Linux build is untouched, because adding the files would
exceed the gate's 25% file-count growth limit and is your call. Suggested fix: use the same
helper in `build_server.py` and accept the one-time count increase explicitly.
