# Host-bound tests

`tests/host-bound.txt` lists 66 unit tests that pass only on a **WSL2 host with the Windows
side reachable** (environment name `wsl2-windows-interop`). The code they test decides what
to do from the host it runs on (a Microsoft kernel string, `/mnt/c`, registered Windows jobs,
interop), so on a plain Ubuntu CI runner they fail for that reason alone. They are real tests
of real behavior; they are not skipped, weakened or relabelled.

## How they are run, and how a release depends on them

- **CI** (`python3 scripts/dev/ci_suite.py`) runs every other test. Any failure fails the job.
  It prints `NOT RUN here: 66 host-bound tests` so they are never mistaken for passed.
- **On the host** (`python3 scripts/dev/ci_suite.py --host`) runs only those 66 and refuses to
  run anywhere else (exit 2, "NOT RUN").
- **For a release**, on that host: commit, then `python3 release/host_attest.py make`, then sign
  `release/host-attestation.json` with the releaser key (command in the script's docstring), commit
  the file and its `.sig`. `release.yml` runs `host_attest.py check` for a tag: the signature must be
  from a pinned releaser, the result must be a complete pass over exactly the tests listed now, and
  nothing under the code paths may have changed since the attested commit.

## Real results

2026-10-29, Ubuntu on WSL2 (Windows 11, Python 3.12, interop binary not executable, `/mnt/c`
mounted): see the PR description for the counts of the run on the commit that introduced this file.
Re-run on every release; the attestation is the record.

## Why they are host-bound

The reason is the owner's measurement in commit `bbee1bf`: each of these passes on WSL2 and fails
the same way once the kernel reads as plain Linux, because the code under test branches on the
host (Windows jobs registered, `/mnt/c`, interop). Per-test reasons have not been written down
yet; the most useful next step is to go through the list, inject the host facts into each test
instead of reading them, and delete its line from `host-bound.txt` once it passes on a plain
runner. Never add a line without a reason recorded here.
