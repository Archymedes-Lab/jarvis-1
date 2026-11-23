# Fast release: one dry-run branch, then promote it

A cold tagged release takes 65-70 minutes on the free runners (2 vCPUs for a private repository,
so the Windows compile cannot be spread out). A dry run with a warm compiler cache and the
install test split across hosts takes about 30. Promotion makes the release itself minutes long
by reusing the dry run instead of rebuilding it. The org's Actions budget is $0 with "stop
usage": every minute saved is budget kept.

## Why one branch

GitHub scopes a cache to a branch: a branch reads its own caches and `main`'s, never a sibling
branch's. A new `release-test/<name>` branch therefore always builds cold (run 42117983818: "Cache
not found for input keys"). **Always push dry runs to the same branch**, so its compiler cache
stays warm:

    git push --force org org-main:refs/heads/release-test/sharded-check-20261106

(That branch name is the standing dry-run branch because its caches are the warm ones; a
different name starts cold once. Check the run is for the commit you mean before tagging.)

A newer push to the branch cancels the run in progress, so push once and wait.

## The flow

1. Merge to `main` as usual (CI runs on every push).
   **Before the dry run**, make and sign the host attestation and commit it
   (`python3 release/host_attest.py make`, then `ssh-keygen -Y sign` with your release key; see
   release/host_attest.py). A tag's `verify` requires it, and the tag must sit on the dry run's
   exact commit, so the attestation commit comes first: attest, push `main`, dry run, tag.
2. Push `main` to the dry-run branch (above). The dry run builds everything, installs the Setup
   on clean Windows hosts (one scenario per host, in parallel), assembles and gates the release,
   and keeps `release-out` and `build-records` for seven days.
3. When it is green, ask which tag promotes it (needs `gh`):

       python3 release/promote.py suggest

   It prints `git tag v<version> <commit>`. The version is the dry run's own
   (`YYYY.MM.DD-<run number>`) because it is stamped into every binary.
4. Push that tag. `meta` finds the dry run, `verify` runs again, and `promote` re-checks every
   file against its record and the dry run's manifest, then runs `assemble.py` and the content gate
   again under the tag's name and creates the **unsigned draft**. Signing and publishing are
   unchanged (`release/sign.py`, then publish).

## What decides

`release/promote.py find` promotes only a dry run that is a push to `release-test/*` of exactly
this commit, finished with success, started by whoever pushed the tag (or by someone listed in
the `ARGUS_PROMOTE_ACTORS` repository variable), still holding both artifacts, and of exactly the
tag's version.

- No dry run of the commit: the tag builds cold, exactly as before.
- A dry run exists but does not match (other version, other commit): the tag run **fails with the
  tag to use**, rather than silently spending 65 minutes.
- A dry run by someone else, expired artifacts: cold build.

## The trade

A dry run builds with a warm compiler cache that anyone who can push the dry-run branch could have
written to, and a cold tag build does not. Promotion trades that for time and relies on the same
people who can already push release branches and tags. A releaser still reads the report and signs
it. If that is not acceptable for a release, delete the dry run's artifacts (or tag a commit that
has no dry run) and the tag builds cold.

## Cost, measured on 2026-11-05 (rates: Linux $0.006/min, Windows $0.010/min)

| | wall clock | billed (approx.) |
|---|---|---|
| cold tagged release | 65-75 min | about $1.00 |
| dry run, warm cache, sharded install test | about 30 min (to be measured) | about $0.60 |
| promotion | a few minutes | cents |
