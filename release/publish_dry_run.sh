#!/usr/bin/env bash
# Publish a green release-test dry run straight to www.archymedes.xyz: the
# owner's release method since 2026-11-03 (docs/guides/RELEASING.md, "Publishing
# a dry run"). No tag, draft or publish.yml; the same gate, signature and
# read-back.
#
#   bash release/publish_dry_run.sh RUN_ID
#
# Stops at the first failure and changes nothing public before step 6. The only
# prompt is your release key's passphrase (asked again on a typo, up to 5
# times); a rerun of a run already signed resumes at the site without it.
# Every path below can be overridden from the environment.
set -euo pipefail

RUN=${1:?usage: release/publish_dry_run.sh RUN_ID (a green release-test run of release.yml)}
[[ "$RUN" =~ ^[0-9]+$ ]] || { echo "run id must be digits only, got: $RUN"; exit 2; }
REPO=${ARGUS_REPO:-Archymedes-Lab/argus-1}
SRC=$(cd "$(dirname "$0")/.." && pwd)                       # this checkout: gate, check, publish
D=${ARGUS_PUBLISH_DIR:-$HOME/.cache/argus-instinct-publish}  # working folder, outside the checkout
OUT=$D/release-out
SITE=$D/site
SITE_REPO=${ARGUS_SITE_REPO:-$HOME/archymedes-site}          # its .vercel/project.json links the deploy
KEY=${ARGUS_RELEASE_KEY:-$HOME/.config/argus-release/signing_key}
# The gate opens the Setup with 7z: from PATH, ARGUS_7Z_DIR, or the owner's unpacked copy.
LOCAL7Z=$HOME/.cache/argus-tools/7zip/root/usr/lib/7zip
if [ -n "${ARGUS_7Z_DIR:-}" ]; then export PATH=$ARGUS_7Z_DIR:$PATH
elif ! command -v 7z >/dev/null && [ -x "$LOCAL7Z/7z" ]; then export PATH=$LOCAL7Z:$PATH; fi
command -v 7z >/dev/null || { echo "7z is needed (sudo apt install 7zip, or set ARGUS_7Z_DIR)"; exit 2; }
export ARGUS_RELEASE_SIGNERS="${ARGUS_RELEASE_SIGNERS:-$(cat "$HOME/.config/argus-release/trusted_signers")}"
mkdir -p "$D"

echo "== 1/7 the dry run must be green"
[ "$(gh run view "$RUN" -R "$REPO" --json conclusion --jq .conclusion)" = success ] \
  || { echo "run $RUN is not green: https://github.com/$REPO/actions/runs/$RUN"; exit 1; }

# Already downloaded, gated and signed for this run (an earlier attempt that
# stopped after signing)? Then resume at the site: no download, no passphrase.
if [ -f "$D/.signed-run" ] && [ "$(cat "$D/.signed-run")" = "$RUN" ] && [ -f "$OUT/SHA256SUMS.sig" ] \
   && (cd "$OUT" && sha256sum --quiet -c SHA256SUMS) \
   && ssh-keygen -Y check-novalidate -n argus-release -s "$OUT/SHA256SUMS.sig" < "$OUT/SHA256SUMS" >/dev/null 2>&1; then
  echo "== 2-4/7 run $RUN is already downloaded, gated and signed: resuming at the site"
else
echo "== 2/7 download the assembled, gated release folder"
rm -rf "$OUT"; mkdir -p "$OUT"
gh run download "$RUN" -R "$REPO" -n release-out -D "$OUT"
ls -la "$OUT"

echo "== 3/7 content gate again, here (every file, the Setup opened with 7z)"
(cd "$SRC" && python3 - "$OUT" <<'PY'
import sys; sys.path.insert(0, "release")
import gate
problems, counts = gate.check_release(sys.argv[1], gate.load_policy())
for p in problems: print("REFUSED  " + p)
if problems: sys.exit(f"{len(problems)} problems: not publishing")
print("gate OK:", counts)
PY
)
(cd "$OUT" && sha256sum -c SHA256SUMS)

echo "== 4/7 sign SHA256SUMS with your release key (passphrase prompt)"
# A wrong passphrase asks again (up to 5 tries) instead of restarting the run.
signed=0
for try in 1 2 3 4 5; do
  rm -f "$OUT/SHA256SUMS.sig"
  if ssh-keygen -Y sign -f "$KEY" -n argus-release "$OUT/SHA256SUMS"; then signed=1; break; fi
  if [ "$try" -lt 5 ]; then echo "signing failed (try $try of 5): enter the passphrase again"; fi
done
[ "$signed" = 1 ] || { echo "not signed after 5 tries: nothing was published"; exit 1; }
echo "$RUN" > "$D/.signed-run"
fi

echo "== 5/7 site: a fresh worktree of its master"
git -C "$SITE_REPO" fetch -q origin
git -C "$SITE_REPO" worktree remove --force "$SITE" 2>/dev/null || true
git -C "$SITE_REPO" worktree add -q -B publish-argus "$SITE" origin/master
# The deploy must target the archymedes-site project: reuse the main checkout's link.
mkdir -p "$SITE/.vercel" && cp "$SITE_REPO/.vercel/project.json" "$SITE/.vercel/project.json"

echo "== 6/7 lay out the downloads, check the site copy, commit and push master"
TAG=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['tag'])" "$OUT/manifest.json")
VERSION=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['version'])" "$OUT/manifest.json")
(cd "$SRC" && python3 release/publish.py --release "$OUT" --site "$SITE" --tag "$TAG")

echo "== 7/7 deploy to production directly, then read the live site back"
(cd "$SITE" && bun install --frozen-lockfile >/dev/null \
  && vercel pull --yes --environment=production \
  && vercel build --prod \
  && vercel deploy --prebuilt --prod)
(cd "$SRC" && python3 release/publish.py --readback --version "$VERSION" --timeout 1500)
echo "ARGUS-INSTINCT $VERSION is live: https://www.archymedes.xyz/en/solutions/argus/#download"
