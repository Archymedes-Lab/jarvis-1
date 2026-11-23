# Releaser keys: adding, losing, revoking, rotating

How trust works (release/signers.py): a key signs a release only if it is
**listed** in `release/allowed_signers` (in the repository) **and** its SHA-256
fingerprint is **pinned** outside the repository: the admin-only
`ARGUS_RELEASE_SIGNERS` variable in Argus-1 and in archymedes-site, and
`~/.config/argus-release/trusted_signers` on the owner's machine (the live audit).
A push can add a line to the file; it cannot pin a key. Any one pinned releaser
is enough to sign. `tests/test_release_keys.py` exercises every case below.

## What is true today (2026-10-29)

- One releaser is listed: `chrisnkuno`.
- `ARGUS_RELEASE_SIGNERS` is **not set** in Argus-1 or archymedes-site, so no key
  is pinned yet and every signature check fails closed. Nothing can be published
  until an admin sets it.
- The signing key is not on the build machine and must never be.
- A second releaser has not been added. With one, losing that key stops releases
  (it never weakens them); see "Lost key" for the exact steps.

## Add a second releaser (do this before you need it)

1. **Authorization.** The owner (an Argus-1 admin) approves in writing who may release.
2. **Key storage.** On the new releaser's own computer, never a shared one or CI:
   `mkdir -p -m 700 ~/.config/argus-release && ssh-keygen -t ed25519 -C <github-login>@argus-release -f ~/.config/argus-release/signing_key`
   with a real passphrase. Back the private key up offline (printed or an encrypted
   USB kept somewhere locked). Never email it, paste it in chat, or store it in a repository.
3. The new releaser reads out `ssh-keygen -lf ~/.config/argus-release/signing_key.pub`
   (the `SHA256:` fingerprint) over a second channel (call or in person).
4. They open a pull request adding one line to `release/allowed_signers`:
   `<github-login> namespaces="argus-release" ssh-ed25519 AAAA...`
5. An admin compares the fingerprint with what was read out, merges, then appends
   `<github-login>=SHA256:...` to `ARGUS_RELEASE_SIGNERS` in **both** repositories and to
   `~/.config/argus-release/trusted_signers` on the owner's machine.
6. Prove it: the new releaser signs a dry-run draft (`python3 release/sign.py <tag>`)
   and `python3 release/check.py <folder>` passes with their key. Do not rely on it unproven.

## Lost key (nobody has the private key any more)

The key cannot be misused, so there is no emergency, but treat it as possibly stolen if
you are not certain where it went.

1. A remaining releaser (or the owner, as admin) removes the lost key's fingerprint from
   `ARGUS_RELEASE_SIGNERS` in both repositories and from `trusted_signers`, then removes its
   line from `release/allowed_signers` by pull request.
2. Releases that key already signed no longer verify. The live audit will say so within 30
   minutes. Re-sign the current live release with another pinned key
   (`python3 release/sign.py <tag>` then `gh release upload <tag> SHA256SUMS.sig --clobber`,
   then publish that tag again with `publish.yml`, `rollback: true` for the same version).
3. If it was the **only** pinned key: releases stop, deliberately. The owner generates a new key
   (steps 2 to 5 above, with the owner acting as admin), pins it, and re-signs the live release.
   Until then the site keeps serving the last published files and the audit reports them unsigned.

## Compromised key (someone else may hold it)

Do the lost-key steps **immediately**, in this order: unpin first (it takes effect at once), then
review everything published since the key was last known good: `git log` on the downloads folder in
archymedes-site and the GitHub Release history. If anything was published that you did not sign, take
the downloads offline (`public/downloads/argus/*` removed except an empty `manifest.json`
`{"version": "", "files": {}}`), then re-publish a release you rebuild and re-sign yourself.

## Rotation (scheduled replacement of a key)

1. Add the new key as above (listed and pinned) while the old one is still pinned.
2. Sign the next release with the new key and check it passes.
3. Unpin and delist the old key. Releases it signed must be re-signed with the new key.
Rotate yearly, and when a releaser leaves the same day they leave.

## What this does not protect against (free GitHub plan)

A collaborator with write access can edit workflows; see "Known limits" in RELEASING.md. The
owner's live audit (release/audit.py), run with the owner's own pinned file, still reports an
unsigned or non-conforming download. Two-person approval is not enforced by the code: it needs
GitHub Team (protected branches, required reviews).

## Windows code signing (Authenticode) is separate

Releaser keys sign `SHA256SUMS` so the site and the audit know who approved a release. They do
not make Windows trust a program. Authenticode identifies the Windows publisher; new signed files can still warn
until reputation develops. EV certificates no longer bypass SmartScreen. See
[Microsoft guidance](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation).
Still missing, and needed from the owner: (1) a publicly trusted code-signing certificate, or
a validated Microsoft Artifact Signing public-trust profile, with its
private key held by a hardware token or cloud signing service, never an exported key file in CI; (2) a signing step in
`release/build_desktop.py` for `argus-desktop-windows-x64.exe` and the installer that signs with
`signtool /fd SHA256 /tr <RFC 3161 timestamp URL> /td SHA256`, so the signature stays valid after the
certificate expires; (3) gate policy to reject an unsigned `.exe`. None of this has been done or tested.


For the concrete signing order, prerequisites and acceptance checks, see
[the Windows publisher-trust plan](WINDOWS-PUBLISHER-TRUST-2026-11-10.md).
