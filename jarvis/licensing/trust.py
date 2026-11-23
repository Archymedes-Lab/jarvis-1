"""Public keys that sign Argus licence certificates and content packs, by kid.

hosted/licence-cloudflare/scripts/licence-keygen.ts adds entries here; the matching private
key is the pay.archymedes.xyz Worker secret LICENCE_SIGNING_KEY and is never in this repository.
Rotation (docs/LICENSING-ARCHITECTURE.md §9): ship a release that has the new kid, switch the
Worker to it, and remove the old kid only after its last 30-day lease has run out.

Values are raw 32-byte Ed25519 public keys, base64url without padding.
"""

PUBLIC_KEYS = {
    '2026-11-a': 'nEZq9X9fM6WzvAJYY3dZHZkrX0uLVOL4NZXU8DM-zC4',
}
