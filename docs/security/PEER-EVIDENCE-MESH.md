# Permissioned peer evidence mesh

## Invariants recorded before editing (2026-10-01)

- Canonical collector logs, cursors, acknowledgments and custody jobs remain authoritative and unchanged. Replication is an explicit CLI action and failure cannot block protection.
- Private raw records, command lines, names, paths, usernames, documents, IPs and domains never enter the projection. Only fixed vocabulary, sequence, coarse time and keyed pseudonyms leave the origin, inside authenticated encryption. Pseudonymization is not anonymity: timing, volume, peer connection IP and stable stream identities leak.
- Ed25519 authenticates origins and witnesses; AES-256-GCM protects projected history. Archive and pseudonym keys remain on the owner computer. Neither peers nor model output can authorize actions. No automatic enrollment, discovery, forwarding, voting, suppression, or deletion.
- A receiver accepts only enrolled public keys, contiguous chains and bounded requests. It durably commits a block before signing a receipt. Duplicate retry returns the same block; forks, gaps, invalid signatures, stale responses and quota exhaustion fail closed.
- Database transactions, FULL synchronous mode, bounded busy timeout, byte and block limits, bounded scans and bounded network retries apply. No automatic pruning. Files are owner-only, symlinks and unsafe directories are refused. Administrator-controlled storage is not WORM.
- A witness receipt is historical evidence of a commit, not a guarantee the peer still holds it. A fresh challenged head check detects rollback below the checkpoint. Recovery requires an independently retained signed checkpoint and its pinned witness key; unknown missing tails remain unknown.
- Lost encryption keys mean lost readable history. Lost source-signing keys require a new stream and explicit re-enrollment. Interrupted requests cannot advance an origin cursor beyond the locally committed encrypted block. No remote response mutates local canonical evidence.

## Alternatives and selection

A single-machine blockchain cannot survive deletion of the machine's copies. A public consensus network adds consensus cost, Sybil defenses, irreversible public metadata and operational complexity without preserving encrypted payloads by itself. Remote WORM provides stronger enforced retention but requires provider, retention and recovery-key decisions. Select per-origin signed chains replicated to explicitly pinned independent witnesses. A configured receipt count describes copies, not independent administrative domains or consensus truth. A malicious origin can sign competing forks or fabricate observations; witnesses reject forks they have seen but global equivocation detection is future work.

Reconsider after measured write latency, backlog, recovery time, disk growth or operator effort exceeds agreed deployment budgets. This first implementation does not claim a production mesh, tamper-proof storage, truthful sensors or complete process capture.

## Wire and privacy contract

Version 1 exports only process-category events and process-present snapshots. Others advance the scan cursor but are not exported; the encrypted batch records the scanned range and count of skipped records. No backfill invents missing observations. Process identity is keyed from host, boot, GUID or PID plus start identity; incomplete identity is explicit. Parent identities remain unknown unless a parent GUID is known. Images receive private keyed pseudonyms, preventing public dictionary lookup of executable hashes or names. Times are rounded down to minutes. Action is from a closed allowlist. Source head and last-record commitment remain encrypted.

Each block contains version, producer public key, height, previous block digest, random GCM nonce and ciphertext, signed with Ed25519. Encryption authenticates the header. Transport uses HTTPS, normal certificate validation and pinned signing keys; redirects and environment proxies are forbidden. Requests are origin-signed and responses witness-signed, bound to a random request nonce and request digest. A receiver needs its own TLS certificate and explicitly enrolled producers. It binds to loopback by default; exposure and firewall configuration are operator tasks.

The peer stores ciphertext and cannot decrypt it. Private archive keys must be backed up separately. Restored data are the minimized projection, not original forensic records. Exact original history still needs separately authorized encrypted archival.

## Operator workflow

Optional dependency: `cryptography` (Ed25519 and AESGCM); missing dependency fails explicitly only for mesh commands. Core JARVIS remains standard-library-only. No software installation or peer configuration is performed implicitly.

`jarvis mesh init --root NEW_OWNER_ONLY_DIRECTORY` creates a new identity and archive key.
`jarvis mesh serve --root PEER_DIRECTORY --allow-producer PRODUCER_PUBLIC_HEX --cert CERT --tls-key KEY` starts a bounded single-request-at-a-time HTTPS witness.
`jarvis mesh publish --root ORIGIN_DIRECTORY --log CANONICAL_LOG --peer https://HOST:PORT,WITNESS_PUBLIC_HEX --quorum 1` prepares at most one batch, retries pending blocks and collects receipts. Run repeatedly or under an independently configured supervisor. No background scheduler is installed by this feature.
`jarvis mesh status --root ORIGIN_DIRECTORY` reports local state and receipt copies, without claiming current remote availability.
`jarvis mesh check --root ORIGIN_DIRECTORY --peer URL,KEY` challenges the current peer head against the locally retained head.
`jarvis mesh checkpoint --root ORIGIN_DIRECTORY --output NEW_FILE` exports signed witness responses for independent custody.
`jarvis mesh recover --root OWNER_DIRECTORY --destination NEW_DIRECTORY --checkpoint SAVED_FILE --peer URL,KEY` recovers into a new store and verifies against the independently held checkpoint.
`jarvis mesh read --root DIRECTORY` decrypts the latest minimized batch locally.

Use peers in different administrative domains. Keep keys and checkpoint exports independently. No network of peers, remote WORM retention or live service integration is configured by merely implementing this protocol.

## Local preparation and measured acceptance (2026-10-02)

The two-server experiment is prepared under ignored `.peer-mesh-local/`, with one origin identity and separate witness identities, databases and TLS keys. Directories are mode 0700 and generated files mode 0600. Certificates are local self-signed certificates valid for 30 days; an explicit local CA bundle preserves certificate validation. Do not share this directory: it contains private signing, archive and TLS keys. Back up the owner's archive and signing keys independently using a protected backup process; key backup is not implemented here.

Start/restart each witness in a separate owner terminal:

```sh
python3 -m scripts.mesh_local serve --node witness1
python3 -m scripts.mesh_local serve --node witness2
```

They listen only on `127.0.0.1:9443` and `127.0.0.1:9444`. This is a foreground experiment with no installed supervision, boot activation, scheduled publisher or protected-service release change. Stop with Ctrl-C in the owning terminal. Stores survive a process restart. Run `python3 -m scripts.mesh_local prepare` only to create a new setup; an existing setup is refused rather than overwritten.

Publish one bounded batch and challenge the retained heads:

```sh
python3 -m scripts.mesh_local publish
python3 -m scripts.mesh_local check
```

Publishing is explicit and processes history from its beginning; repeat to advance the local replication cursor. Only three blocks were replicated during acceptance, not the complete original history. The first local publication required two witnesses and returned two fresh confirmations. After refining source verification, the next real batch scanned 963 committed observations and retained 500 process rows: 1.82 seconds wall time, 1.23 user CPU seconds, ~37.8 MiB peak RSS and 310,420 wire bytes per witness. This is a short-run measurement with source history concentrated in a large old segment, not a sustained throughput guarantee. Initial full-source verification took 19.82 seconds / 12.10 user CPU seconds and was replaced by verification of all header links plus complete hashes of the touched payloads. A segment can contain up to 256 MiB of uncompressed source bytes; a pass verifies at most 256 MiB and retains at most 8 MiB of minimized selection, scans at most 2,000 observations and exports at most 500 process rows. Already replicated old payloads are not rehashed every pass. An exhaustive canonical audit remains `jarvis history verify`.

Witness idle RSS measured ~32.0 and ~31.8 MiB, with zero additional CPU ticks during one five-second idle sample. Database budget defaults to 64 MiB, with no pruning; SQLite limits main-database pages as well as payload bytes. Rollback journals can transiently require additional space up to approximately another database budget. Each witness has one global capacity budget, not per-producer fairness: a trusted but faulty producer can exhaust it. Serial bounded HTTPS handling limits resource use but is not a public-network denial-of-service defense. Public exposure, dedicated operator identities, rate limits, capacity partitioning and administrative independence require separate deployment verification.

Witnesses retain signed contiguous blocks and issue receipts after commit. Origin receipt records reference the stored block instead of duplicating its ciphertext; full signed requests are reconstructed for verification and exported checkpoints. Exact recovery from a saved three-block checkpoint passed, including archive authentication and final digest comparison. The checkpoint and recovered copies currently remain on this host; independent custody is not claimed. Two-block recovery measured 0.73 seconds / ~34.5 MiB peak RSS. The real protected service readback remained healthy, ready and protection_healthy after local publication.

Commands to preserve a new checkpoint and recover its minimized timeline:

```sh
python3 -m scripts.mesh_local checkpoint --output .peer-mesh-local/NEW-CHECKPOINT.json
python3 -m scripts.mesh_local recover --output .peer-mesh-local/NEW-CHECKPOINT.json --destination .peer-mesh-local/NEW-RECOVERY
python3 -m jarvis mesh read --root .peer-mesh-local/NEW-RECOVERY --height 1
```

Keep the checkpoint independently and pin witness public keys before relying on it. Checkpoint exports include encrypted blocks and signed receipts; they are owner-only and refuse overwrite. Recovery resumes an incomplete destination in bounded 16-block passes and reports complete only when the saved digest matches. Exact names and paths cannot be recovered from this minimized projection. Original evidence archival remains a separate custody requirement.

Validation: 31 focused isolated security/transport/recovery tests passed; the final permitted-host full suite passed 1,946 tests in 311.6 seconds; all six architecture-layer tests passed; compilation and `git diff --check` passed. The first full suite caught a new package placed outside the existing layers; it was moved into `jarvis/platform/peerledger` without weakening the architectural tests. Ruff is not installed in this environment, so no Ruff result is claimed.

Cryptographic APIs use [Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/) and [AESGCM](https://cryptography.io/en/latest/hazmat/primitives/aead/). Encryption and pseudonym keys are derived with distinct HMAC-SHA256 purpose labels from the private archive master key. Missing optional cryptography fails explicitly for mesh commands; core commands remain usable.

Both experimental witnesses were then stopped by exact process identity and restarted with the final package layout; their databases and keys were retained. Fresh challenged heads still matched height 3, and a new post-restart recovery reproduced all three checkpointed blocks. This is process-restart evidence, not reboot or power-loss validation.

Final Jev implementation review used fixed engineering metadata and aggregate measurements only. Choice selected permissioned chains with concentration 1.0; Noul gave 0.95 for the full-anonymity limitation and 0.91 for conditional recovery despite receipts. Advice supported the design and its explicit boundaries; it did not authorize deployment or replace any deterministic gate. All 1,946 regression tests, the 31 focused mesh checks, local HTTPS execution and checkpoint recovery established the reported results independently. The updated assurance descriptions additionally passed all nine assurance tests.
