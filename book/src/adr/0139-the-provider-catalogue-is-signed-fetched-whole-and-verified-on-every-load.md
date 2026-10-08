# ADR-0139: The provider catalogue is signed, fetched whole, and verified on every load

Status: accepted

## Context

`envv enrich` recognises issuers by the public prefix of a stored secret (`ghp_`, `sk-ant-`, `AKIA`). That table was compiled into the binary, so a new issuer needed a release. Phase 31 publishes it as a static file. Enrichment writes into the vault, so the file is an input an attacker would like to control: it can mislabel a secret type, point a card at a hostile URL, or make every secret match.

## Decision

`vault-core/src/catalogue.rs` defines the format and every rule; `envv catalogue update|show|diff|export|sign` and the `catalogue_status` / `catalogue_update` Tauri commands are thin I/O around it.

- **Signed, key pinned in the binary.** The wire form is `{payload, signature}` where `payload` is a JSON _string_, so the Ed25519 signature covers the exact bytes signed and no re-serialisation can disturb it. The public key is `PINNED_KEY_HEX`; the private half is the `CATALOGUE_SIGNING_KEY` Actions secret. Rotating the key is a release.
- **Verified on every load, not only on download.** The cache file is re-verified each time `enrich` starts; a missing or invalid cache silently means "use the compiled table".
- **Shape checks after the signature.** A correctly signed mistake is still a mistake: prefixes under 3 characters (they would match nearly every secret), non-graphic prefixes, unknown `secret_type`, non-`https` URLs and oversize lists are refused.
- **No rollback.** `generated_at` may not be older than the cached catalogue's, so an old, valid, signed file cannot be replayed.
- **Fetched whole, never per provider.** One request tells the host nothing about which issuers a vault holds (the icon-CDN argument). https only, CA validation, 4 MiB cap.
- **The compiled table stays.** Lookup takes the longest matching prefix across catalogue and compiled table; a tie goes to the catalogue. `enrich` behaves identically on an air-gapped machine. `catalogue update --file` installs a catalogue from disk through the same checks.
- **Reference URLs** (`docs_url`, `rotate_url`, `revoke_url`) are carried and shown, not applied to entries.

## Consequences

The signing key is the one thing that must not leak or be lost. If it leaks, a forged catalogue verifies until the next release replaces the pin. If it is lost, new catalogues cannot be published until a release pins a new key.

`docs.yml` signs `catalogue/providers.json` on every push and daily, and serves it at `/catalogue/catalogue.json` on Pages. Without the secret (a fork) nothing is published and clients use the compiled table.

## Evidence

`cargo test -p vault-core catalogue` (tamper, wrong key, overbroad prefix, http URL, rollback). End to end: `envv catalogue sign` with the real seed, `update --file`, then `enrich` proposing a prefix that exists only in the catalogue; a one-letter edit of the signed file exits 10.
