# ADR-0138: The vault is stored row-per-entry, and a stale writer is merged, not refused

Status: accepted

## Context

Schema v1 kept the whole vault as one JSON string in one row (review-01 section 2.1). Every write parsed and re-serialised all of it; the compare-and-swap token was a hash of the blob, so two people editing different entries conflicted, and both branches of the conflict prompt discarded someone's changeset; `version_history` (up to 50 revisions of secret material per entry) lived inside the thing written most often; nothing could be indexed.

## Decision

`vault-core/src/storage.rs` stores one row per entry and per project, a row for the category list, and a row for every other top-level key (`vault_rows`). `version_history` lives in `vault_history`, one row per entry, attached on load. The document API is unchanged: `load_vault` returns the same JSON and `save_vault` takes it, so the app, `unv-server` and `envv` call the same functions. `VAULT_SCHEMA_VERSION` is 2; a v1 build refuses the file with `VAULT_SCHEMA_TOO_NEW`.

**The version token is `"<seq>.<state hash>"`.** The state hash is the XOR of a hash of every row's `(kind, key, position, content hash)`, maintained incrementally, so a save costs O(changed rows) of hashing; `verify_vault_integrity` recomputes it from the rows. The sequence number indexes `vault_saves` and `vault_changes`, which record which rows each of the last 2000 saves changed.

**A stale writer is merged per row.** Given the version the writer read, the changes since then say what each row looked like when the writer read it (the `prev_rev` of the first later change). A row the writer did not touch keeps whatever the other writer did; a row both changed to the same content is not a conflict; a row both changed differently, or one changed and the other deleted, is a conflict, named in the error. A row the writer does not have, created after it read, is kept. A token the history no longer holds (older than 2000 saves, or in the old bare-hash form) is a whole-vault conflict, as it always was.

**A merged save is marked.** The version it returns ends in `+merged`: the writer's copy is behind what was stored, so a client that holds a document reloads it (the app's `persist()`, the remote store through `X-Vault-Merged`), and a one-shot client (the CLI) never looks. Returning the new bare token would let a stale copy overwrite the merge on its next save; returning the old base would make that save conflict with the writer's own previous one.

**Migration is one-way and backed up.** The first open of a v1 vault copies `vault.db` to `vault.db.v1.bak` (owner-only), converts the blob inside one transaction without writing audit rows (nothing about the data changed), and deletes the blob so no second copy of every secret is left. `envv doctor` notes the backup so it is removed deliberately.

The selective read (`GET /api/vault/entries`) loads the document without any entry's history. The local CLI now saves conditionally on the version it loaded, so a long `enrich --online` merges with, or is refused by, a concurrent edit instead of overwriting it silently.

## Consequences

Writing is O(changed rows) in database work. It is not O(changed rows) in CPU: a client still sends the whole document, which the server must serialise to find what changed. Measured at 5,000 entries with 3 history records each (release build): one edit saves in about 90 ms against about 165 ms for the v1 sequence (read blob, parse, index, serialise, hash, rewrite), and writes one row instead of 3.6 MB; a full load is slower than v1's single parse (about 88 ms against about 35 ms) because it parses 10,000 rows, and the load without history is about 22 ms. A delta API from the client would remove the rest and is a separate change.

Anything that adds a top-level key to the document needs no change: it rides in the `doc` row. A new per-entity table would need a kind in `storage.rs`.

## Evidence

`vault-core/src/storage.rs` (22 tests, including the merge matrix and the v1 conversion), `vault-core/src/lib.rs` (`save_vault_txn`), `unv-server/src/lib.rs` (`saved_response`), `src/ts/state.ts` (`takeMerged`, `reloadFromStore`), `tests/vault-merge.test.ts`
