# ADR-0146: The app saves deltas, and a project's chunks are rows of their own

Status: accepted

## Context

Phase 30 made saves cost O(changed rows) on the server, but the client still sent the whole document for one edit, the server still built one project row per project (so two people editing different chunks of one config conflicted), the change log kept only the newest 2,000 saves (a script saving thousands of times a day turned an hour-old token into a whole-vault conflict), and a full load parsed every row on one thread.

## Decision

**Delta saves.** `PATCH /api/vault` and the Tauri command `save_vault_rows` take `{put, delete, projects_put, projects_delete, categories}`. `vault_core::apply_row_patch` applies it to the stored document by `id`; the result goes through the same `save_vault`, so the compare-and-swap, the per-row merge, the audit rows, the history snapshots and `X-Vault-Merged` are identical to a whole-document save. Owner only: a sub-user's write is filtered against the document it was served, which a delta cannot reconstruct. The server still loads the whole document to apply the delta; what shrinks is what crosses the wire and what the client must build.

**The client diffs, it does not track.** Everything in the renderer mutates `st.vault` in place, so there is no dirty list to read. `persist()` remembers the JSON of each entry and project as of the last save that reached the store and sends the difference. The snapshot is trusted only while the document and its arrays are the very objects it was taken from; anything that replaced one (a reload, an import, a filter that reassigned `api_keys`) or any change of order falls back to the whole-document save. A save that did not reach the store leaves the old snapshot, so the same changes go out again. A store that refuses deltas (403/404/405) is saved whole.

**Chunk rows, schema v3.** A project's chunks are rows of kind `chunk`, keyed by the project row's key and the chunk's id. The project row keeps an empty `chunks` array to say they live elsewhere. Two writers editing different chunks of one project merge; the same chunk is a conflict naming it. A chunk whose project was deleted by the other writer is dropped rather than left as an orphan row. A v2 vault loads unchanged (a project row with inline chunks is understood) and is rewritten by its first save. The schema version is raised to 3 so a v2 build refuses the file: it would read a project with no chunks and delete the chunk rows.

**Retention by age.** The change log keeps the newest 2,000 saves and anything newer than 30 days, bounded by a hard ceiling of 200,000, so a busy script cannot burn the window in hours or grow it without limit. `envv doctor` reports how far back a stale writer can still be merged.

**Load speed.** Row and history JSON is parsed on worker threads once there are enough rows to pay for them. At 5,000 entries with history a full load went from 73 ms to 36 ms (release build), below the old single-parse figure. `load_entries_where`, which nothing called, is deleted; `entry_history` and `GET /api/vault/entries/{id}/history` read one entry's history alone.

**Over the pinned HTTPS proxy** `remote_request` now returns the `ETag` and `X-Vault-Merged` it used to drop, so a remote store reached that way writes with an `If-Match` like any other.

## Consequences

The first save after upgrading rewrites every project row once. A stale writer whose token predates that save sees a conflict on any project it touched. Lazy loading of history in the app was not done: the rotation and health code read `version_history` from the loaded entry, and a client that loaded entries without it would have to be taught that "absent" means "unchanged" in the save path first.

## Evidence

`vault-core/src/storage.rs` (chunk split/join, five chunk tests, retention test, `entry_history`, `par_parse`), `vault-core/src/lib.rs` (`apply_row_patch`), `envv-server/src/lib.rs` (`patch_vault`, `entry_history_handler`), `src-tauri/src/lib.rs` (`save_vault_rows`, headers on `remote_request`), `src/ts/state.ts` (`currentPatch`, `saveWholeOrDelta`), `tests/delta-save.test.ts`, `tests/remote-save-rows.test.ts`. Fault injection: delete not applied, orphan filter, chunk split disabled, the age condition of the prune, the order check, the array-identity check and the failed-save snapshot rule each fail a test.
