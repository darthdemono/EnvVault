# ADR-0141: Config history keeps a masked and a real copy of every rendered config, and prunes behind a checkpoint

Status: accepted

## Context

Config lives in git and its secrets live elsewhere, so the file that runs is versioned by nobody, and "what was deployed on the 3rd" has no answer. The vault holds both the structure and the values, so it can keep the answer, but two things make that dangerous: old secrets would live forever, and a history that can be pruned is a history whose integrity cannot be checked. The audit chain (Handoff-23, T4) names both problems; Phase 35 had to ship a retention policy and a checkpoint or not ship.

## Decision

**Every rendered config is snapshotted when a save changes it.** `vault-core/src/config_history.rs` stores one row per change per stream (project, exporter) in `vault.db` (so SQLCipher encrypts it with the rest). `envv_cli::history::snapshot_all` renders each project with its type's exporter (Compose is two streams, the YAML and the `.env` beside it) and `record` stores the result only when its hash differs from the stream's newest. Reverting to an earlier text is a new snapshot. Every writer calls the same hook: `Access::save` (local CLI), `put_vault` (server, in the background so a save does not wait on rendering), and the Tauri `save_vault`. A failure to snapshot is logged and never fails the save. Saves in quick succession coalesce: a snapshot renders the vault as it is when it runs.

**Two texts per snapshot.** `content` is the deployable file; `masked` is the same render with every resolved secret replaced by its fingerprint, which is what `envv project export` already prints. Every default view (list, show, diff, the Tools pane) reads `masked`, so a rotation reads as a changed fingerprint without either key being read. The real text needs `--reveal`, `--out` or the pane's confirmed Reveal. Masking the stored text afterwards was rejected: a rotated-away secret is no longer in the vault, so nothing would know to mask it in an old snapshot, and an old snapshot is exactly where it lives.

**One dispatcher, three surfaces.** `envv_cli::history::call(conn, op, args)` is the only implementation. The local CLI calls it directly, `envv-server` exposes it as owner-only `POST /api/history {op, args}`, and the app reaches it through the `history_call` command (local vault) or that route (remote vault). Rejected: a route and a Tauri command per operation, which is nine places to keep in step.

**The diff is Rust, once.** `vault-core/src/textdiff.rs`: common head and tail stripped, an LCS table over the middle, and above 4 million cells the middle is reported as one delete and one insert (correct, less minimal). A TypeScript diff was rejected: it would be a twin pair needing its own golden fixture, for a function whose output the UI only displays.

**Tamper evidence and retention.** Each stream is a hash chain over the previous chain value, project, exporter, the hashes of both texts and the timestamp. `prune` deletes, per stream, rows that are both beyond the newest `keep` and older than `days` (always a prefix, never the newest row), and writes a **checkpoint** holding the chain value at the boundary so what remains still verifies. The same transaction appends a `config.prune` row to the vault's audit chain naming that value, and `verify` requires every checkpoint to have a matching audit row: forging a checkpoint means forging the audit chain too. Defaults: history on, newest 50 per stream and everything from the last 90 days. `envv history policy --disable` turns it off.

**The file on a host can be traced to a snapshot.** `find_by_sha` answers "which snapshot rendered this hash", and the hub's node list adds `snapshot: {seq, at}` to a target whose reported hash is in the history, so drift reads "this host still runs what was rendered on 3 October" (Phase 34's nodes).

## Not built (and why)

- **Restore into chunks.** A rendered file cannot be turned back into chunks without the parsers, which are TypeScript. `envv history show --out` writes the old file; deploying it is the operator's act, or a node's pull and the normal import.
- **A diff against a node's live file.** The hub knows only its hash, not its content, by design (ADR-0140). It can say which snapshot matches, not show how the file differs.
- **History for sub-users.** Snapshots hold every project in the clear, so the whole feature is owner-only.

## Consequences

The vault database grows by the size of each changed rendered config twice (real and masked); a typical config is kilobytes, a snapshot over 2 MB is refused rather than truncated, and the default policy bounds the total. Pruning is the only way secrets leave the history, and it is irreversible; the CLI and the pane count first and ask.

## Evidence

`vault-core/src/config_history.rs` (18 tests: dedupe, per-stream chains, every kind of tampering, prune and checkpoint, forged checkpoint, restart from a checkpoint, policy), `vault-core/src/textdiff.rs` (7), `envv-cli/src/history.rs` (6), `envv-server/src/history.rs` (6 over the real router, including a sub-user refused), `envv-cli/tests/history.rs` (4, the real binary: a rotation diffs as a changed fingerprint, `--reveal`/`--out`, tampering exits 10), `src/ts/history-pane.ts` and `tests/history-pane.test.ts` (11). Fault injection: 13 mutations (real text in the masked column, no dedupe, a stream restarting without its checkpoint, prune deleting the kept rows, prune without its audit row, checkpoint not checked against the audit chain, chain not verified, content hash not verified, show ignoring reveal, diff always real, route not owner-only, the local save not snapshotting) each fail at least one test.
