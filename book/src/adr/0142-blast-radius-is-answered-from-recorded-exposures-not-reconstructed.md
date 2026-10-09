# ADR-0142: Blast radius is answered from recorded exposures, not reconstructed after the fact

Status: accepted

## Context

After a compromise the question is "which credentials were on that machine, and when?". It is never answerable, so the answer becomes "rotate everything", so nobody does. The hub knows what it rendered, the node knows what it wrote, and the audit chain knows what changed (Handoff-23, T6), but three things stood in the way: nothing recorded which secrets a rendered file contained, local `envv exec` and `--out` are deliberately outside the audit chain, and by the time of a compromise an entry may have been rotated, renamed or deleted.

## Decision

**Record, at the time, which secrets a file contained.** `envv_cli::exposure::Matcher` is the exact-value matcher of `envv shield` (Phase 26), built from the vault's secret values, but keeping _which entry and which field_ matched and the fingerprint of the matched value. Every config-history snapshot stores that list (`exposed`, covered by the stream's hash chain, so editing it to hide an entry is detected). It is exact, so it also catches a secret pasted literally into a field and one that arrived through a composite or a bundle, which reading the `${…}` references would miss. A value under 8 characters is still reported, marked `short`, because a missed exposure is the failure that matters and a coincidence costs one extra rotation.

**The hub's answer comes from its own records.** `node.apply` audit rows (Phase 34) say which file hash a node applied and when, using the audit row's timestamp, the hub's clock, not the time the node put in its own report (a node under investigation is not the source for when things happened). The hash is looked up in the history (`exposed_by_sha`, the union over every snapshot with that hash). A failed apply counts when the file reached the disk first (a failed validate or reload writes, then restores), and does not when it was refused before any write. To make "every file a host was ever sent is in the history" true even when no save passed through the server's hook, the hub records the exact render it is about to push (`snapshot_stream`, cause `push:<node>`) before sending it.

**"Still current" is a fingerprint comparison.** The recorded fingerprint is compared with the entry's present values (not its `version_history`). Equal means the value that was on the host is the live one: rotate it. A recorded value that is now only in history means it was already rotated away. An entry that no longer exists is reported and never put in the rotate command. Rejected: comparing `last_rotated_at` with the deployment time, which is wrong whenever an entry was edited without being marked rotated.

**One command, for the vault's copy only.** The report ends with `envv entry rotate '<name>' --generate; …` for exactly the still-current entries, sorted first, quoted only when the name can be quoted safely (a name containing a quote is printed as a comment for a human instead of a guess). It says plainly that this replaces the vault's copy and the old credential must also be revoked at its issuer, and prints the entry's console link when it has one.

**What the hub cannot know is reported, not dropped.** A deployment whose file hash has no snapshot (history off, or pruned) is listed as _unaccounted_; a pull target's file was never rendered by the hub and is not covered.

**Local materialisations go to a bounded log outside the chain.** `envv exec`, anything written with `--out` (`write_secret_file`, `emit`) and `--reveal` exports append to `materialisations.jsonl` beside `sessions.json`: 0600, newest 5,000 records (compacted at 6,000), each holding when, how, which vault and the entries, fields and fingerprints that were in what was written, never a value. A write containing no vault secret is not recorded. This is the shape `AGENTS.md` already prescribes for read auditing (separate, bounded, outside the hash chain) so growth cannot compromise tamper evidence. **Not covered:** `get --reveal`, the app's copy buttons, and anything that opened the vault directly; the log is evidence of what the CLI did on this machine, not of what a compromised user could have done.

## Consequences

Every snapshot now builds the matcher once (O(secrets)) when it records something. Concurrent snapshotters (a save's background task and a push) are serialised with `BEGIN IMMEDIATE`, because both extending the same chain tail forks it and the stream never verifies again.

## Evidence

`vault-core/src/blast.rs` (9 tests: live vs rotated, deleted, unaccounted, `since`, collapse, failed applies, unquotable names, renames, short), `vault-core/src/config_history.rs` (exposed union, tamper detection, concurrent writers), `envv-cli/src/exposure.rs` (5), `envv-cli/src/matlog.rs` (4), `envv-server/tests/nodes_e2e.rs` (2 end to end: a pushed file names Stripe and stops naming it after a rotation; a push is recorded before it is sent, and a missing history is reported as unaccounted), `envv-cli/tests/blast.rs` (3, the real binary), `src/ts/nodes-pane.ts` (`formatBlast`, tested).
