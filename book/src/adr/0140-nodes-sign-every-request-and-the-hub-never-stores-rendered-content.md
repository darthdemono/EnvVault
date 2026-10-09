# ADR-0140: Nodes sign every request, are configured only by their own file, and the hub never stores rendered content

Status: accepted

## Context

Phase 34 adds agents on other hosts (nodes) that observe config files and, where allowed, write what the vault renders (a hub is an `unv-server`). The design (Handoff-23) decided: apply is per target and default off; each target is push (vault to file) or pull (file to vault); the reload command is node-local; enrollment is a one-time token; transport is TLS 1.3 with the pins going both ways; state lives outside the vault; a locked hub idles push but not observe. Three of those needed a concrete mechanism, and two could not be built as written.

## Decision

**Identity is a signing key, not a client certificate.** A node generates an Ed25519 key. The hub stores the public half at enrollment and checks, on every request, a signature over `envv-node-v1`, method, path, a millisecond timestamp and the SHA-256 of the body (`vault_core::nodes::sign_request`). A timestamp must be within 60 s of the hub's clock **and** strictly greater than the last one accepted for that node; the high-water mark is persisted, so a restart does not reopen a replay window. Signature is checked first, so skew, replay and revocation are only reported to someone holding the key. The node pins the hub's certificate (the existing `FingerprintVerifier`) and offers TLS 1.3 only (`client_config_tls13`); the hub pins the node through the signature. This is "both ends pinned" without a custom `ClientCertVerifier` and a peer-certificate extractor behind `axum-server`, which would be the largest and least testable part of the phase. **Deviation, written down:** the hub's own listener still accepts TLS 1.2 (it serves the app and the CLI too); only the node client refuses to negotiate down. A plain-HTTP hub is refused by the agent unless it is the loopback, because a signature authenticates a request without hiding it and a push carries secrets.

**What a node does is decided by its own file.** `[[target]]` in the node config names the path, project, exporter, mode, `apply`, and the only two commands it will run (`validate`, `reload`). Unknown keys are an error; a pull target may not carry `apply`, `validate` or `reload`. A `Push` the hub sends for a target the node does not declare, or declares with `apply = false`, is refused by the node and reported as a failed result. The hub additionally restricts each node to the projects named when the enrollment token was minted: a node cannot widen that by declaring a target.

**Apply is transactional and hash-bound.** `nodes_apply::apply` recomputes the SHA-256 of the received bytes against the hash the hub announced before touching anything; copies the previous file aside (0600, last 3 kept); writes a temp file in the same directory, `fsync`, renames; runs `validate` against the file in place; on failure restores the previous file (or removes a file that did not exist) and does not reload; runs `reload`; on failure restores and does not retry. Output of the commands is cut to three lines and any line that is also a line of the file is elided, because a validator that echoes the offending line would otherwise carry a secret to the hub and into its audit log. The announced hash is what Phase 37's approval token will bind to.

**The hub renders on demand and stores no content.** `nodes.json` (0600, beside the vault) holds enrollment-token hashes, node records (public key, fingerprint, projects, last host info) and per-target status words with hashes. It never holds file content: a rendered `wg0.conf` contains a private key and the file is not encrypted. A pull target's file passes through hub memory for at most 120 s, only when the owner asked, and is handed over once. The hub renders with the CLI's exporters (`chunks::render_project`, so `unv-server` now depends on the `unv-cli` library) and runs `config_check` first: an error finding refuses the push (`refused`, with the finding) because a node is about to write that file to a live host.

**State words are decided in one place.** `derive_status` yields `in_sync`, `drift`, `pending`, `missing`, `unknown`, `refused` for push targets and `unreviewed`, `in_sync`, `changed`, `missing` for pull targets (a human accepts a hash into the vault with `envv node accept`).

**Heartbeats write nothing to the audit chain.** Enrollment tokens, enrollments, revocations, pulls and every reported apply do (`node.token`, `node.enroll`, `node.revoke`, `node.pull`, `node.accept`, `node.apply`, the last attributed to `node:<name>`). Apply results ride the next beat and are cleared by the node only when the hub says it recorded them (`results_ack`): a locked hub cannot append to the chain, and clearing on a reply that did not keep them would lose the only record that an apply happened.

**Opt-in.** `--nodes` on the server; without it every `/api/nodes/*` route answers 404 and `nodes.json` is not created.

## Not built (and why)

- **`listen` dialing** (hub dials a node with a public address). The wire protocol is symmetric enough to add it, but it needs a hub-side scheduler and a hub signing key the node pins; it is Phase 34.1.
- **`pull` into the vault as chunks.** The parsers that turn a `wg0.conf` into chunks are TypeScript (`chunks/parsers.ts`). A pull delivers the file to the owner (`envv node pull --out`, or the pane's save), and the existing import flows ingest it; `accept` records that it was.
- **A shipped systemd unit** is in `packaging/envv-node.service`; a container node is observe-only by design (reloading a host's nginx from inside one needs host PID or dbus, a worse hole than the one node-local reload closes).

## Consequences

The CLI binary is also the agent, so a node host carries the whole `envv` binary; the agent half uses none of its vault code. Beats cost one registry write each (a few hundred bytes per node), which is why they are not routed through `save_vault`.

## Evidence

`vault-core/src/nodes.rs` (signing, registry, config, status; 12 tests), `vault-core/src/nodes_apply.rs` (apply; 11 tests), `unv-server/src/nodes.rs` (routes; 18 tests over the real router), `unv-server/tests/nodes_e2e.rs` (the real agent against a real socket; 5 tests), `unv-cli/src/node_agent.rs`, `unv-cli/src/node_cmd.rs`, `src/ts/nodes-pane.ts`, `tests/nodes-pane.test.ts`. Fault injection: 13 mutations (no signature check, no replay check, no skew check, no revocation check, reusable token, no project scope in either place, push ignoring `apply`, gate off, unsolicited upload accepted, ack while locked, no hash check, agent clearing unacknowledged results) each fail at least one test.
