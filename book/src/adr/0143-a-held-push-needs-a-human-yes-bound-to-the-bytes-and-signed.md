# ADR-0143: A held push needs a human's yes, bound to the exact bytes and signed by the hub

Status: accepted

## Context

Nodes (ADR-0140) make an automation able to change production: edit the vault and a node writes the file on a live host within a beat. That is the point, and it is why nobody sensible would switch `apply` on for a production target. Handoff-23 T5 asks for a human between the render and the apply, bound to the content so that approving "a change to nginx" cannot become approving different bytes (a time-of-check/time-of-use hole), with staging applying freely and production requiring a tap.

## Decision

**Policy is per node, set by the owner on the hub** (`envv node policy NODE --approval required|none`, the Tools, Nodes toggle). With `required`, every push to that node is held. A separate, host-side setting makes the refusal independent of the hub: `require_approval = true` on a `[[target]]` in the node's own config.

**A request is for exact bytes.** When a push is ready (the node's `apply` is on, the rendered hash differs from what it reports), the hub records the proposed file in the config history (cause `proposed:<node>`), finds the snapshot of the file the node has, and opens one request per `(node, target, sha256)` with both snapshot numbers. It never opens a second for the same bytes while one is pending, approved or rejected. If the vault changes before the node picks the push up, the rendered hash changes, the old request no longer matches, and a new one opens: the old yes is not for the new bytes. A consumed or expired request for the same bytes (a revert) does not cover a later push either.

**The human reads a diff.** The request holds snapshot numbers, not content. `envv node approve ID` prints the node, target and the proposed file's hash, then the diff against what the node has, secrets as fingerprints unless `--reveal` (Phase 35's diff and masked text), and asks; `--yes` is for someone who has looked. The pane's Review button shows the same diff and its Approve question names the hash. A request answered after seven days has lapsed. Rejection is final for those bytes: the same request is not asked again.

**The hub signs what was approved.** An approved push carries `approval = {token, sig}`: an Ed25519 signature over `envv-approval-v1` and a token naming the node, target, `sha256`, approval id, approver, time, expiry (the approval time plus one hour) and a fresh nonce. The hub's approval seed is created on first use in the vault's own encrypted `vault_meta`, so a copy of `nodes.json` cannot forge one and the key exists only while the vault is open. The hub withholds the content entirely until there is a usable approval: a pending request produces no `Push` action, only a `pending` note.

**The node checks it before it writes.** For a target with `require_approval`, the agent verifies the signature against the hub key it has pinned, that the token names this node, this target and the hash of these bytes, that it has not expired, and that its nonce has not been used; any failure is a failed apply with the reason, which reaches the hub's audit log. The nonce is spent by a write, not an attempt, so a failed validate leaves the approval usable for the retry. The node pins the hub's approval key the first time a beat shows it, over the already-pinned TLS channel, and refuses a different key later (trust on first use over a pinned channel; re-enroll to change it). A node that has not yet seen the key refuses approval-requiring pushes.

**Audit.** `node.policy`, `node.approval.request` (one per request, however many beats ask), `node.approve` and `node.reject` are chain rows; a node's applies are `node.apply` as before.

**Consumption.** When a node reports the approved hash, the approval is consumed; an approved request the node did not act on within the hour lapses.

## Not built (and why)

- **Approval signed on the human's own device.** The hub signs on the owner's authenticated request, so a compromised hub can mint approvals; what the scheme guarantees is that a hub bug, a sub-user write path or a replayed action cannot push to a node that requires approval, and that the owner's yes is for exact bytes. A key held by the app would close the compromised-hub case and needs a key-management design of its own.
- **A per-target hub policy.** The policy is per node (staging nodes `none`, production nodes `required`); a target-level setting is the node's own `require_approval`.
- **Notifying the owner.** A held push appears in `envv node approvals`, the Nodes pane and `envv node run --once`; a push notification is not part of this.

## Evidence

`vault-core/src/nodes.rs` (token sign/verify; request, decide, usable, consume, expire; policy; 7 tests), `envv-server/src/nodes.rs` (6 tests over the real router: held until a yes, a changed vault asks again, a rejection is final, owner-only decisions including a node's own signed headers, audit rows and a single request row per request, policy off and a consumed yes), `envv-server/tests/nodes_e2e.rs` (4 with the real agent: a held push waits and a changed vault waits again; a node that requires approval refuses no approval, another hub's key, other bytes, another target, another node, an expired token, and a replay; a changed hub key is refused; a node that has not seen the key refuses), `src/ts/nodes-pane.ts` (6 tests). Fault injection: 16 mutations (each token check removed, a request opened every time, a decided request decided again, pending treated as approved or the lifetime ignored, an approval not bound to the bytes, never consumed, the policy ignored on push, decisions open to any session, a token outliving its approval, the node ignoring `require_approval`, accepting a replay, accepting a changed hub key) each fail at least one test.
