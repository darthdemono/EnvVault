# ADR-0147: An approval can be signed on the owner's device, and then the hub cannot make one

Status: accepted

## Context

ADR-0143 put a human between a render and a write, bound the yes to the exact bytes, and had the hub sign it. That holds against bugs, replays and a sub-user write path. It does not hold against a hub someone else controls: the hub holds the approval key (in the vault's encrypted `vault_meta`), so whoever runs it can mint approvals for any push. The decision recorded the gap ("approval signed on the owner's own device: not built").

## Decision

**A third policy, `device`, and a key that never leaves the owner's machine.** `approver.key` is a 32-byte Ed25519 seed made on first use under the data directory (0600), shared by `envv` and the desktop app. Its public key is registered with the hub (`envv node approver register`, or the pane's "Use this device to approve") and written into each node's own config as `approver = "<hex>"`.

**The device signs; the hub only checks and forwards.** For a node set to `device`, the owner's client takes the held request (node, target, bytes, request id) from the hub, builds the token itself (lifetime = the hub's own, fresh nonce, `device:<fingerprint>` as approver), signs it and posts `{signed}`. The hub accepts it only if it verifies under a registered device, names exactly this request, and does not outlive the hub's own limit (`decide_signed`). It stores the signed token on the request and sends exactly that. The hub's own click on a `device` node is refused (409), and `process` never signs for a `device` node whatever the record holds, so switching a node to `device` after a hub-made yes voids that yes.

**The node trusts only its own config.** With `approver` in its config, a node checks an approval against that key alone. The hub's key, pinned or not, is not consulted, so a hub that signs its own approvals (policy `required`) produces pushes the node refuses and reports.

**The desktop signs through two commands, not a seed.** `approver_public` returns the public key and fingerprint; `approver_sign` takes the request's ids and builds and signs the token in Rust, so a compromised page cannot choose a lifetime, a nonce or an approver, and the seed never crosses the IPC boundary.

**Removing the last device returns `device` nodes to `required`**, rather than leaving a node that nothing can approve or one that quietly becomes approvable by the hub alone.

## Consequences

A node that names an `approver` is only as good as the secrecy of that device's `approver.key`. Losing the device means re-registering another and editing each node's config, deliberately: the node config is the only authority a node has. Approving needs the owner's machine, not just a session on the hub.

## Not built

- **A hardware key or passkey as the approver.** The seed is a file; a hardware-backed signer is a different `approver_sign`.
- **Several approvers needed for one push** (two-person rule). The registry holds several devices; any one suffices.

## Evidence

`vault-core/src/nodes.rs` (`Approver`, `add_approver`, `remove_approver`, `decide_signed`, `approver_seed`, `sign_device_approval`, `NodeConfig.approver`; 4 tests), `envv-server/src/nodes.rs` (decision route, approver routes, `process`), `envv-cli/src/node_agent.rs` (`check_approval`), `envv-cli/src/node_cmd.rs`, `src-tauri/src/lib.rs` (`approver_public`, `approver_sign`), `src/ts/nodes-pane.ts`. End to end with a real agent (`envv-server/tests/nodes_e2e.rs`): a `device` node holds a push, refuses the hub's click, refuses a signature from an unregistered key, accepts the registered device's and writes; a node naming an approver ignores an approval the hub made itself; switching to `device` voids an earlier hub-made yes (the guard in `process` was removed to see it fail). Writing the first e2e test also found that a `device` node was not held at all, because two places compared the policy to `"required"` only.
