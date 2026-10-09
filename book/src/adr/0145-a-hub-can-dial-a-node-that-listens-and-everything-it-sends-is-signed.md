# ADR-0145: A hub can dial a node that listens, and everything it sends is signed

Status: accepted

## Context

ADR-0140 made every node dial its hub: outbound only, NAT-safe, nothing listening on the managed host. That does not suit a node with a public address (a VPS) whose operator would rather open one port than let the host initiate sessions, and it leaves a locked hub unable to look at such a node at all. The design always allowed a second direction ("per node: `dial` or `listen`"); the wire types were written to be symmetric enough for it.

## Decision

**The direction of the connection changes; what a node does does not.** A node enrolled with `--listen ADDR --advertise https://host:port` runs a small TLS listener instead of a heartbeat loop. The hub makes two requests to it per round:

- `POST /node/v1/poll` (empty body). The node observes its targets and answers with the same `Beat` a dialling node would send.
- `POST /node/v1/act`, body a `BeatReply`. The hub computes it with the same `process()` it uses for a dialled beat. The node takes it through the same `accept_reply`, which includes every check from ADR-0140 and ADR-0143: its own config decides what is written, an approval is verified against the pinned approval key, and a held push carries nothing.

**Both ends are authenticated.** The hub pins the node's TLS certificate (a self-signed certificate the node generated, its SHA-256 sent in the token-authenticated enrollment request), TLS 1.3 only, no redirects. The node checks an Ed25519 signature on every request, under a hub transport key delivered in the enrollment reply, over `envv-hub-v1`, method, path, a millisecond timestamp and the body hash. The timestamp must be within 60 seconds and strictly newer than the last accepted, and the mark is written to disk before the request is acted on. Every failure is the same bare 401. The node signs its answer to a poll exactly as it signs a dialled beat, so the hub verifies it with the same `NodeStore::authenticate` (signature, revocation, skew, replay).

**The two directions have different signing domains** (`envv-node-v1` and `envv-hub-v1`), so a signature made for one cannot be replayed as the other; a test pins that.

**The hub transport key lives in `nodes.json`, not in the vault.** The approval key stays in the vault's `vault_meta` so a locked hub cannot push; the transport key is in a plain 0600 file so a locked hub can still poll (observation continues, as it does for dialling nodes). Cost, stated: a copy of `nodes.json` lets its holder speak as the hub to listening nodes, within what those nodes' own configs allow, and cannot mint an approval. The same is true today of the hub's `server.key` for dialling nodes.

**Scheduling.** A task started with the server polls every listening node every 30 seconds and at once whenever the vault is saved or a decision is made (the same wake signal held beats use). A node that does not answer is logged and retried; it is not marked failed anywhere, because `last_seen` and `last_polled` already say when it last spoke.

**A deliberately small HTTP reader on the node.** Two routes, 16 KiB of headers, 8 MiB of body, no chunked bodies, a 5 second read timeout and a 10 second total deadline per connection. A framework would add attack surface to a host that exists to be boring.

**A stalled stranger must not lock the hub out.** The first version served one connection at a time, so a client that connected and said nothing held the listener for the whole timeout. Each connection is now read on its own thread, and only a whole, signed request takes the lock on the agent. The cap on concurrent connections went through two values: 16 let twenty idle sockets starve the hub (an end-to-end test caught it once under load), so it is 128. An attacker who can hold 128 sockets open can still delay a poll; on a public address the port should be reachable from the hub's address only, as for SSH. Nothing a stranger sends is acted on.

## Consequences

A listening node opens one inbound port, reachable by anyone, that does nothing without a valid hub signature and a pinned TLS handshake. The hub holds an outbound client per poll. Revoking a node removes it from the poll list at once.

## Not built

- **Rotating a node's certificate or the hub transport key.** Re-enroll.
- **Concurrent polls.** One node at a time per hub; fine at tens of nodes.
- **Polling through a locked hub's pushes.** A locked hub polls and records, and sends nothing, exactly as for a dialling node.

## Evidence

`vault-core/src/nodes.rs` (`ListenInfo`, hub request signing, `NodeStore::{hub_node_key, listening, mark_polled}`, 4 tests), `vault-core/src/tls.rs` (`self_signed`, `server_config_tls13`, a pinned-handshake test), `envv-cli/src/node_listen.rs`, `envv-cli/src/node_agent.rs` (enroll with `--listen`), `envv-server/src/nodes.rs` (`poll_node`, `spawn_poller`), and `envv-server/tests/nodes_e2e.rs`: the hub dials a real listening agent and a save reaches it; a listener refuses replay, skew, another key, a node-domain signature and a wrong path, and a wrong pin never reaches the handler; the hub ignores a beat that is unsigned, signed by another key or for another id, with a control signed correctly. Fault injection on the node's replay mark, signature check and skew check.
