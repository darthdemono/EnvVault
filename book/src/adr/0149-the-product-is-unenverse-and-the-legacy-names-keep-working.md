# ADR-0149: The product is UnENVerse, and every name that holds data or signatures keeps its old spelling

Status: accepted

## Context

The product is renamed UnENVerse (a pun on "universe" and "un-env"): the CLI is `unv`, the server `unv-server`. The old `envv` binary name also collided with an unrelated SaaS product. A rename that touches data directories, signature domains or stored settings would orphan existing vaults and invalidate enrolled nodes.

## Decision

**Renamed:** the product name, the two binaries, the Docker service, release artifact names, the window title and `productName`, user-facing text, and the environment variables (`UNV_*`).

**Not renamed, on purpose:**

- the Tauri identifier and data directory `io.envvault`, `$XDG_STATE_HOME/envv/`, the node default config directory, `.envv.json`: existing data stays where it is;
- the signing and hash domain strings (`envv-node-v1`, `envv-hub-v1`, `envv-approval-v1`, `envv-history-v2`): changing them would make every enrolled node, approval token and history chain fail verification;
- `localStorage` keys `envvault-*` and the CXF extension keys `envvault_type` / `envvault_bundle`;
- Cargo package and crate names and directory names (`envv-cli`, `envv-server`, `vault-core`, `src-tauri` package `envvault`).

**Environment compatibility:** `vault_core::compat::adopt_legacy_env()` copies every set `ENVV_*` variable to `UNV_*` when the new name is unset. The three binaries call it first in `main`. The new name wins when both are set.

## Consequences

Old scripts and compose files keep working until the maintainer chooses to drop the shim. The tests that clear the environment clear both prefixes, because the shim would otherwise import a developer's shell variables into a test.
