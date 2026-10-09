# ADR-0144: Stack integrations are data descriptors, interpreted once in Rust and once in TypeScript

Status: accepted

## Context

Phase 38 asks for Prometheus, Grafana, Homarr/Homepage, Nextcloud and VS Code integrations "and the adapter shape they share". Every existing project type is hand-written in four places (Rust exporter, TypeScript exporter, starter chunks, config-check rules), which is why only four types are stable. Adding three more that way is twelve more code sites and twelve chances for the two halves to drift.

## Decision

**An integration is a JSON descriptor**, `vault-core/data/stack-adapters.json`, read by Rust (`vault-core/src/stack.rs`) and by TypeScript (`src/ts/stack.ts`). A descriptor lists the chunk types (fields, secret flags, defaults), the output document as a small node grammar (literal, field, map, list, each, singleton, group, entry, when), and the semantic rules (unique, required, exclusive, together, choices, needs_one_of). Two small interpreters render the document and run the rules. One file is read by both halves, so the twin pair needs a golden fixture per adapter (`tests/fixtures/parity/stack-*.yml|yaml`) rather than a hand-kept pair of exporters.

**YAML scalars are written bare only if** they match `^[A-Za-z_][A-Za-z0-9_.-]*$` and are not a YAML reserved word (`on`, `no`, `null`, ...); everything else is JSON-quoted. This is the rule that decides whether a hostile value can change the document structure.

**Secrets go through the resolver** with the descriptor's per-field secret flag, so a redacting resolver masks exactly the fields the descriptor says are secret and nothing is masked by guess.

**Rules run from `config_check::check_project`**, so `envv check`, the app panel and the node push gate (ADR-0140) all apply them with no extra wiring, plus a generic rule that flags a `${ref}` naming nothing in the vault.

**Nodes accept an adapter id as an exporter**, so a Prometheus file can be pushed, held for approval (ADR-0143) and recorded in history like any other.

**The three new project types are experimental** (behind `experimentalProjectTypes`) until CI validates the output against the real software. Outputs were validated locally with Docker: `promtool check config` accepts the Prometheus golden and rejects a basic_auth plus authorization control; Grafana provisioned both datasources with its secure fields set; Homepage loaded groups, services and widgets, and an invalid file gave an error and an empty list. `.github/workflows/exporters.yml` repeats this with images pinned by digest.

**A finding from that check:** Grafana does not reject two datasources with the same name, it provisions only the last one and the first vanishes without a warning. The `unique` rule on `name` states that.

**VS Code**: `vscode-extension/` completes and hovers `${Provider/FIELD}` references and runs `envv scan --exposed`. Its pure logic (`src/refs.ts`) is tested in the main suite; the rest is thin glue over the CLI and has not been run in a real editor.

## Not built

- **Nextcloud importer and a Grafana API probe.** Both need a live service and a format that has not been verified against one; deferred as 38.1.
- **Marking the types stable.** Not until the CI jobs have run green.

## Evidence

`vault-core/src/stack.rs` (15 tests), `envv-cli/tests/stack_parity.rs` (8) and `stack_cli.rs` (3), `tests/stack.test.ts` (17), `tests/stack-ui.test.ts`, `tests/vscode-refs.test.ts` (12), two node push tests in `envv-server/src/nodes.rs`. Fault injection: 16 mutations (quoting, reserved words, group default, disabled chunks, `when`, secret flag, exclusive and together rules, duplicate detection, rules not run by check, CLI render ignoring adapters, nodes refusing adapter exporters, and the TypeScript counterparts) each fail at least one test.
