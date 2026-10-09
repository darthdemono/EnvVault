# ADR-0137: The config compiler ships six hand-written checks that fire only on positive evidence

Status: accepted

## Context

Phase 18's validation matrix checks each generated file against its own tool (`nginx -t`, `wg-quick strip`), so every check sees one format. The mistakes that bite are between chunks and formats. A validator that cries wolf gets switched off and then protects nothing, so a false positive costs far more than a missing check.

## Decision

`vault-core/src/config_check.rs` holds six rules, pure over the project JSON, called by `envv check` and by the desktop app over IPC (`config_check_project`). No rule language. Each rule is silent unless the project shows it means to define the thing: the proxy_pass rule needs a `docker_service` chunk, the Ingress rule needs a `k8s_service` chunk, and a pg host is only compared against services that actually mention it. References that could be satisfied elsewhere (`name@provider`, `${bundle:…}`, a dotted hostname, an IP, `localhost`, a variable) are skipped, never guessed at. Findings carry chunk and field names and never field values.

The six designed checks are implemented as written. Two of them split into a certain case and a softer one, so there are eight rule ids:

- **WireGuard AllowedIPs overlap.** The same network on two peers is an `error` (the kernel silently gives it to the later peer). One peer's network strictly containing another's is a `warning`, because WireGuard routes by longest prefix and nesting is how a split route is written. A default route (`/0`) beside host routes, the standard full-tunnel pattern, is not reported.
- **Kubernetes.** A Deployment naming a Secret no `k8s_secret` chunk creates is an `error`. This needed model fields the Deployment did not have: `secretEnv` (Secret names, exported as `envFrom`) and `secretMounts` (`secret:/path` pairs, exported as read-only volume mounts and a `volumes` block). Both exporters (`exportK8s`, `export_k8s`) emit them and `parity/k8s.yaml` pins the bytes. An Ingress whose Service no `k8s_service` chunk defines is a separate `warning` that the model already supported.
- **Compose.** Every `${NAME}` in any service value (image tag, command, ports, an environment value) must be a key some `env_file` chunk sets or a vault entry; `${NAME:-x}` and the other operator forms and `$${NAME}` are the author's own fallback.
- **Postgres.** A service is a consumer of a `pg_connection` if it lists the database service in `depends_on`, spells its name in an environment value, or reads the connection through `${chunk:<name>/…}`.

## Consequences

Adding a seventh rule is a deliberate edit to `RULES` and a new unit test with its silent case. The Traefik rule is a warning because a middleware may be defined in another file of the same provider; the message says to write `name@file`.

## Evidence

`vault-core/src/config_check.rs`, `tests/fixtures/parity/k8s.yaml`, `unv-cli/src/check_cmd.rs`, `unv-cli/tests/check.rs`, `src/ts/config-check.ts`, `tests/config-check.test.ts`
