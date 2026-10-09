# ADR-0148: A Grafana token is probed only where it is safe to send it, and a PHP config is read, not run

Status: accepted

## Context

Phase 38 deferred two integrations because both needed a live service: a Nextcloud importer and a Grafana API probe (38.1). Both were checked against the real software this time (Grafana 11.2 and a Nextcloud 29 container's installer).

## Decision

**`enrich --online` can ask a self-hosted Grafana who a service-account token is** (`glsa_`): `GET /api/user` for the login, `GET /api/org` for the organisation. Every other probe sends the token to the issuer's own public host; this one sends it to the entry's `api_url`, which in an imported or shared vault is text an attacker can choose. So the URL must be a plain origin with no userinfo, query or fragment; `https` is allowed anywhere, and plain `http` only to a name that cannot be reached from the public internet (loopback, private and link-local addresses, single-label names, `.local`, `.lan`, `.home.arpa`, `.internal`). The consent screen names the host (`issuer_for` returns `Grafana at host:port`), the client does public-CA validation and follows no redirect, and a cookie entry is never probed.

**Checked against the real server, the plan changed.** `/api/user/orgs`, the obvious source of a role, answers a service-account token with "Endpoint only available for users", and `/api/serviceaccounts/{id}` needs a permission an ordinary token lacks. The role is therefore not available and is not guessed; the organisation name from `/api/org` is. The exporters workflow gained a job that mints a token on a pinned Grafana image and runs the probe, with a control token the server refuses.

**A Nextcloud `config.php` is read, never executed.** `vault_core::php_config` parses the `$CONFIG = array(...)` literal (or the `[...]` form): strings with PHP's two escape rules, numbers, `true`/`false`/`null`, nested arrays, the three comment styles. A value that needs PHP to evaluate (`getenv()`, a constant, a concatenation) becomes `null` and a warning naming the line; nesting depth and node count are bounded. A first draft recomputed line numbers per value and took 104 seconds on a 150,000-item file; line numbers are now computed only when a warning is written.

**What it imports.** `passwordsalt` and `secret`, the database password (with user and host in the note), the SMTP password, the Redis password, the licence key and an object store's key and secret, one entry each, named with the instance id so two instances do not overwrite each other and a re-import changes nothing. The preview shows fingerprints. The file is the whole of what is read: the Docker image's `*.config.php` fragments are PHP scripts, not arrays, and importing one reports that rather than guessing.

## Consequences

The Grafana probe is the first that can send a secret to a host the user typed. The rules above are the control, and each is pinned by a test, including that a plain-`http` public address and a URL with userinfo are refused.

## Not built

- **A Nextcloud rotation adapter** (app passwords revoked per device). The importer reads a config file; rotation needs the admin API.
- **Grafana token expiry.** `GET /api/serviceaccounts/{id}/tokens` carries it but needs the service account id and a permission an ordinary token lacks.

## Evidence

`envv-cli/src/enrich.rs` (`grafana_base`, `probe_grafana`, `issuer_for`; 3 tests including a fake Grafana that records the `Authorization` header), run by hand against Grafana 11.2 (accepted and rejected tokens), `vault-core/src/php_config.rs` (5 tests), `envv-cli/src/import_vaults.rs` (`source_value`, `read_nextcloud`), `envv-cli/tests/import_vaults.rs` (a real SQLite installer's `config.php` and a synthetic full one, idempotence, no value in the preview), `.github/workflows/exporters.yml` (`grafana-probe`).
