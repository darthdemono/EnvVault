# ADR-0096: ${…} cannot reach a TOTP seed

Status: accepted

## Context

A reference resolves into a config file, and no config file wants an authenticator seed; a code cannot be rendered either, being dead before the file deploys. The seed stays reachable by its literal field name (`--field totp_secret`, redacted), which is the parity that matters

## Decision

`${…}` cannot reach a TOTP seed

## Evidence

`unv-cli/src/refs.rs`
