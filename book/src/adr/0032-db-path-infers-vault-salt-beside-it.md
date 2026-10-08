# ADR-0032: --db-path infers vault.salt beside it

Status: accepted

## Context

A vault paired with the wrong salt derives the wrong key and reports "wrong password" for a correct password

## Decision

`--db-path` infers `vault.salt` beside it

## Evidence

`envv-cli/src/access.rs`
