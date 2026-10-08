# ADR-0013: TOTP is refused for the owner, in vault-core rather than at each caller

Status: accepted

## Context

The owner authenticates by deriving the SQLCipher key: no stored hash, no login form, nothing for a factor to gate. Enforcing it in the shared crate is what stops the app and the CLI disagreeing about who may have one

## Decision

TOTP is refused for the owner, in `vault-core` rather than at each caller

## Evidence

`vault-core/src/users.rs`
