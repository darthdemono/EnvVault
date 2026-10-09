# ADR-0074: There is one list of secret entry fields, out::SECRET_FIELDS, and it is public

Status: accepted

## Context

Two lists is one list and one leak: the copy goes stale exactly when a phase adds a field, which is what let a stored TOTP seed print in clear from `envv get --field totp_secret` while the whole-entry dump masked it. The test pins the property the printing path evaluates, not the membership

## Decision

There is **one** list of secret entry fields, `out::SECRET_FIELDS`, and it is public

## Evidence

`unv-cli/src/out.rs`
