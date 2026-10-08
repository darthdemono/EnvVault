# ADR-0092: An import never replaces an existing seed with a different one without --force

Status: accepted

## Context

An import is exactly when a stale export gets pointed at a vault that has since been re-enrolled. Taking the incoming value silently destroys a working second factor at the moment the user believes they are backing one up. Same-seed is a no-op, which is what makes a re-run idempotent

## Decision

An import **never** replaces an existing seed with a different one without `--force`

## Evidence

`vault-core/src/totp_import.rs` (`plan`)
