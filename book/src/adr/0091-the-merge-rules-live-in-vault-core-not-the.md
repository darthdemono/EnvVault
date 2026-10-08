# ADR-0091: The merge rules live in vault-core, not the CLI

Status: accepted

## Context

Whether a working second factor survives an import must not be able to differ between the app and the terminal, so `plan`/`write_fields`/`new_entry` are shared and the desktop Import button calls all three

## Decision

The **merge rules** live in `vault-core`, not the CLI

## Evidence

`vault-core/src/totp_import.rs`
