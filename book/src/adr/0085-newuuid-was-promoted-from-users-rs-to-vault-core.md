# ADR-0085: New_uuid() was promoted from users.rs to vault-core's root

Status: accepted

## Context

The TOTP importer needed one and `src-tauri` has no `uuid` crate. A second generator is a second thing to get the version and variant bits wrong in, and an id-less entry falls back to `entry_ck`'s legacy tuple

## Decision

`new_uuid()` was promoted from `users.rs` to `vault-core`'s root

## Evidence

`vault-core/src/lib.rs`
