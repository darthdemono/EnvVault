# ADR-0073: An entry's TOTP parameter fields are read only by Params::from_fields

Status: accepted

## Context

They were read three ways in Rust alone, so one entry listed as a 99-digit credential, produced six digits, and handed the app an error instead of a code. Falling back to the `otpauth://` default rather than refusing is what keeps one mistyped number from making a whole entry unreadable. Twin: `totpParamsOf`, pinned by the fixture's `params` table

## Decision

An entry's TOTP parameter fields are read **only** by `Params::from_fields`

## Evidence

`vault-core/src/totp.rs`
