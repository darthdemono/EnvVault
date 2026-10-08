# ADR-0080: A stored OTP seed's kind is a field, totp_kind, not a second SecretType

Status: accepted

## Context

It is the same credential in the same place; only where the counter comes from differs. A type would split the model for a difference three lines of `match` cover, and every consumer — masking, history, import, export, `${ref}` — would need a second case

## Decision

A stored OTP seed's kind is a field, `totp_kind`, not a second `SecretType`

## Evidence

`vault-core/src/totp.rs`
