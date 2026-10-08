# ADR-0101: A pasted otpauth:// URI is split into seed + three fields, never stored whole

Status: accepted

## Context

The URI is a container holding the secret plus three numbers. Storing it whole means a second field that also holds the secret — needing the same masking in `SECRET_FIELDS`, the card, `version_history` and every export — and two copies of one value drift the first time either is edited. Unlike `custom_icon`'s slug-or-data-URI, these are not one value in two spellings

## Decision

A pasted `otpauth://` URI is **split** into seed + three fields, never stored whole

## Evidence

`vault-core/src/totp.rs`, `src/ts/totp.ts`
