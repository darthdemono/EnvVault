# ADR-0102: A stored TOTP seed is a field on any entry, not a SecretType

Status: accepted

## Context

A seed sits beside a credential rather than being one. A `'totp'` type would split a GitHub login and its second factor across two entries, making `${GitHub/…}` ambiguous, `envv entry rm GitHub` refuse, and the password's card unable to show the code. Bitwarden and 1Password model it the same way, for the same reason

## Decision

A stored TOTP seed is a **field on any entry**, not a `SecretType`

## Evidence

`src/ts/types.ts`
