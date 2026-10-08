# ADR-0014: TOTP enrollment is two-phase: enroll mints, confirm enables

Status: accepted

## Context

There is no QR code (the CSP allows no external script, and relaxing it to draw a _secret_ is a poor trade), so the base32 is typed by hand — manual entry that did not take is routine, not an edge case. Enabling on enrollment locks those users out of their own account

## Decision

TOTP enrollment is two-phase: `enroll` mints, `confirm` enables

## Evidence

`vault-core/src/users.rs`
