# ADR-0012: TOTP gates the password path only; token auth skips it

Status: accepted

## Context

There is no human at a CI runner to read a phone. This exact regression already shipped once in Phase 5.1 and is in the bug history

## Decision

TOTP gates the password path only; token auth skips it

## Evidence

`unv-server/src/lib.rs`
