# ADR-0094: Six authenticator import formats are parsed in one place, vault-core

Status: accepted

## Context

Parsed twice is six chances for the app and the CLI to disagree about what a file meant, and the disagreement is a seed that imports with the wrong period and produces codes the issuer rejects. The app calls it over IPC, as `pools.ts` already does — no twin, no parity fixture

## Decision

Six authenticator import formats are parsed in **one** place, `vault-core`

## Evidence

`vault-core/src/totp_import.rs`
