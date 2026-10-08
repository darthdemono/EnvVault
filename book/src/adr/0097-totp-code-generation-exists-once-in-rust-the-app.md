# ADR-0097: TOTP code generation exists once, in Rust; the app asks over IPC

Status: accepted

## Context

A second HMAC is a second thing to get wrong, and getting it wrong yields six digits that look right and are rejected with no explanation. Parsing is the twin that had to exist twice — the form splits a pasted URI as it is typed — so it is pinned by `parity/totp-seeds.json` from both sides

## Decision

TOTP code generation exists **once**, in Rust; the app asks over IPC

## Evidence

`vault-core/src/totp.rs`, `src-tauri/src/lib.rs`
