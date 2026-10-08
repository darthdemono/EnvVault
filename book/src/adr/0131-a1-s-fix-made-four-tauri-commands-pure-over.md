# ADR-0131: A1's fix made four Tauri commands pure over their arguments rather than gating on

Status: accepted

## Context

The gate was checking whether the _local_ vault was unlocked, which is orthogonal to whether the renderer holds a decrypted vault at all (local or remote) — `st.vaultOpen` is the caller-side gate that actually answers the right question

## Decision

A1's fix made four Tauri commands pure over their arguments rather than gating on `VaultState`

## Evidence

`src-tauri/src/lib.rs`, `src/ts/totp.ts`
