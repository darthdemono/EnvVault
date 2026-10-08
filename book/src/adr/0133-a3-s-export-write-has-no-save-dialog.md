# ADR-0133: A3's export write has no save dialog

Status: accepted

## Context

`tauri-plugin-dialog` is a real dependency and capability-file addition for a defect fix; the downloads directory plus filename disambiguation (never overwrite, append `(2)`) gives correct behaviour without it. Revisit if a "Save As…" UX is explicitly requested

## Decision

A3's export write has no save dialog

## Evidence

`src-tauri/src/lib.rs`, `src/ts/utils.ts`
