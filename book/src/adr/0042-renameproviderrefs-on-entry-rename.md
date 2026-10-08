# ADR-0042: RenameProviderRefs() on entry rename

Status: accepted

## Context

Chunk fields address entries by provider name; the security audit could detect the resulting stale refs but nothing prevented them

## Decision

`renameProviderRefs()` on entry rename

## Evidence

`chunk-ops.ts`, `modals.ts`
