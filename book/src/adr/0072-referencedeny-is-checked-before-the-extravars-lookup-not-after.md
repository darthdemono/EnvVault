# ADR-0072: REFERENCE_DENY is checked before the extra_vars lookup, not after

Status: accepted

## Context

`${X/id}` has to mean one thing everywhere. Letting an entry's own vars decide whether it resolves reintroduces the divergence the deny-list closes

## Decision

`REFERENCE_DENY` is checked **before** the `extra_vars` lookup, not after

## Evidence

`unv-cli/src/refs.rs`, `src/ts/chunk-ops.ts`
