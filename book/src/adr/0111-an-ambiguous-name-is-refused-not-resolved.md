# ADR-0111: An ambiguous ${NAME} is refused, not resolved

Status: accepted

## Context

The legacy `Provider_keyid` split and the name template occupy the same syntactic position, so a vault holding both kinds of match has two honest answers. Returning either writes a plausible-looking wrong value into a rendered config, which is the Phase 21 defect class; "unresolved" is what every exporter already reports

## Decision

An ambiguous `${NAME}` is **refused**, not resolved

## Evidence

`envv-cli/src/refs.rs`, `src/ts/chunk-ops.ts`
