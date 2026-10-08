# ADR-0083: The TOTP ticker holds no references between ticks

Status: accepted

## Context

An element or an index captured across a render points at whatever took its place (invariant 1). Re-querying `[data-totp-for]` and re-looking-up the entry by id each second is what makes a deleted entry's slot go blank rather than paint its neighbour's code

## Decision

The TOTP ticker holds no references between ticks

## Evidence

`src/ts/totp.ts`
