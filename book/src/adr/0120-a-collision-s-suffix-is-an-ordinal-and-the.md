# ADR-0120: A collision's suffix is an ordinal, and the first occurrence keeps its name

Status: accepted

## Context

The design's "pool members get `_1`, everything else gets the `key_id`" was written when `key_id` was not expected to be in the generated name; here it always is, so appending it cannot disambiguate anything. And renaming both halves would change a variable that was never ambiguous for whoever reads it first

## Decision

A collision's suffix is an **ordinal**, and the first occurrence keeps its name

## Evidence

`src/ts/state.ts`, `envv-cli/src/envfile.rs`
