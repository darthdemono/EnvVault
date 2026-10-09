# ADR-0127: An empty primary is omitted from a .env, not written as NAME=

Status: accepted

## Context

`NAME=` means "set to the empty string" in a file about to be loaded, which is a different claim from saying nothing — and it is exactly the distinction `out.rs` keeps by fingerprinting an empty value as `empty` rather than as a hash

## Decision

An empty primary is **omitted** from a `.env`, not written as `NAME=`

## Evidence

`src/ts/state.ts`, `unv-cli/src/profile.rs`
