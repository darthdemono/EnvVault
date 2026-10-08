# ADR-0118: Envv file write has no stdout form, and never will

Status: accepted

## Context

The point of E17 is that the consumer wants a _path_: printing the contents is the mistake, not a redaction question. Materialising by construction rather than guarded by `--reveal`

## Decision

`envv file write` has no stdout form, and never will

## Evidence

`envv-cli/src/entries.rs`
