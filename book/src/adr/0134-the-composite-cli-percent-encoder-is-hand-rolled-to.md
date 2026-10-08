# ADR-0134: The composite/CLI percent-encoder is hand-rolled to exactly RFC 3986's unreserved set,

Status: accepted

## Context

JS's built-in additionally leaves `! ~ * ' ( )` unescaped. Using it on one side while Rust used a strict encoder would make the twin pair disagree on precisely the inputs a parity fixture would think to test

## Decision

The composite/CLI percent-encoder is hand-rolled to exactly RFC 3986's unreserved set, not `encodeURIComponent`

## Evidence

`vault-core/src/composite.rs`, `src/ts/composite.ts`
