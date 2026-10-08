# ADR-0135: A composite's zone classifier reads the template's text, never the rendered output

Status: accepted

## Context

Substituting real values first and then parsing the result means the parser's input already contains whatever ambiguity (an `@` or `/` in a secret part) the classification exists to resolve. The template's structure is fixed before any part is filled in

## Decision

A composite's zone classifier reads the **template's** text, never the rendered output

## Evidence

`vault-core/src/composite.rs`, `src/ts/composite.ts`
