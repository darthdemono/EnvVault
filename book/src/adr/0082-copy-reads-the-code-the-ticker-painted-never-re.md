# ADR-0082: Copy reads the code the ticker painted, never re-derives it

Status: accepted

## Context

Re-deriving hands the user the _next_ code when the click crosses a step boundary — invisible, and guaranteed to be blamed on the website

## Decision

Copy reads the code the ticker painted, never re-derives it

## Evidence

`src/ts/vault.ts`
