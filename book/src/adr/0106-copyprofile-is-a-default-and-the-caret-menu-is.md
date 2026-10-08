# ADR-0106: CopyProfile is a default, and the caret menu is why

Status: accepted

## Context

A setting that cannot be overridden per copy becomes a wall the moment somebody needs the other answer once. The one-off choice is deliberately **not** persisted: a "give me everything" press must not silently change what the next fifty copies contain

## Decision

`copyProfile` is a default, and the caret menu is why

## Evidence

`src/ts/modals.ts`
