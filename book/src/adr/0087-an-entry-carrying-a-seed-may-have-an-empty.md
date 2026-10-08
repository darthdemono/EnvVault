# ADR-0087: An entry carrying a seed may have an empty primary value

Status: accepted

## Context

That is what an import produces — the password may never be stored here at all. Demanding one would make every imported entry unsaveable the first time somebody opened it to fix its name. A carve-out for seeds, not a general relaxation

## Decision

An entry carrying a seed may have an **empty primary value**

## Evidence

`src/ts/modals.ts`
