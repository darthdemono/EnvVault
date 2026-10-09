# ADR-0113: An unresolved ${ref} is written into a .env raw, not quoted

Status: accepted

## Context

Quoting turns a recognisable broken placeholder into an escaped literal, and the caller is told about the unresolved reference either way. A visibly wrong line beats an invisibly wrong one

## Decision

An unresolved `${ref}` is written into a `.env` **raw**, not quoted

## Evidence

`unv-cli/src/exporters.rs`, `src/ts/render.ts`
