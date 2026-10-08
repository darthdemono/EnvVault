# ADR-0130: Version_history matches extra_vars by name, never by index

Status: accepted

## Context

The array is rebuilt by the form on every save, so a position captured across an edit points at whatever took its place. Invariant 1, in the one place where getting it wrong writes the wrong secret into history — and a history that quietly attributes value A to variable B is worse than no history

## Decision

`version_history` matches `extra_vars` **by name**, never by index

## Evidence

`vault-core/src/lib.rs`
