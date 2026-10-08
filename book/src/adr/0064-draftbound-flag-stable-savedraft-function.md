# ADR-0064: _draftBound flag + stable _saveDraft function

Status: accepted

## Context

`openAdd()` called on every modal open; listeners must be bound once to permanent DOM nodes

## Decision

`_draftBound` flag + stable `_saveDraft` function

## Evidence

`modals.ts`
