# ADR-0112: FormToEntry(base?) spreads the entry being edited

Status: accepted

## Context

A field with no form input has to survive **by construction**, not because the save path remembered it by name — it remembered five, and every field a later phase adds would have been erased on the first edit. A cleared input still clears its field, because spread copies an `undefined` value

## Decision

`formToEntry(base?)` spreads the entry being edited

## Evidence

`src/ts/modals.ts`
