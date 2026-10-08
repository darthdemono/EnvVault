# ADR-0009: Caps Lock is derived from the typed character, never from getModifierState

Status: superseded by ADR-0004

## Context

The platform lies about it (see Pitfalls). A cased letter is unambiguous evidence and is the same answer everywhere. The cost — the hint cannot appear before the first letter — beats a warning that is confidently wrong all session

## Decision

Caps Lock is derived from the typed character, never from `getModifierState`

## Evidence

`src/ts/ui-qol.ts`
