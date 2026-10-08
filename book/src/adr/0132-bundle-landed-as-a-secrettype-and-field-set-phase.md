# ADR-0132: Bundle landed as a SecretType and field set (Phase 24.1 step 2) with no card, operations

Status: accepted

## Context

`Record<SecretType, TypeConfig>` would not typecheck with an un-exhaustive union the moment anything else touched it — the same call E4 made about `formToEntry`'s spread: land the shape now, the behaviour later

## Decision

`bundle` landed as a `SecretType` and field set (Phase 24.1 step 2) with no card, operations or scope resolution built on it yet

## Evidence

`src/ts/types.ts`, `src/ts/modals.ts`
