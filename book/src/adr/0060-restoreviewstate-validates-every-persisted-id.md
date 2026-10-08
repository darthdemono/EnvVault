# ADR-0060: RestoreViewState() validates every persisted id

Status: accepted

## Context

A filter restored from `localStorage` can point at a project/tag the vault no longer has; unvalidated it matches nothing and the app opens to an empty grid under a filter the user never set

## Decision

`restoreViewState()` validates every persisted id

## Evidence

`state.ts`
