# ADR-0059: ClearAllFilters() separate from resetViewState()

Status: accepted

## Context

"Show me everything" must not also drop expanded cards and bulk ticks; `resetViewState` is for when the _data_ is replaced

## Decision

`clearAllFilters()` separate from `resetViewState()`

## Evidence

`state.ts`
