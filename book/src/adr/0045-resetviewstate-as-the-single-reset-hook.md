# ADR-0045: ResetViewState() as the single reset hook

Status: accepted

## Context

Import, backup restore, vault switch and lock had each drifted apart; a stale project selection made a successful import render an empty grid

## Decision

`resetViewState()` as the single reset hook

## Evidence

`state.ts`
