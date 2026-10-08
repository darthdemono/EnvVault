# ADR-0063: _ddCleanup module-level ref

Status: accepted

## Context

`showDropdown` creates new closure each call; need stable ref to remove previous listener on re-open

## Decision

`_ddCleanup` module-level ref

## Evidence

`modals.ts`
