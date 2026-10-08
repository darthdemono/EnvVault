# ADR-0040: Tests load the real index.html

Status: accepted

## Context

A mock fixture cannot catch element-id drift — the Phase 3 `#new-category-form` failure would pass against a mock

## Decision

Tests load the real `index.html`

## Evidence

`tests/helpers.ts`
