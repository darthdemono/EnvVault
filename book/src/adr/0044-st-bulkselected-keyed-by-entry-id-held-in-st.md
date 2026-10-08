# ADR-0044: St.bulkSelected keyed by entry id, held in st

Status: accepted

## Context

Array positions retargeted bulk delete onto the wrong secrets; living in `st` lets `resetViewState()` clear it and `buildCard` re-apply the tick across a re-render

## Decision

`st.bulkSelected` keyed by entry id, held in `st`

## Evidence

`state.ts`, `tools.ts`
