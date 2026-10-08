# ADR-0084: The Authenticator surface is a sidebar section, not a fifth activity-bar panel

Status: superseded by ADR-0076

## Context

It is a filter over the secrets already in that panel, not a new place to be. As a `sidebar-section` it inherits collapse, reorder, hide and the settings editor, and adds no second navigation idiom

## Decision

The Authenticator surface is a **sidebar section**, not a fifth activity-bar panel

## Evidence

`index.html`, `src/ts/render.ts`
