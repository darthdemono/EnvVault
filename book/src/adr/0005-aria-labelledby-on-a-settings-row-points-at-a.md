# ADR-0005: Aria-labelledby on a settings row points at a span around the title, not the whole label

Status: accepted

## Context

The block contains the hint paragraph, so pointing at it announces sixty words as the checkbox's _name_

## Decision

`aria-labelledby` on a settings row points at a span around the title, not the whole label block

## Evidence

`index.html`, `src/css/settings.css`
