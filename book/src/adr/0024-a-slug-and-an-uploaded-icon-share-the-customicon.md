# ADR-0024: A slug and an uploaded icon share the custom_icon field

Status: accepted

## Context

Two fields would eventually disagree, and every consumer would have to learn which one wins

## Decision

A slug and an uploaded icon share the `custom_icon` field

## Evidence

`src/ts/icons.ts`, `unv-cli/src/entries.rs`
