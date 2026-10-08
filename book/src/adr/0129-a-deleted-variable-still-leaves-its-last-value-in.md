# ADR-0129: A deleted variable still leaves its last value in history

Status: accepted

## Context

Deleting a row makes its value exactly as unrecoverable as overwriting one, and the row's absence is not evidence the user meant to lose it

## Decision

A **deleted** variable still leaves its last value in history

## Evidence

`vault-core/src/lib.rs`
