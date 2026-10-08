# ADR-0128: A public variable is not versioned

Status: accepted

## Context

It is a region or a client id by declaration. Filling a 50-record per-entry history with them evicts the values that cannot be recovered any other way

## Decision

A `public` variable is **not** versioned

## Evidence

`vault-core/src/lib.rs`
