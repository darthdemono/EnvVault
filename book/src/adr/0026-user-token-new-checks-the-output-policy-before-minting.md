# ADR-0026: User token new checks the output policy before minting

Status: accepted

## Context

Checking afterwards left a live credential nobody could read — an orphan token that still authenticates

## Decision

`user token new` checks the output policy before minting

## Evidence

`envv-cli/src/users_cmd.rs`
