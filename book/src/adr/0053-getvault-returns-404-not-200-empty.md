# ADR-0053: Get_vault() returns 404 (not 200+empty)

Status: accepted

## Context

Allows client to distinguish "vault not initialized" from "empty vault" — prevents silent data wipe on reconnect

## Decision

`get_vault()` returns 404 (not 200+empty)

## Evidence

`unv-server/main.rs`
