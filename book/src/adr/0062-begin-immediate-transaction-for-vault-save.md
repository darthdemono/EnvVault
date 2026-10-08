# ADR-0062: BEGIN IMMEDIATE transaction for vault save

Status: accepted

## Context

Prevents crash between data+hash writes from leaving mismatched integrity state

## Decision

`BEGIN IMMEDIATE` transaction for vault save

## Evidence

`vault-core/src/lib.rs`
