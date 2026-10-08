# ADR-0095: Version_history snapshots every secret-carrying field, with api_key writing no

Status: accepted

## Context

A re-enrolled seed is as unrecoverable as a replaced key, and leaving it unversioned is the one option E8 calls unacceptable. Absent `field` has always meant `api_key`, and every vault written before this relies on it. The 50-cap stays per entry so a chatty seed cannot evict a key's history

## Decision

`version_history` snapshots every secret-carrying field, with `api_key` writing **no** discriminator

## Evidence

`vault-core/src/lib.rs`
