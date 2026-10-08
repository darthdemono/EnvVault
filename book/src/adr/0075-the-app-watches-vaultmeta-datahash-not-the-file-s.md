# ADR-0075: The app watches vault_meta.data_hash, not the file's mtime

Status: accepted

## Context

It is written in the same transaction as the data, so it is by construction the hash of the bytes on disk, and it is already what the compare-and-swap compares. An mtime heuristic or a Rust-side file watcher would be a second definition of "changed" to keep in step with the first

## Decision

The app watches `vault_meta.data_hash`, not the file's mtime

## Evidence

`src/ts/vault-watch.ts`
