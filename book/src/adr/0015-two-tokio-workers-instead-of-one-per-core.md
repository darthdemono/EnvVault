# ADR-0015: Two tokio workers instead of one per core

Status: accepted

## Context

The work is IO-bound; the CPU-heavy step (Argon2id, 64 MB) is rare and self-limiting. Threads cost stacks and glibc arenas, which is what shows up as container RSS

## Decision

Two tokio workers instead of one per core

## Evidence

`unv-server/src/main.rs`
