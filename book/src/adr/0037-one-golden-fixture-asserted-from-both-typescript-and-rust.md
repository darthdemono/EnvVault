# ADR-0037: One golden fixture asserted from both TypeScript and Rust

Status: accepted

## Context

A config format implemented twice drifts silently; reviewing the two for agreement does not work. The fixture found two live export bugs on its first run

## Decision

One golden fixture asserted from both TypeScript and Rust

## Evidence

`tests/fixtures/parity/`, `tests/cli-parity.test.ts`, `unv-cli/tests/parity.rs`
