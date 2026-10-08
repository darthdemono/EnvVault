# ADR-0089: Google's migration protobuf is decoded by hand

Status: accepted

## Context

One message with seven scalar fields, against `prost` plus a build-time generator. Same trade as base32 — the sixty lines are what a reader has to check. Every length in the payload is attacker-controlled, so the varint shift is capped and each prefix bounds-checked

## Decision

Google's migration protobuf is decoded by hand

## Evidence

`vault-core/src/totp_import.rs`
