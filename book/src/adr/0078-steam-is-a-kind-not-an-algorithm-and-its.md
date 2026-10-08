# ADR-0078: Steam is a Kind, not an Algorithm, and its shape is forced rather than validated

Status: accepted

## Context

The HMAC is RFC 6238's, unchanged; only the rendering is base 26 over Steam's alphabet. Forcing SHA-1/5/30 on read means a generic exporter's `digits: 6` beside a Steam seed cannot produce six characters no Steam login accepts

## Decision

Steam is a `Kind`, not an `Algorithm`, and its shape is forced rather than validated

## Evidence

`vault-core/src/totp.rs`
