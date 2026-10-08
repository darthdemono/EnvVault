# ADR-0066: FingerprintVerifier custom rustls verifier

Status: accepted

## Context

`danger_accept_invalid_certs(true)` doesn't verify — replaced with actual SHA-256 comparison before handshake completes

## Decision

`FingerprintVerifier` custom rustls verifier

## Evidence

`src-tauri/src/lib.rs`
