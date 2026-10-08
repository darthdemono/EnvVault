# ADR-0041: Probe_cert_fingerprint as a separate command

Status: accepted

## Context

Confines the unverified handshake to one unauthenticated call that carries no credentials, so TOFU can bootstrap without weakening `remote_request`

## Decision

`probe_cert_fingerprint` as a separate command

## Evidence

`src-tauri/src/lib.rs`
