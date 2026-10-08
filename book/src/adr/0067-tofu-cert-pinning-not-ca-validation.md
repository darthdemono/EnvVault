# ADR-0067: TOFU cert pinning (not CA validation)

Status: accepted

## Context

Server uses self-signed certs; CA chain meaningless for local-only server

## Decision

TOFU cert pinning (not CA validation)

## Evidence

`src-tauri/src/lib.rs`
