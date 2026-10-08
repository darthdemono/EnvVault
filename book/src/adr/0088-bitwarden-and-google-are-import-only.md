# ADR-0088: Bitwarden and Google are import-only

Status: accepted

## Context

A Bitwarden export is a whole password vault; one holding nothing but seeds imports as a set of empty logins. Google's payload is a QR code this app cannot draw, so the URI behind it is a format nothing reads

## Decision

Bitwarden and Google are **import-only**

## Evidence

`vault-core/src/totp_import.rs`
