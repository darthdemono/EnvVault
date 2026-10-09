# ADR-0047: Require_owner on TOTP and user-management endpoints

Status: accepted

## Context

Any authenticated user could otherwise manage other users' 2FA — TOTP management is owner-only

## Decision

`require_owner` on TOTP and user-management endpoints

## Evidence

`unv-server/main.rs`
