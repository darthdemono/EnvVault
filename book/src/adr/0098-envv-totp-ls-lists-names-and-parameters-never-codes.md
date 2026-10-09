# ADR-0098: Envv totp ls lists names and parameters, never codes

Status: accepted

## Context

A vault-wide dump of live codes is the same shape as the vault-wide export to stdout that Phase 14 refuses. That each code dies in thirty seconds does not make the transcript it lands in any less of one

## Decision

`envv totp ls` lists names and parameters, **never codes**

## Evidence

`unv-cli/src/totp_cmd.rs`
