# ADR-0001: Local-first storage

Status: accepted

## Context

Credentials should remain usable without a hosted account or network service.

## Decision

Store the vault locally in SQLCipher; make the server optional.

## Consequences

The user controls storage and backups. Lost master passwords cannot be reset.
