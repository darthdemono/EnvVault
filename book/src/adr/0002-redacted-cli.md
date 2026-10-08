# ADR-0002: Redacted CLI defaults

Status: accepted

## Context

CLI output is commonly retained in logs and automation transcripts.

## Decision

Redact stored secret values by default and require an explicit reveal action.

## Consequences

Automation must opt into exposure or materialise values directly to files.
