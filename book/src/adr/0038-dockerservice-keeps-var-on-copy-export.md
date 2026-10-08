# ADR-0038: Docker_service keeps ${VAR} on copy/export

Status: accepted

## Context

Compose substitutes from the `.env` written beside it — the placeholder is correct output there, unlike wg/nginx/ssh

## Decision

`docker_service` keeps `${VAR}` on copy/export

## Evidence

`chunk-ops.ts`
