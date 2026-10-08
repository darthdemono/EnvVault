# ADR-0052: Confidence-scored ENV link matching

Status: accepted

## Context

Real-world env vars have prefixes (`ND_LASTFM_APIKEY` → `LASTFM`) that prevent exact name matches

## Decision

Confidence-scored ENV link matching

## Evidence

`chunk-ops.ts`
