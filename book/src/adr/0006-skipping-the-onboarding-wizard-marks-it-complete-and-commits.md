# ADR-0006: Skipping the onboarding wizard marks it complete and commits nothing

Status: accepted

## Context

Re-showing something dismissed on purpose is how a welcome screen becomes an obstacle; committing settings the user only _looked at_ is worse. Settings has an explicit "Run setup again"

## Decision

Skipping the onboarding wizard marks it complete and commits nothing

## Evidence

`src/ts/onboarding.ts`
