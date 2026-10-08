# ADR-0007: The onboarding wizard is built and destroyed per showing

Status: accepted

## Context

Every handler is then bound to nodes that live for exactly one run, so invariant 9 holds by construction — and static hidden markup is what produces WebKitGTK ghost widgets

## Decision

The onboarding wizard is built and destroyed per showing

## Evidence

`src/ts/onboarding.ts`
