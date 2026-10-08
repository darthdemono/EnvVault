# ADR-0010: GetModifierState('CapsLock') is read only after two typed characters agreed with it, and

Status: superseded by ADR-0004

## Context

The derived reading is right and free, but says nothing until a letter is typed — which is exactly when a master password is most likely to be wrong. Checking the platform against observed reality buys back the click-to-focus case on platforms that do not lie, while WebKitGTK's always-true mask disqualifies itself on the first lowercase letter. There is deliberately no "consistently inverted" state: a stuck mask is indistinguishable from an inverted one until the lock changes, and believing an inversion is the original bug in mirror image

## Decision

`getModifierState('CapsLock')` is read only after two typed characters agreed with it, and never again after one disagreed

## Evidence

`src/ts/ui-qol.ts`
