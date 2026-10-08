# ADR-0003: Native export writes

Status: accepted

## Context

WebKitGTK can ignore browser-style download links without reporting a failure.

## Decision

Desktop exports are written through the native backend into the download
directory with collision-safe filenames and private Unix permissions.

## Consequences

The success message follows the completed write rather than an attempted link
click. A future save-as flow can replace the target selection without changing
the write safety rules.
