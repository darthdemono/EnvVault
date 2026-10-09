# ADR-0034: Confirm() errors on a non-tty rather than assuming yes

Status: accepted

## Context

A script that forgot `--yes` must fail loudly, not delete quietly

## Decision

`confirm()` errors on a non-tty rather than assuming yes

## Evidence

`unv-cli/src/fmt.rs`
