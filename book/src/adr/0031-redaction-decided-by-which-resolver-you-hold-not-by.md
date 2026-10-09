# ADR-0031: Redaction decided by which Resolver you hold, not by a flag check

Status: accepted

## Context

An exporter cannot print a real value without being handed a materialising resolver, so a _new_ exporter is safe by default

## Decision

Redaction decided by which `Resolver` you hold, not by a flag check

## Evidence

`unv-cli/src/refs.rs`, `exporters.rs`
