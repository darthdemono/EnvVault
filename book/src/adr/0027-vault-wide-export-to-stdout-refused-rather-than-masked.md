# ADR-0027: Vault-wide export to stdout refused rather than masked

Status: accepted

## Context

A masked `.env` looks deployable and is not; project exports mask instead because their structure is worth reading

## Decision

Vault-wide `export` to stdout refused rather than masked

## Evidence

`envv-cli/src/envfile.rs`
