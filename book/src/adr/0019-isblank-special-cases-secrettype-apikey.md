# ADR-0019: Is_blank special-cases secretType == "api_key"

Status: accepted

## Context

Every writer stamps that default, so treating it as "set" left every imported `postgres://` URL misclassified forever

## Decision

`is_blank` special-cases `secretType == "api_key"`

## Evidence

`envv-cli/src/enrich.rs`
