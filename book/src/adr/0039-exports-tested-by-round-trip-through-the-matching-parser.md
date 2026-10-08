# ADR-0039: Exports tested by round trip through the matching parser

Status: accepted

## Context

A copied config a parser cannot read back is one the server will not read either; catches wrong directives and unresolved refs that string assertions miss

## Decision

Exports tested by round trip through the matching parser

## Evidence

`tests/exports.test.ts`
