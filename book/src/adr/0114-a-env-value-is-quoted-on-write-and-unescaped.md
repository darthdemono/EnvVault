# ADR-0114: A .env value is quoted on write and unescaped on read, and the fixture asserts the round

Status: accepted

## Context

`parse(write(v)) == v` is the property a `.env` has to have; the bytes in between are an implementation detail. Pinning the bytes alone would pass for an escaping scheme the parser cannot read back, which is precisely the state this replaced

## Decision

A `.env` value is quoted on write and unescaped on read, and the fixture asserts the **round trip**

## Evidence

`parity/env-names.json`
