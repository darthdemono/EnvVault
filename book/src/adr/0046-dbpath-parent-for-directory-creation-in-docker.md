# ADR-0046: Db_path.parent() for directory creation in Docker

Status: accepted

## Context

Computed `data_dir` path fails for non-root users in Docker; parent of actual db file always accessible

## Decision

`db_path.parent()` for directory creation in Docker

## Evidence

`unv-server/main.rs`
