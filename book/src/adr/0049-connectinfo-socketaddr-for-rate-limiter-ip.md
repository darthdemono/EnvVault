# ADR-0049: ConnectInfo<SocketAddr> for rate limiter IP

Status: accepted

## Context

`X-Forwarded-For` is trivially spoofable; real socket address is not

## Decision

`ConnectInfo<SocketAddr>` for rate limiter IP

## Evidence

`unv-server/main.rs`
