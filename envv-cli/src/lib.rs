//! Library half of the `envv` CLI.
//!
//! The binary is a thin argument parser over these modules. They live in a
//! library so integration tests can call the exporters directly and assert them
//! against the same golden files the TypeScript test suite uses — the two
//! implementations of a config format have to agree, and only a shared fixture
//! makes that check possible.

pub mod access;
pub mod agentio;
pub mod backup;
pub mod chunks;
pub mod data;
pub mod enrich;
pub mod entries;
pub mod exec;
pub mod envfile;
pub mod error;
pub mod exporters;
pub mod fmt;
pub mod gen;
pub mod out;
pub mod projects;
pub mod render;
pub mod refs;
pub mod scan;
pub mod session;
pub mod starters;
pub mod users_cmd;
