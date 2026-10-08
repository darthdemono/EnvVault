//! Library half of the `envv` CLI.
//!
//! The binary is a thin argument parser over these modules. They live in a
//! library so integration tests can call the exporters directly and assert them
//! against the same golden files the TypeScript test suite uses — the two
//! implementations of a config format have to agree, and only a shared fixture
//! makes that check possible.

pub mod access;
pub mod agentio;
pub mod authreq;
pub mod backup;
pub mod bundle_cmd;
pub mod catalogue_cmd;
pub mod check_cmd;
pub mod chunks;
pub mod context;
pub mod cookies;
pub mod cxf_cmd;
pub mod data;
pub mod diff_cmd;
pub mod doctor;
pub mod emit_cmd;
pub mod enrich;
pub mod entries;
pub mod envfile;
pub mod error;
pub mod exec;
pub mod exporters;
pub mod feed_cmd;
pub mod filecred;
pub mod fmt;
pub mod gen;
pub mod import_vaults;
pub mod oauth_cmd;
pub mod out;
pub mod pool;
pub mod profile;
pub mod projects;
pub mod ratelimit;
pub mod refs;
pub mod render;
pub mod reset_cmd;
pub mod scan;
pub mod session;
pub mod session_cmd;
pub mod shield;
pub mod starters;
pub mod template_cmd;
pub mod tls;
pub mod totp_cmd;
pub mod uid_cmd;
pub mod users_cmd;
