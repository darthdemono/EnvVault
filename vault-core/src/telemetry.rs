//! Structured logging, shared by all three binaries.
//!
//! Before this module the workspace had no `tracing`, no metrics crate and no
//! structured log anywhere: a failure in production left `println!` output and
//! nothing correlatable. Everything in the operability goals — uptime
//! monitoring, failure detection, API analytics — depends on this existing
//! first, which is why it landed ahead of the rest of its phase.
//!
//! # Three rules, and they are not style preferences
//!
//! 1. **Logs go to stderr, always.** The CLI's stdout is a machine-readable
//!    contract (`{"ok":true,…}`); a log line written there corrupts the JSON
//!    envelope an agent is parsing. `with_writer(std::io::stderr)` is what makes
//!    `envv … --json | jq` keep working with `ENVV_LOG=debug` set.
//! 2. **Never log a secret value.** Log the fingerprint (`out::fingerprint`),
//!    the entry id, or the provider name — never `api_key`, never a password,
//!    never a session token. A log file is not encrypted and is routinely
//!    shipped somewhere else.
//! 3. **Logging is off unless asked for.** The default level is chosen by each
//!    binary, and every one of them is quiet enough that normal operation
//!    produces nothing on stderr. A secrets manager that chatters is a secrets
//!    manager whose output nobody reads.
//!
//! # Configuring it
//!
//! | Variable | Effect |
//! | -------- | ------ |
//! | `ENVV_LOG` | `tracing` filter directive (`info`, `envv_server=debug`, …). Checked first. |
//! | `RUST_LOG` | Same, checked only when `ENVV_LOG` is unset, so an unrelated `RUST_LOG` in the environment still works. |
//! | `ENVV_LOG_FORMAT` | `json` for one JSON object per line; anything else is the human format. |
//!
//! An unparseable filter falls back to the caller's default rather than
//! panicking: a typo in an environment variable must not stop a server booting.

use std::sync::OnceLock;

/// Set once by the first successful [`init`], so a second call is a no-op
/// rather than a panic from `tracing`'s global-subscriber guard. The desktop
/// app can host `envv-server`'s router in-process, which is exactly the case
/// where two `init` calls happen in one program.
static INITIALISED: OnceLock<()> = OnceLock::new();

/// Installs the process-wide subscriber. Safe to call more than once; only the
/// first call has any effect.
///
/// `service` names the binary and is attached to the startup line so a merged
/// log tells `envv-server` apart from a desktop app hosting the same router.
/// `default_level` applies when neither `ENVV_LOG` nor `RUST_LOG` is set.
pub fn init(service: &str, default_level: &str) {
    if INITIALISED.set(()).is_err() {
        return;
    }

    let directive = std::env::var("ENVV_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| default_level.to_string());

    let filter = tracing_subscriber::EnvFilter::try_new(&directive)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));

    let json = std::env::var("ENVV_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    // `try_init` rather than `init`: another crate in the process may already
    // own the global subscriber, and losing that race is not an error worth
    // aborting a boot over.
    if json {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .json()
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .try_init();
    }

    tracing::debug!(
        service,
        version = env!("CARGO_PKG_VERSION"),
        filter = %directive,
        "logging initialised"
    );
}

/// True once [`init`] has run in this process. Tests use it; nothing else
/// should need to ask.
pub fn is_initialised() -> bool {
    INITIALISED.get().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_idempotent() {
        init("test", "error");
        assert!(is_initialised());
        // A second call must not panic on tracing's global-subscriber guard.
        init("test", "error");
        assert!(is_initialised());
    }
}
