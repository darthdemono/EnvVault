//! Structured errors with stable exit codes.
//!
//! An agent cannot read prose. Every failure carries a machine code that means
//! the same thing forever, so a caller can branch on "ambiguous" without
//! string-matching a message that may be reworded next release.

use std::fmt;

/// Stable failure classes. The numeric value is the process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// Something went wrong that has no more specific class.
    Error = 1,
    // 2 is reserved: clap uses it for argument-parsing failures.
    /// The named entry, project, chunk, user or class does not exist.
    NotFound = 3,
    /// The name matched several things. Never guessed — see `data.rs`.
    Ambiguous = 4,
    /// Authentication failed, or the session lacks the permission.
    Denied = 5,
    /// The thing already exists, or a concurrent write won.
    Conflict = 6,
    /// The vault or server could not be reached, or is locked.
    Unavailable = 7,
    /// A destructive action needs `--yes` (stdin is not a terminal).
    NeedsConfirmation = 8,
    /// The output would contain secret values; pass `--reveal` or `--out`.
    Redacted = 9,
    /// The request was well-formed but the input was not valid.
    Invalid = 10,
}

impl Code {
    /// Lowercase snake_case name used in JSON output.
    pub fn as_str(&self) -> &'static str {
        match self {
            Code::Error => "error",
            Code::NotFound => "not_found",
            Code::Ambiguous => "ambiguous",
            Code::Denied => "denied",
            Code::Conflict => "conflict",
            Code::Unavailable => "unavailable",
            Code::NeedsConfirmation => "needs_confirmation",
            Code::Redacted => "redacted",
            Code::Invalid => "invalid",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CliError {
    pub code: Code,
    pub message: String,
    /// Extra machine-readable context — candidate names for an ambiguous
    /// lookup, the field that failed validation, and so on.
    pub details: Option<serde_json::Value>,
}

impl CliError {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), details: None }
    }
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(Code::NotFound, message)
    }
    pub fn ambiguous(message: impl Into<String>) -> Self {
        Self::new(Code::Ambiguous, message)
    }
    pub fn denied(message: impl Into<String>) -> Self {
        Self::new(Code::Denied, message)
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(Code::Conflict, message)
    }
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(Code::Unavailable, message)
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(Code::Invalid, message)
    }
    pub fn redacted(message: impl Into<String>) -> Self {
        Self::new(Code::Redacted, message)
    }

    pub fn to_json(&self) -> serde_json::Value {
        let mut err = serde_json::json!({
            "code": self.code.as_str(),
            "message": self.message,
        });
        if let Some(d) = &self.details {
            err["details"] = d.clone();
        }
        serde_json::json!({ "ok": false, "error": err })
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Plain `String` errors from vault-core and older code become generic failures.
///
/// A few carry a shape worth classifying: vault-core marks a lost-update refusal
/// with `VAULT_CONFLICT`, and the HTTP client prefixes server rejections with
/// their status, so 401/403 arrive as denials rather than nameless errors.
impl From<String> for CliError {
    fn from(s: String) -> Self {
        let code = if s.contains(vault_core::CONFLICT_ERR) {
            Code::Conflict
        } else if s.contains("Server error 401") || s.contains("Server error 403") {
            Code::Denied
        } else if s.contains("Server error 404") {
            Code::NotFound
        } else if s.contains("Cannot reach server") || s.contains("Vault not unlocked") {
            Code::Unavailable
        } else {
            Code::Error
        };
        CliError::new(code, s)
    }
}

impl From<&str> for CliError {
    fn from(s: &str) -> Self {
        CliError::from(s.to_string())
    }
}

pub type CliResult<T = ()> = Result<T, CliError>;
