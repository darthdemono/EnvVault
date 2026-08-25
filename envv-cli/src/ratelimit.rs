//! Rate limits: parsing the free-text form, and rendering the structured one.
//!
//! An entry carries the limit twice on purpose. `rate_limit_count` +
//! `rate_limit_period` are the structured pair everything reads;
//! `rate_limit` is a human string kept alongside it so a vault written by a
//! current build still means something to an older one, and so a limit nobody
//! can express as `<n> per <period>` ("varies by endpoint") is not thrown away.
//!
//! **This module is the twin of `src/ts/ratelimit.ts`.** Both are pinned
//! against the same golden table in `tests/fixtures/parity/rate-limit.json` by
//! `envv-cli/tests/ratelimit.rs` and `tests/ratelimit.test.ts`. Two
//! implementations of one format drift silently; the fixture is what turns a
//! divergence into a test failure.

use serde_json::Value;

/// The window a rate-limit count applies to.
///
/// `Second` and `Minute` exist even though most published limits are hourly or
/// daily, because the ones that bite are per-second burst caps — and because
/// the free-text values already in vaults are overwhelmingly `"n/min"`, which
/// has to survive migration as something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Period {
    Second,
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
}

impl Period {
    /// The canonical name, and the only spelling ever written to a vault.
    pub fn as_str(self) -> &'static str {
        match self {
            Period::Second => "second",
            Period::Minute => "minute",
            Period::Hour => "hour",
            Period::Day => "day",
            Period::Week => "week",
            Period::Month => "month",
            Period::Year => "year",
        }
    }

    /// Every period, ascending. Used by `--rate-limit-period`'s help text so the
    /// accepted values cannot drift from the enum.
    pub const ALL: [Period; 7] = [
        Period::Second,
        Period::Minute,
        Period::Hour,
        Period::Day,
        Period::Week,
        Period::Month,
        Period::Year,
    ];

    /// Read one canonical name. Strict: this is for values already in a vault
    /// or given to a flag, not for the free text [`parse`] handles.
    pub fn from_canonical(s: &str) -> Option<Period> {
        Period::ALL.into_iter().find(|p| p.as_str() == s)
    }

    /// Read any accepted spelling: `min`, `hr`, `daily`, `mo`, `yr`, …
    ///
    /// Deliberately generous on input and strict on output. The strings already
    /// in people's vaults were typed by hand over years, and a migration that
    /// only understood its own output would drop most of them.
    fn from_alias(s: &str) -> Option<Period> {
        Some(match s {
            "s" | "sec" | "secs" | "second" | "seconds" => Period::Second,
            "m" | "min" | "mins" | "minute" | "minutes" => Period::Minute,
            "h" | "hr" | "hrs" | "hour" | "hours" => Period::Hour,
            "d" | "day" | "days" | "daily" => Period::Day,
            "w" | "wk" | "week" | "weeks" | "weekly" => Period::Week,
            "mo" | "mon" | "month" | "months" | "monthly" => Period::Month,
            "y" | "yr" | "yrs" | "year" | "years" | "annual" | "annually" => Period::Year,
            _ => return None,
        })
    }
}

impl std::fmt::Display for Period {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Words that may sit between the number and the period: `100 req/min`,
/// `5000 requests per hour`, `60 calls/minute`.
///
/// A unit that *changes the meaning* — `tokens`, `GB` — is deliberately absent.
/// "40000 tokens/min" is not a request limit, and recording it as one would be
/// wrong; it falls through to `None` and is preserved verbatim as a note.
fn is_noise(w: &str) -> bool {
    matches!(
        w,
        "req" | "reqs" | "request" | "requests" | "call" | "calls" | "hit" | "hits" | "api"
    )
}

/// Read a free-text rate limit into a count and a period.
///
/// Returns `None` for anything it cannot read with confidence — including a
/// count with no period, which is not a rate limit but a number.
pub fn parse(raw: &str) -> Option<(u64, Period)> {
    let text = raw.trim().to_lowercase();
    if text.is_empty() {
        return None;
    }

    // The number: optional thousands separators, no decimals. "1.5k/min" is
    // ambiguous enough to be worth refusing rather than guessing at.
    let digits: String = text
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == ',' || *c == '_' || *c == ' ')
        .collect();
    let cleaned: String = digits.chars().filter(|c| c.is_ascii_digit()).collect();
    if cleaned.is_empty() || !digits.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let count: u64 = cleaned.parse().ok()?;

    // Everything after the number, with separators and noise words removed.
    let rest = text[digits.len()..].replace(['/', '-'], " ");
    let words: Vec<&str> = rest
        .split_whitespace()
        .filter(|w| !w.is_empty() && *w != "per" && *w != "a" && *w != "every" && !is_noise(w))
        .collect();

    // Exactly one token must remain, and it must name a period. Anything else —
    // "100 tokens min", "60 per user per minute" — means the string is saying
    // more than this schema can hold, and guessing at it loses the difference.
    if words.len() != 1 {
        return None;
    }
    Period::from_alias(words[0]).map(|p| (count, p))
}

/// Render the structured pair as the canonical human string.
///
/// Uses the full period name rather than an abbreviation so the output round
/// trips through [`parse`] — a format that cannot read its own output is how the
/// two halves of an entry drift apart.
pub fn format(count: Option<u64>, period: Option<Period>) -> String {
    match (count, period) {
        (Some(c), Some(p)) => format!("{c}/{p}"),
        _ => String::new(),
    }
}

/// The three rate-limit fields as they should be stored.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Normalized {
    pub legacy: Option<String>,
    pub count: Option<u64>,
    pub period: Option<Period>,
    pub note: Option<String>,
}

/// Normalise whatever an entry carries into the three fields it should carry.
///
/// The migration runs on read rather than as a one-off pass: an entry can
/// arrive from an older desktop build, from a remote server on a different
/// version, or from a backup restored years later, so there is no single moment
/// when "the vault has been migrated" is true.
///
/// Precedence is structured-wins — otherwise editing the number would be
/// silently reverted by the stale string sitting beside it.
pub fn normalize(entry: &Value) -> Normalized {
    let str_of = |k: &str| entry.get(k).and_then(Value::as_str).map(str::to_string);

    let count = entry.get("rate_limit_count").and_then(Value::as_u64);
    let period = entry
        .get("rate_limit_period")
        .and_then(Value::as_str)
        .and_then(Period::from_canonical);

    // The note is *derived*, never authored. It exists only to hold text that
    // could not be read as a limit, so once a limit can be read the note has
    // nothing left to say and is dropped. Carrying it forward produced an entry
    // reading "100/minute" with a note beside it still saying "varies by
    // endpoint" — two contradictory answers to one question, the newer one
    // quietly undermined by the older.
    //
    // A count without a period is not a rate limit; both halves or neither.
    if let (Some(c), Some(p)) = (count, period) {
        return Normalized {
            legacy: Some(format(Some(c), Some(p))),
            count: Some(c),
            period: Some(p),
            note: None,
        };
    }

    let legacy_raw = str_of("rate_limit").unwrap_or_default();
    if let Some((c, p)) = parse(&legacy_raw) {
        return Normalized {
            legacy: Some(format(Some(c), Some(p))),
            count: Some(c),
            period: Some(p),
            note: None,
        };
    }

    // Unparseable, but not empty: keep the human's words. They knew something
    // the schema does not express, and dropping the text on the first save
    // under a new version is data loss nobody asked for.
    let trimmed = legacy_raw.trim().to_string();
    let kept = if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    };
    Normalized {
        legacy: kept.clone(),
        count: None,
        period: None,
        note: kept,
    }
}

/// Write the normalised fields back onto an entry, removing what is absent.
///
/// Removing rather than writing `null` matters: `entry set --rate-limit ""`
/// must leave an entry that looks like one which never had a limit, or the
/// health scan and the UI both have to special-case a null they cannot
/// distinguish from an absent field.
pub fn apply(entry: &mut Value, n: &Normalized) {
    let Some(obj) = entry.as_object_mut() else {
        return;
    };
    let mut set = |key: &str, v: Option<Value>| match v {
        Some(v) => {
            obj.insert(key.to_string(), v);
        }
        None => {
            obj.remove(key);
        }
    };
    set("rate_limit", n.legacy.clone().map(Value::from));
    set("rate_limit_count", n.count.map(Value::from));
    set(
        "rate_limit_period",
        n.period.map(|p| Value::from(p.as_str())),
    );
    set("rate_limit_note", n.note.clone().map(Value::from));
}
