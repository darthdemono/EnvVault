//! iCalendar (RFC 5545) feed for the vault's dates — the Rust twin of
//! `src/ts/calendar.ts`.
//!
//! This is the fourth format in the project implemented twice, and it follows
//! the rule the other three established: **one golden file, asserted from both
//! sides**. `tests/fixtures/parity/calendar.ics` is written by the TypeScript
//! suite and read back by `envv-cli/tests/parity.rs`, because reviewing two
//! implementations for agreement does not work — the first time that fixture
//! ran for the exporters it found two live bugs.
//!
//! # What is deliberately not in the file
//!
//! No secret values, and no fingerprints either. An `.ics` is the least private
//! thing this program writes: it exists to be handed to Google Calendar or a
//! phone, which stores it unencrypted on hardware nobody here controls. A
//! fingerprint is stable per value, so a feed carrying them would tell anyone
//! holding two feeds which secrets are the same — an equality oracle over the
//! vault, published to a third party. Names and dates travel; nothing else.

use serde_json::Value;
use time::OffsetDateTime;

/// Which kinds of event to emit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventKind {
    Created,
    Expires,
    Rotation,
}

impl EventKind {
    /// The `CATEGORIES` value, matching the TypeScript side's
    /// `ev.kind.toUpperCase()`.
    fn category(self) -> &'static str {
        match self {
            EventKind::Created => "CREATED",
            EventKind::Expires => "EXPIRES",
            EventKind::Rotation => "ROTATION",
        }
    }

    /// Parses a CLI `--kind` value.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "created" | "creation" => Some(EventKind::Created),
            "expires" | "expiry" | "expiring" => Some(EventKind::Expires),
            "rotation" | "rotate" => Some(EventKind::Rotation),
            _ => None,
        }
    }
}

/// Options for [`build_ics`].
pub struct IcsOptions {
    pub kinds: Vec<EventKind>,
    /// `DTSTAMP` as an RFC 3339 string.
    ///
    /// Injectable for the same reason as the TypeScript side: a fixture that
    /// embeds the wall clock cannot be compared with anything, and without a
    /// fixed stamp the CLI and the app can never produce identical bytes.
    pub now: String,
    pub calendar_name: String,
}

impl Default for IcsOptions {
    fn default() -> Self {
        IcsOptions {
            kinds: vec![EventKind::Created, EventKind::Expires, EventKind::Rotation],
            now: vault_core::iso_now(),
            calendar_name: "EnvVault".to_string(),
        }
    }
}

struct CalEvent {
    uid: String,
    date: String,
    summary: String,
    description: String,
    kind: EventKind,
    alarm_days_before: u32,
}

/// RFC 5545 §3.3.11 escaping: backslash, semicolon, comma, newline.
pub fn ics_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\r' => {
                // CRLF collapses to one escaped newline, matching the
                // TypeScript `/\r?\n/`.
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push_str("\\n");
            }
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// RFC 5545 §3.1 folding: 75 **octets** for the first line, 74 for each
/// continuation, which begins with a space.
///
/// Octets, not characters — the same trap the TypeScript twin documents. A name
/// with an accent or an emoji is several bytes per character, and folding by
/// character count yields a line that is legal by one measure and illegal by the
/// one a parser applies.
pub fn ics_fold(line: &str) -> String {
    let bytes = line.as_bytes();
    if bytes.len() <= 75 {
        return line.to_string();
    }
    let mut out = String::new();
    let mut start = 0usize;
    let mut limit = 75usize;
    while start < bytes.len() {
        let mut end = (start + limit).min(bytes.len());
        // Never split a UTF-8 sequence: continuation bytes are 0b10xxxxxx.
        while end > start && end < bytes.len() && (bytes[end] & 0xC0) == 0x80 {
            end -= 1;
        }
        if !out.is_empty() {
            out.push_str("\r\n ");
        }
        out.push_str(&line[start..end]);
        start = end;
        limit = 74;
    }
    out
}

/// Parses an RFC 3339 timestamp, falling back to a bare `YYYY-MM-DD` prefix.
///
/// The fallback is not laxity for its own sake: vault JSON can come from an
/// imported backup or a hand edit, and a date-only `expires_at` is exactly what
/// a human types. `new Date()` on the TypeScript side accepts it, so refusing
/// it here would put an event in the app's calendar and not in the CLI's.
fn parse_dt(iso: &str) -> Option<OffsetDateTime> {
    if let Ok(dt) = OffsetDateTime::parse(iso, &time::format_description::well_known::Rfc3339) {
        return Some(dt);
    }
    let head = iso.get(0..10)?;
    let mut parts = head.split('-');
    let y: i32 = parts.next()?.parse().ok()?;
    let m: u8 = parts.next()?.parse().ok()?;
    let d: u8 = parts.next()?.parse().ok()?;
    let date = time::Date::from_calendar_date(y, time::Month::try_from(m).ok()?, d).ok()?;
    Some(date.midnight().assume_utc())
}

/// `2026-08-26T21:00:00Z` → `20260826` (UTC), or `None` when unparseable.
pub fn to_ics_date(iso: Option<&str>) -> Option<String> {
    let dt = parse_dt(iso?)?;
    Some(format!(
        "{:04}{:02}{:02}",
        dt.year(),
        dt.month() as u8,
        dt.day()
    ))
}

/// `2026-08-26T21:00:00Z` → `20260826T210000Z`, for `DTSTAMP`.
pub fn to_ics_stamp(iso: &str) -> String {
    let dt = parse_dt(iso).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let utc = dt.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        utc.year(),
        utc.month() as u8,
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

/// The day after `YYYYMMDD` — what an all-day `DTEND` must be.
pub fn next_day(yyyymmdd: &str) -> String {
    let y: i32 = yyyymmdd[0..4].parse().unwrap_or(1970);
    let m: u8 = yyyymmdd[4..6].parse().unwrap_or(1);
    let d: u8 = yyyymmdd[6..8].parse().unwrap_or(1);
    let date = time::Month::try_from(m)
        .ok()
        .and_then(|mm| time::Date::from_calendar_date(y, mm, d).ok())
        .map(|dd| dd.next_day().unwrap_or(dd));
    match date {
        Some(dd) => format!("{:04}{:02}{:02}", dd.year(), dd.month() as u8, dd.day()),
        None => yyyymmdd.to_string(),
    }
}

fn s(entry: &Value, key: &str) -> Option<String> {
    entry
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Display name: provider, plus whatever distinguishes it from its siblings.
pub fn entry_label(entry: &Value) -> String {
    let provider = s(entry, "provider").unwrap_or_default();
    let extra: Vec<String> = ["key_id", "account_name"]
        .iter()
        .filter_map(|k| s(entry, k))
        .collect();
    if extra.is_empty() {
        provider
    } else {
        format!("{provider} ({})", extra.join(" / "))
    }
}

/// When rotation is next due, anchored on the last rotation or, failing that,
/// on creation.
///
/// A 90-day key that has never been rotated is due 90 days after it was issued,
/// not never. An entry with neither anchor gets no event: putting a deadline in
/// someone's calendar that no evidence supports is worse than leaving it out.
pub fn rotation_due(entry: &Value) -> Option<String> {
    let days = entry.get("rotation_days").and_then(|v| v.as_i64())?;
    if days <= 0 {
        return None;
    }
    let anchor = s(entry, "last_rotated_at").or_else(|| s(entry, "created_at"))?;
    let dt = parse_dt(&anchor)?;
    let due = dt + time::Duration::days(days);
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        due.year(),
        due.month() as u8,
        due.day(),
        due.hour(),
        due.minute(),
        due.second()
    ))
}

fn meta_lines(entry: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(t) = s(entry, "secretType") {
        parts.push(format!("Type: {t}"));
    }
    if let Some(e) = s(entry, "environment") {
        parts.push(format!("Environment: {e}"));
    }
    let cats: Vec<String> = entry
        .get("categories")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|c| c.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if !cats.is_empty() {
        parts.push(format!("Categories: {}", cats.join(", ")));
    }
    parts.join("\n")
}

fn events_for_entry(entry: &Value, kinds: &[EventKind]) -> Vec<CalEvent> {
    let mut out = Vec::new();
    // `id` is guaranteed by the app's `ensureEntryIds`; the fallback stops a
    // hand-edited vault producing two events with one UID, which a calendar
    // treats as one event updating itself.
    let id = s(entry, "id").unwrap_or_else(|| {
        format!(
            "{}:{}:{}",
            s(entry, "provider").unwrap_or_default(),
            s(entry, "key_id").unwrap_or_default(),
            s(entry, "account_name").unwrap_or_default()
        )
    });
    let label = entry_label(entry);
    let meta = meta_lines(entry);
    let join = |head: String| -> String {
        if meta.is_empty() {
            head
        } else {
            format!("{head}\n{meta}")
        }
    };

    if kinds.contains(&EventKind::Created) {
        if let Some(date) = to_ics_date(s(entry, "created_at").as_deref()) {
            out.push(CalEvent {
                uid: format!("{id}-created@envvault"),
                date,
                summary: format!("Created: {label}"),
                description: join(format!("{label} was added to the vault.")),
                kind: EventKind::Created,
                alarm_days_before: 0,
            });
        }
    }

    if kinds.contains(&EventKind::Expires) {
        if let Some(date) = to_ics_date(s(entry, "expires_at").as_deref()) {
            out.push(CalEvent {
                uid: format!("{id}-expires@envvault"),
                date,
                summary: format!("Expires: {label}"),
                description: join(format!("{label} expires on this day.")),
                kind: EventKind::Expires,
                // A reminder on the morning it dies arrives during the outage.
                alarm_days_before: 7,
            });
        }
    }

    if kinds.contains(&EventKind::Rotation) {
        if let Some(due) = rotation_due(entry) {
            if let Some(date) = to_ics_date(Some(&due)) {
                let days = entry
                    .get("rotation_days")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                out.push(CalEvent {
                    uid: format!("{id}-rotation@envvault"),
                    date,
                    summary: format!("Rotate: {label}"),
                    description: join(format!("{label} is due for rotation (every {days} days).")),
                    kind: EventKind::Rotation,
                    alarm_days_before: 3,
                });
            }
        }
    }

    out
}

/// Builds the calendar. Byte-identical to `buildIcs` in `src/ts/calendar.ts`
/// for the same input — that is what the parity fixture checks.
pub fn build_ics(entries: &[Value], opts: &IcsOptions) -> String {
    let stamp = to_ics_stamp(&opts.now);

    let mut events: Vec<CalEvent> = entries
        .iter()
        .flat_map(|e| events_for_entry(e, &opts.kinds))
        .collect();
    // Sorted by date then UID so two runs over one vault produce the same bytes;
    // otherwise the file's order follows the entry array and a reordered vault
    // looks like a changed calendar to anything diffing it.
    events.sort_by(|a, b| a.date.cmp(&b.date).then_with(|| a.uid.cmp(&b.uid)));

    let mut lines: Vec<String> = vec![
        "BEGIN:VCALENDAR".into(),
        "VERSION:2.0".into(),
        "PRODID:-//EnvVault//Secrets Calendar//EN".into(),
        "CALSCALE:GREGORIAN".into(),
        "METHOD:PUBLISH".into(),
        format!("X-WR-CALNAME:{}", ics_escape(&opts.calendar_name)),
        "X-WR-TIMEZONE:UTC".into(),
    ];

    for ev in &events {
        lines.push("BEGIN:VEVENT".into());
        lines.push(format!("UID:{}", ics_escape(&ev.uid)));
        lines.push(format!("DTSTAMP:{stamp}"));
        lines.push(format!("DTSTART;VALUE=DATE:{}", ev.date));
        lines.push(format!("DTEND;VALUE=DATE:{}", next_day(&ev.date)));
        lines.push(format!("SUMMARY:{}", ics_escape(&ev.summary)));
        lines.push(format!("DESCRIPTION:{}", ics_escape(&ev.description)));
        lines.push(format!("CATEGORIES:{}", ev.kind.category()));
        // Markers, not commitments: three expiries on one day must not show the
        // owner as busy all day.
        lines.push("TRANSP:TRANSPARENT".into());
        if ev.alarm_days_before > 0 {
            lines.push("BEGIN:VALARM".into());
            lines.push("ACTION:DISPLAY".into());
            lines.push(format!("DESCRIPTION:{}", ics_escape(&ev.summary)));
            lines.push(format!("TRIGGER:-P{}D", ev.alarm_days_before));
            lines.push("END:VALARM".into());
        }
        lines.push("END:VEVENT".into());
    }
    lines.push("END:VCALENDAR".into());

    let folded: Vec<String> = lines.iter().map(|l| ics_fold(l)).collect();
    // CRLF is not optional in RFC 5545, and the trailing one is what makes the
    // last line a line.
    format!("{}\r\n", folded.join("\r\n"))
}

/// Number of `VEVENT` blocks in a rendered calendar — for the CLI's summary
/// line, which reports a count rather than printing the file.
pub fn event_count(ics: &str) -> usize {
    ics.matches("BEGIN:VEVENT").count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn escapes_the_four_reserved_characters() {
        assert_eq!(ics_escape("a,b;c\\d\ne"), "a\\,b\\;c\\\\d\\ne");
    }

    #[test]
    fn folds_on_octets_not_characters() {
        // Ninety é characters: 90 chars, 180 bytes. Folding by character count
        // would leave the first line legal-looking and 180 octets long.
        let line = "é".repeat(90);
        let folded = ics_fold(&line);
        for part in folded.split("\r\n") {
            let content = part.strip_prefix(' ').unwrap_or(part);
            assert!(
                content.len() <= 75,
                "folded segment is {} octets",
                content.len()
            );
        }
        // Folding must be reversible: unfolding restores the original exactly.
        assert_eq!(folded.replace("\r\n ", ""), line);
    }

    #[test]
    fn rotation_falls_back_to_the_creation_date() {
        // A 90-day key that has never been rotated is due 90 days after it was
        // issued. Reporting "never" for it is how a cadence silently does
        // nothing.
        let e =
            json!({ "provider": "X", "created_at": "2026-01-01T00:00:00Z", "rotation_days": 90 });
        assert_eq!(
            to_ics_date(rotation_due(&e).as_deref()),
            Some("20260401".to_string())
        );
    }

    #[test]
    fn an_entry_with_no_anchor_gets_no_rotation_event() {
        let e = json!({ "provider": "X", "rotation_days": 90 });
        assert!(rotation_due(&e).is_none());
    }

    #[test]
    fn no_secret_value_reaches_the_calendar() {
        // The guarantee the whole module exists to keep. An .ics is handed to a
        // third-party calendar; a value in it is disclosed to that service.
        let e = json!({
            "id": "e1",
            "provider": "GitHub",
            "api_key": "ghp_SUPERSECRETVALUE",
            "api_secret": "second-secret",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-06-01T00:00:00Z"
        });
        let ics = build_ics(&[e], &IcsOptions::default());
        assert!(!ics.contains("ghp_SUPERSECRETVALUE"));
        assert!(!ics.contains("second-secret"));
        assert!(ics.contains("SUMMARY:Created: GitHub"));
    }

    #[test]
    fn uids_are_stable_so_a_re_import_updates_rather_than_duplicates() {
        let e = json!({ "id": "abc", "provider": "X", "expires_at": "2026-06-01T00:00:00Z" });
        let a = build_ics(std::slice::from_ref(&e), &IcsOptions::default());
        let b = build_ics(&[e], &IcsOptions::default());
        assert!(a.contains("UID:abc-expires@envvault"));
        assert_eq!(event_count(&a), 1);
        assert_eq!(event_count(&b), 1);
    }

    #[test]
    fn all_day_events_end_on_the_following_day() {
        // An all-day DTEND is exclusive. Ending on the same day makes the event
        // zero-length, and several clients then drop it entirely.
        assert_eq!(next_day("20261231"), "20270101");
        assert_eq!(next_day("20260228"), "20260301");
    }
}
