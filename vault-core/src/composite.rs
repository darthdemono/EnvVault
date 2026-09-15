//! Composite secrets (Phase 24.1) — one value with secrets inside it.
//!
//! The motivating case is a calendar-sharing URL,
//! `https://outlook.office365.com/owa/calendar/{mailbox_id}@inf.elte.hu/{calendar_key}/calendar.ics`,
//! where two path segments are credentials and the rest is structure. The
//! root is the **template**; each placeholder is a **part**. Parts are
//! ordinary `extra_vars` — see the design note in `src/ts/composite.rs`'s
//! TypeScript twin (`src/ts/composite.ts`) for why a second array was
//! rejected. This module renders the template against a set of parts and does
//! nothing else: it does not know about `VaultEntry`, redaction, or `${…}`
//! references.
//!
//! This is a twin pair with `src/ts/composite.ts`, pinned by
//! `tests/fixtures/parity/composite.json` — the form needs a live preview, so
//! rendering exists in both languages, and two implementations of one
//! template language drift silently if nothing asserts they agree.
//!
//! ## Encoding — decided 2026-09-14
//!
//! A URL is several zones with different reserved characters, and a value
//! inserted raw can change what the URL *means*
//! (`postgres://app:p@ss@db/prod` parses with host `ss@db`). So: parts are
//! stored **raw** (the vault holds the credential the issuer gave), and the
//! renderer classifies each placeholder by the zone it sits in — from a parse
//! of the **template text**, not of a URL built from real values — and
//! percent-encodes accordingly. `custom` never encodes: the preview shows the
//! encoded result, so what is copied is what was seen.
//!
//! The encoder implements exactly RFC 3986's unreserved set
//! (`ALPHA / DIGIT / "-" / "." / "_" / "~"`) rather than delegating to a
//! JS/Rust built-in — `encodeURIComponent` and this module must byte-for-byte
//! agree, and the built-ins on the two sides do not use the same unreserved
//! set (JS additionally leaves `! ~ * ' ( )` unescaped).

use std::collections::BTreeMap;
use std::fmt;

/// What a composite template *is*, which decides its encoding and whether an
/// Open action is offered. Open past the four presets, the same
/// open-vocabulary reasoning as `primary_role`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `http(s)://` only; Open behind a confirmation; zone-aware encoding.
    Link,
    /// A presigned/SAS URL — same zone encoding as `Link`. Whether editing
    /// outside the signature part is refused is a form-level rule (C10), not
    /// a rendering one, so it is not enforced here.
    SignedLink,
    /// A connection string (`postgres://user:pass@host/db`) — same zone
    /// encoding; userinfo encoding is what stops a `@`/`:` in a password from
    /// moving the host.
    Connection,
    /// Not a URL. No encoding, no zone classification.
    Custom,
    /// An unrecognised kind string. Treated as `Custom` — the safe default,
    /// since assuming URL structure over an unknown shape as easily
    /// *corrupts* a rendered value as it protects one.
    Other,
}

impl Kind {
    pub fn parse(s: &str) -> Self {
        match s {
            "link" => Kind::Link,
            "signed_link" => Kind::SignedLink,
            "connection" => Kind::Connection,
            "custom" => Kind::Custom,
            _ => Kind::Other,
        }
    }

    fn is_url_shaped(self) -> bool {
        matches!(self, Kind::Link | Kind::SignedLink | Kind::Connection)
    }
}

/// Where in the template a placeholder sits, decided by a parse of the
/// template text around it — never by parsing the rendered output, which
/// would already contain the (possibly `/`- or `@`-bearing) part value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Zone {
    /// Before `://`, or the whole string when there is no `://` at all
    /// (a `custom`-shaped value, or a URL-kind template with no scheme).
    Unstructured,
    UserInfo,
    Host,
    Path,
    QueryName,
    QueryValue,
    Fragment,
}

/// One named `{part}` and the raw value it holds.
#[derive(Debug, Clone)]
pub struct Part {
    pub key: String,
    pub value: String,
}

/// What went wrong rendering a template. `Display` gives the user-facing text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// A `{name}` with no matching part. The name is the placeholder, exactly
    /// as it appeared in the template.
    UnfilledPlaceholder(String),
    /// A `{` that starts neither `{{` nor a valid `{name}` — a template typo,
    /// not a literal brace.
    UnbalancedBrace(usize),
    /// A part's raw value contains a newline or control character, and the
    /// kind is URL-shaped (link/signed_link/connection) — C6.
    ControlCharacterInPart(String),
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RenderError::UnfilledPlaceholder(name) => {
                write!(
                    f,
                    "no part named \"{name}\" — the template cannot render without it"
                )
            }
            RenderError::UnbalancedBrace(at) => {
                write!(
                    f,
                    "unbalanced '{{' at position {at} — use '{{{{' for a literal brace"
                )
            }
            RenderError::ControlCharacterInPart(name) => {
                write!(f, "part \"{name}\" contains a newline or control character, which a URL cannot carry")
            }
        }
    }
}

/// The result of a successful render: the text, and which parts were used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub text: String,
    /// Placeholder names actually found in the template, in first-use order.
    pub used: Vec<String>,
    /// Parts supplied but never referenced by any placeholder (C8's sibling —
    /// not an error, a health-scan-shaped warning for the caller to raise).
    pub unused: Vec<String>,
}

/// Exactly RFC 3986's unreserved set. Deliberately not `encodeURIComponent`
/// (JS) or `percent-encoding`'s `NON_ALPHANUMERIC` (Rust) — both leave a
/// different, larger set unescaped than this, and the two sides must agree on
/// every byte, not merely on "encoded enough".
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn has_control_char(s: &str) -> bool {
    s.chars().any(|c| c.is_control())
}

/// One token of a tokenised template: either literal text or a placeholder.
enum Token {
    Literal(String),
    /// `(name, byte_offset_in_template)` — the offset is what `classify_zone`
    /// needs, and it is the offset in the *template*, before substitution.
    Placeholder(String, usize),
}

/// Splits a template into literal and placeholder tokens, validating brace
/// balance and placeholder-name syntax as it goes.
fn tokenize(template: &str) -> Result<Vec<Token>, RenderError> {
    let bytes = template.as_bytes();
    let mut tokens = Vec::new();
    let mut literal = String::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' if bytes.get(i + 1) == Some(&b'{') => {
                literal.push('{');
                i += 2;
            }
            b'}' if bytes.get(i + 1) == Some(&b'}') => {
                literal.push('}');
                i += 2;
            }
            b'{' => {
                let start = i;
                let close = template[i..].find('}').map(|p| p + i);
                let close = match close {
                    Some(c) => c,
                    None => return Err(RenderError::UnbalancedBrace(start)),
                };
                let name = &template[i + 1..close];
                if name.is_empty() || !is_valid_name(name) {
                    return Err(RenderError::UnbalancedBrace(start));
                }
                if !literal.is_empty() {
                    tokens.push(Token::Literal(std::mem::take(&mut literal)));
                }
                tokens.push(Token::Placeholder(name.to_string(), start));
                i = close + 1;
            }
            b'}' => return Err(RenderError::UnbalancedBrace(i)),
            _ => {
                // Push whole UTF-8 scalar values, not raw bytes, so a
                // multi-byte character is never split across two pushes.
                let ch = template[i..].chars().next().unwrap();
                literal.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    if !literal.is_empty() {
        tokens.push(Token::Literal(literal));
    }
    Ok(tokens)
}

fn is_valid_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Classifies the zone a placeholder at `at` (a byte offset into `template`)
/// sits in, by scanning the template's own structural characters —
/// `://`, `@`, `/`, `?`, `#`, `&`, `=` — never the rendered output.
fn classify_zone(template: &str, at: usize) -> Zone {
    let scheme_end = match template.find("://") {
        Some(p) => p + 3,
        None => return Zone::Unstructured,
    };
    if at < scheme_end {
        return Zone::Unstructured;
    }
    // The authority region runs from the scheme to the first '/', '?' or '#'.
    let authority_end = template[scheme_end..]
        .find(['/', '?', '#'])
        .map(|p| p + scheme_end)
        .unwrap_or(template.len());
    if at < authority_end {
        let authority = &template[scheme_end..authority_end];
        if let Some(at_sign) = authority.find('@') {
            let at_sign = at_sign + scheme_end;
            return if at < at_sign {
                Zone::UserInfo
            } else {
                Zone::Host
            };
        }
        return Zone::Host;
    }
    let query_start = template[authority_end..]
        .find('?')
        .map(|p| p + authority_end);
    let fragment_start = template[authority_end..]
        .find('#')
        .map(|p| p + authority_end);
    if let Some(fs) = fragment_start {
        if at >= fs {
            return Zone::Fragment;
        }
    }
    if let Some(qs) = query_start {
        if at >= qs {
            let query_end = fragment_start.unwrap_or(template.len());
            let query = &template[qs..query_end];
            // Which '&'-delimited segment contains `at`, and is `at` before or
            // after that segment's '='?
            let rel = at - qs;
            let seg_start = query[..rel].rfind('&').map(|p| p + 1).unwrap_or(0);
            let seg_end = query[rel..]
                .find('&')
                .map(|p| p + rel)
                .unwrap_or(query.len());
            let segment = &query[seg_start..seg_end];
            return match segment.find('=') {
                Some(eq) if rel - seg_start > eq => Zone::QueryValue,
                Some(_) => Zone::QueryName,
                None => Zone::QueryName,
            };
        }
    }
    Zone::Path
}

/// Renders `template` against `parts`, refusing on any unfilled placeholder,
/// unbalanced brace, or (for a URL-shaped kind) a control character in a part.
///
/// `custom` and unrecognised kinds render every placeholder raw. Every other
/// kind percent-encodes by zone, computed from the **template's** structure —
/// see the module doc for why that has to be the template and not the output.
pub fn render(template: &str, parts: &[Part], kind: Kind) -> Result<Rendered, RenderError> {
    let by_name: BTreeMap<&str, &str> = parts
        .iter()
        .map(|p| (p.key.as_str(), p.value.as_str()))
        .collect();
    let tokens = tokenize(template)?;

    let mut text = String::new();
    let mut used = Vec::new();
    let encode = kind.is_url_shaped();

    for tok in &tokens {
        match tok {
            Token::Literal(s) => text.push_str(s),
            Token::Placeholder(name, at) => {
                let value = *by_name
                    .get(name.as_str())
                    .ok_or_else(|| RenderError::UnfilledPlaceholder(name.clone()))?;
                if encode && has_control_char(value) {
                    return Err(RenderError::ControlCharacterInPart(name.clone()));
                }
                if !used.contains(name) {
                    used.push(name.clone());
                }
                if encode {
                    let zone = classify_zone(template, *at);
                    text.push_str(&match zone {
                        Zone::Unstructured => value.to_string(),
                        Zone::UserInfo
                        | Zone::Host
                        | Zone::Path
                        | Zone::QueryName
                        | Zone::QueryValue
                        | Zone::Fragment => percent_encode(value),
                    });
                } else {
                    text.push_str(value);
                }
            }
        }
    }

    let unused: Vec<String> = parts
        .iter()
        .map(|p| p.key.clone())
        .filter(|k| !used.contains(k))
        .collect();

    Ok(Rendered { text, used, unused })
}

/// The placeholder names a template references, without needing any parts —
/// used by the form to build "Make part" suggestions and by the health scan
/// to find orphaned parts, without rendering (and therefore without needing
/// every part filled in first).
pub fn placeholders(template: &str) -> Result<Vec<String>, RenderError> {
    let mut names = Vec::new();
    for tok in tokenize(template)? {
        if let Token::Placeholder(name, _) = tok {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(k: &str, v: &str) -> Part {
        Part {
            key: k.into(),
            value: v.into(),
        }
    }

    #[test]
    fn renders_a_calendar_url_with_two_parts() {
        let tpl = "https://outlook.office365.com/owa/calendar/{mailbox_id}@inf.elte.hu/{calendar_key}/calendar.ics";
        let r = render(
            tpl,
            &[
                part("mailbox_id", "js.doe"),
                part("calendar_key", "abc-123"),
            ],
            Kind::Link,
        )
        .unwrap();
        assert_eq!(
            r.text,
            "https://outlook.office365.com/owa/calendar/js.doe@inf.elte.hu/abc-123/calendar.ics"
        );
        assert_eq!(r.used, vec!["mailbox_id", "calendar_key"]);
        assert!(r.unused.is_empty());
    }

    #[test]
    fn refuses_an_unfilled_placeholder() {
        let err = render("https://x/{a}", &[], Kind::Link).unwrap_err();
        assert_eq!(err, RenderError::UnfilledPlaceholder("a".into()));
    }

    #[test]
    fn double_braces_are_literal() {
        let r = render("{{literal}}", &[], Kind::Custom).unwrap();
        assert_eq!(r.text, "{literal}");
    }

    #[test]
    fn an_unbalanced_brace_is_a_form_error_not_a_literal() {
        assert!(matches!(
            render("https://x/{oops", &[], Kind::Link),
            Err(RenderError::UnbalancedBrace(_))
        ));
    }

    #[test]
    fn one_placeholder_used_twice_is_one_part_filled_twice() {
        // C3
        let r = render("{tok}/x/{tok}", &[part("tok", "abc")], Kind::Custom).unwrap();
        assert_eq!(r.text, "abc/x/abc");
        assert_eq!(r.used, vec!["tok"]);
    }

    #[test]
    fn a_part_no_placeholder_uses_is_reported_not_refused() {
        let r = render("no holes here", &[part("orphan", "v")], Kind::Custom).unwrap();
        assert_eq!(r.unused, vec!["orphan"]);
    }

    #[test]
    fn userinfo_encoding_stops_at_and_colon_from_moving_the_host() {
        // The motivating bug: postgres://app:p@ss@db/prod parses with host ss@db.
        let r = render(
            "postgres://{user}:{pass}@db.example.com/prod",
            &[part("user", "app"), part("pass", "p@ss:word")],
            Kind::Connection,
        )
        .unwrap();
        assert_eq!(r.text, "postgres://app:p%40ss%3Aword@db.example.com/prod");
    }

    #[test]
    fn query_value_is_encoded_and_query_name_is_too() {
        let r = render(
            "https://x/?{name}={value}",
            &[
                part("name", "a b"),
                part("value", "bot applications.commands"),
            ],
            Kind::Link,
        )
        .unwrap();
        assert_eq!(r.text, "https://x/?a%20b=bot%20applications.commands");
    }

    #[test]
    fn custom_never_encodes() {
        let r = render("{a}", &[part("a", "sp ace/slash")], Kind::Custom).unwrap();
        assert_eq!(r.text, "sp ace/slash");
    }

    #[test]
    fn control_character_in_a_url_shaped_part_is_refused() {
        let err = render("https://x/{a}", &[part("a", "line\nbreak")], Kind::Link).unwrap_err();
        assert_eq!(err, RenderError::ControlCharacterInPart("a".into()));
    }

    #[test]
    fn control_character_in_a_custom_part_is_allowed() {
        let r = render("{a}", &[part("a", "line\nbreak")], Kind::Custom).unwrap();
        assert_eq!(r.text, "line\nbreak");
    }

    #[test]
    fn placeholders_lists_names_with_no_parts_needed() {
        assert_eq!(
            placeholders("https://x/{a}/{b}/{a}").unwrap(),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn an_unknown_kind_string_behaves_like_custom() {
        // Assuming URL structure over an unrecognised shape corrupts a value
        // as easily as it protects one.
        assert_eq!(Kind::parse("nonsense"), Kind::Other);
        let r = render("{a}", &[part("a", "raw value")], Kind::parse("nonsense")).unwrap();
        assert_eq!(r.text, "raw value");
    }
}
