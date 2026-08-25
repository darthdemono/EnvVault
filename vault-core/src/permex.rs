//! Permission expressions — a small boolean language over vault entries.
//!
//! Replaces the flat list of `(scope_type, scope_value, permission)` rows, which
//! could only ever mean "any of these matches". Admins can now express what they
//! actually want:
//!
//! ```text
//! project:Alpha AND NOT category:secret
//! (project:web OR project:api) AND env:production
//! tag:shared OR type:certificate
//! ```
//!
//! # Grammar
//!
//! ```text
//! expr      := or_expr
//! or_expr   := and_expr (OR and_expr)*
//! and_expr  := not_expr (AND not_expr)*
//! not_expr  := NOT not_expr | primary
//! primary   := '(' expr ')' | predicate
//! predicate := field ':' glob
//! ```
//!
//! Precedence is `NOT` > `AND` > `OR`; parentheses override. Operators are
//! case-insensitive and `&&` / `||` / `!` are accepted as aliases. Adjacency is
//! **not** implicit AND — an operator is always required, so an expression can
//! never quietly mean something other than it reads.
//!
//! # Fields
//!
//! | Field       | Matches against                                    |
//! |-------------|----------------------------------------------------|
//! | `vault`     | everything (the value is ignored)                  |
//! | `project`   | the entry's project ids **and** their display names |
//! | `category`  | any of the entry's categories                      |
//! | `tag`       | any of the entry's tags                            |
//! | `env`       | the entry's environment                            |
//! | `type`      | the entry's secret type (default `api_key`)        |
//!
//! # Two rules worth knowing
//!
//! **`field:*` is unconditional.** It means "no constraint on this field",
//! not "has at least one value matching `*`". Without that, `project:*` would
//! match unfiled entries (every entry carries the `Universal` catch-all) while
//! `category:*` would not (an entry can have no categories at all) — the same
//! wildcard behaving differently depending on the field.
//!
//! **A specific project grant is never satisfied by `Universal`.** Every entry
//! belongs to it, so matching it would silently turn any project grant into a
//! vault-wide one.

use crate::users::glob_matches;
use std::fmt;

/// The catch-all project every entry carries.
const UNIVERSAL: &str = "Universal";

// ── AST ───────────────────────────────────────────────────────────────────────

/// Which part of an entry a predicate tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Vault,
    Project,
    Category,
    Tag,
    Env,
    Type,
}

impl Field {
    fn parse(s: &str) -> Option<Field> {
        match s.to_ascii_lowercase().as_str() {
            "vault" => Some(Field::Vault),
            "project" | "proj" => Some(Field::Project),
            "category" | "cat" => Some(Field::Category),
            "tag" => Some(Field::Tag),
            "env" | "environment" => Some(Field::Env),
            "type" | "secrettype" => Some(Field::Type),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Field::Vault => "vault",
            Field::Project => "project",
            Field::Category => "category",
            Field::Tag => "tag",
            Field::Env => "env",
            Field::Type => "type",
        }
    }
}

/// A parsed permission expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Pred { field: Field, glob: String },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

impl fmt::Display for Expr {
    /// Renders back to source form. Round-trips through [`parse`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Pred { field, glob } => {
                let needs_quotes = glob.is_empty()
                    || glob
                        .chars()
                        .any(|c| c.is_whitespace() || c == '(' || c == ')' || c == '"');
                if needs_quotes {
                    write!(f, "{}:\"{}\"", field.name(), glob.replace('"', "\\\""))
                } else {
                    write!(f, "{}:{}", field.name(), glob)
                }
            }
            Expr::And(a, b) => write!(f, "({a} AND {b})"),
            Expr::Or(a, b) => write!(f, "({a} OR {b})"),
            Expr::Not(a) => write!(f, "NOT {a}"),
        }
    }
}

// ── Entry view ────────────────────────────────────────────────────────────────

/// The parts of a vault entry an expression can test.
///
/// Borrowed rather than owned: evaluation runs once per entry per request, and
/// the source JSON already outlives it.
#[derive(Debug, Default, Clone)]
pub struct EntryView<'a> {
    pub categories: Vec<&'a str>,
    pub project_ids: Vec<&'a str>,
    /// Display names for `project_ids`, so rules can be written against either.
    pub project_names: Vec<String>,
    pub tags: Vec<&'a str>,
    pub environment: Option<&'a str>,
    pub secret_type: Option<&'a str>,
}

impl<'a> EntryView<'a> {
    /// Extracts the testable fields from a raw vault entry.
    ///
    /// `project_names` maps project id → display name; ids without a mapping
    /// fall back to the id itself.
    pub fn from_entry(
        entry: &'a serde_json::Value,
        project_names: &std::collections::HashMap<String, String>,
    ) -> EntryView<'a> {
        let strs = |key: &str| -> Vec<&'a str> {
            entry
                .get(key)
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default()
        };
        let project_ids = strs("projectIds");
        let names = project_ids
            .iter()
            .map(|id| {
                project_names
                    .get(*id)
                    .cloned()
                    .unwrap_or_else(|| (*id).to_string())
            })
            .collect();
        EntryView {
            categories: strs("categories"),
            project_ids,
            project_names: names,
            tags: strs("tags"),
            environment: entry.get("environment").and_then(|v| v.as_str()),
            secret_type: entry.get("secretType").and_then(|v| v.as_str()),
        }
    }
}

// ── Evaluation ────────────────────────────────────────────────────────────────

/// Does `expr` grant access to `entry`?
pub fn eval(expr: &Expr, entry: &EntryView<'_>) -> bool {
    match expr {
        Expr::And(a, b) => eval(a, entry) && eval(b, entry),
        Expr::Or(a, b) => eval(a, entry) || eval(b, entry),
        Expr::Not(a) => !eval(a, entry),
        Expr::Pred { field, glob } => eval_pred(*field, glob, entry),
    }
}

fn eval_pred(field: Field, glob: &str, e: &EntryView<'_>) -> bool {
    // `field:*` places no constraint on the field — see the module docs.
    let wildcard = glob == "*";
    match field {
        Field::Vault => true,
        Field::Category => wildcard || e.categories.iter().any(|c| glob_matches(glob, c)),
        Field::Tag => wildcard || e.tags.iter().any(|t| glob_matches(glob, t)),
        Field::Env => wildcard || e.environment.is_some_and(|v| glob_matches(glob, v)),
        // Entries without an explicit type are api_key by convention.
        Field::Type => wildcard || glob_matches(glob, e.secret_type.unwrap_or("api_key")),
        Field::Project => {
            if wildcard {
                return true;
            }
            // Skip the catch-all: every entry carries it, so allowing it to
            // match would promote any project grant to vault-wide.
            e.project_ids.iter().enumerate().any(|(i, id)| {
                if *id == UNIVERSAL {
                    return false;
                }
                glob_matches(glob, id)
                    || e.project_names
                        .get(i)
                        .is_some_and(|n| glob_matches(glob, n))
            })
        }
    }
}

// ── Lexer ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Pred(Field, String),
    And,
    Or,
    Not,
    LParen,
    RParen,
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }

        match c {
            '(' => {
                out.push(Tok::LParen);
                i += 1;
                continue;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
                continue;
            }
            '!' => {
                out.push(Tok::Not);
                i += 1;
                continue;
            }
            '&' => {
                i += if i + 1 < chars.len() && chars[i + 1] == '&' {
                    2
                } else {
                    1
                };
                out.push(Tok::And);
                continue;
            }
            '|' => {
                i += if i + 1 < chars.len() && chars[i + 1] == '|' {
                    2
                } else {
                    1
                };
                out.push(Tok::Or);
                continue;
            }
            _ => {}
        }

        // A bare word: either an operator keyword or the field half of a predicate.
        let start = i;
        while i < chars.len()
            && !chars[i].is_whitespace()
            && chars[i] != '('
            && chars[i] != ')'
            && chars[i] != ':'
        {
            i += 1;
        }
        let word: String = chars[start..i].iter().collect();
        if word.is_empty() {
            return Err(format!("unexpected character '{c}' at position {start}"));
        }

        // Not followed by ':' → it must be an operator.
        if i >= chars.len() || chars[i] != ':' {
            match word.to_ascii_uppercase().as_str() {
                "AND" => out.push(Tok::And),
                "OR" => out.push(Tok::Or),
                "NOT" => out.push(Tok::Not),
                _ => {
                    return Err(format!(
                        "expected AND, OR, NOT or a `field:value` term, found '{word}'"
                    ))
                }
            }
            continue;
        }

        i += 1; // consume ':'
        let Some(field) = Field::parse(&word) else {
            return Err(format!(
                "unknown field '{word}' — expected one of vault, project, category, tag, env, type"
            ));
        };

        // Value: quoted (may contain spaces) or bare up to whitespace/paren.
        let value = if i < chars.len() && chars[i] == '"' {
            i += 1;
            let mut v = String::new();
            loop {
                if i >= chars.len() {
                    return Err("unterminated quoted value".to_string());
                }
                match chars[i] {
                    '\\' if i + 1 < chars.len() => {
                        v.push(chars[i + 1]);
                        i += 2;
                    }
                    '"' => {
                        i += 1;
                        break;
                    }
                    ch => {
                        v.push(ch);
                        i += 1;
                    }
                }
            }
            v
        } else {
            let vs = i;
            while i < chars.len() && !chars[i].is_whitespace() && chars[i] != '(' && chars[i] != ')'
            {
                i += 1;
            }
            chars[vs..i].iter().collect()
        };

        if value.is_empty() {
            return Err(format!(
                "field '{word}' has no value — write {word}:* to match everything"
            ));
        }
        out.push(Tok::Pred(field, value));
    }

    Ok(out)
}

// ── Parser ────────────────────────────────────────────────────────────────────

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Or)) {
            self.next();
            let rhs = self.parse_and()?;
            lhs = Expr::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_not()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.next();
            let rhs = self.parse_not()?;
            lhs = Expr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_not(&mut self) -> Result<Expr, String> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.next();
            return Ok(Expr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.next() {
            Some(Tok::Pred(field, glob)) => Ok(Expr::Pred { field, glob }),
            Some(Tok::LParen) => {
                let inner = self.parse_or()?;
                match self.next() {
                    Some(Tok::RParen) => Ok(inner),
                    _ => Err("missing closing ')'".to_string()),
                }
            }
            Some(Tok::RParen) => Err("unexpected ')'".to_string()),
            Some(Tok::And) | Some(Tok::Or) => Err("expression begins with an operator".to_string()),
            Some(Tok::Not) => unreachable!("handled in parse_not"),
            None => Err("unexpected end of expression".to_string()),
        }
    }
}

/// Parses a permission expression.
///
/// Returns `Err` with a human-readable reason for anything malformed. Callers
/// must treat a parse failure as **deny** — never as "no restriction".
pub fn parse(src: &str) -> Result<Expr, String> {
    let toks = lex(src)?;
    if toks.is_empty() {
        return Err("empty expression".to_string());
    }
    let mut p = Parser { toks, pos: 0 };
    let expr = p.parse_or()?;
    if p.pos != p.toks.len() {
        return Err("trailing input after the end of the expression".to_string());
    }
    Ok(expr)
}

/// Convenience: parse and evaluate, treating a malformed expression as deny.
pub fn eval_str(src: &str, entry: &EntryView<'_>) -> bool {
    parse(src).map(|e| eval(&e, entry)).unwrap_or(false)
}

// ── Compiling legacy permission rows ──────────────────────────────────────────

/// Builds the expression equivalent to a set of legacy `(scope_type, scope_value)`
/// rows, which always meant "any of these matches".
///
/// Returns `None` when there are no rows — the caller must treat that as
/// "no grant", not "no restriction".
pub fn compile_scopes<'a, I>(scopes: I) -> Option<Expr>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut acc: Option<Expr> = None;
    for (scope_type, scope_value) in scopes {
        let field = match Field::parse(scope_type) {
            Some(f) => f,
            None => continue, // unknown legacy scope type: ignore rather than over-grant
        };
        let pred = Expr::Pred {
            field,
            glob: scope_value.to_string(),
        };
        acc = Some(match acc {
            None => pred,
            Some(prev) => Expr::Or(Box::new(prev), Box::new(pred)),
        });
    }
    acc
}

/// Combines a class expression with an individual one.
///
/// Both present → **AND**: a class restriction cannot be undone by an individual
/// grant, which is what makes classes an actual boundary. Exactly one present →
/// that one. Neither → `None`, meaning no grant at all.
///
/// The AND is why "neither" must be `None` rather than a vacuous truth: treating
/// an absent expression as `true` would make a user with no permissions
/// whatsoever evaluate to `true AND true` and see everything.
//
// (This block documents `combine`, below. It sat above `any_of` for several
// phases, so `any_of` appeared to be the function that ANDs — it is not.)
/// ORs two optional expressions, used for "write implies read".
pub fn any_of(a: Option<Expr>, b: Option<Expr>) -> Option<Expr> {
    match (a, b) {
        (Some(x), Some(y)) => Some(Expr::Or(Box::new(x), Box::new(y))),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

pub fn combine(class: Option<Expr>, individual: Option<Expr>) -> Option<Expr> {
    match (class, individual) {
        (Some(c), Some(i)) => Some(Expr::And(Box::new(c), Box::new(i))),
        (Some(c), None) => Some(c),
        (None, Some(i)) => Some(i),
        (None, None) => None,
    }
}

/// Rewrites a permission expression so **every** top-level alternative must
/// match, instead of any one of them.
///
/// This is what "strict write scoping" means in a codebase where scopes became
/// expressions. `compile_scopes` joins a subject's scopes with `Or`, so a user
/// scoped to two projects may write anything in *either*. Under strict mode an
/// entry must satisfy all of them — in practice, be in both.
///
/// Only the top-level `Or` chain is rewritten. Nested groups an author wrote by
/// hand are left alone: `(a OR b) AND c` was deliberate, and silently turning
/// its inner alternation into a conjunction would change a rule its author
/// already expressed precisely. Strictness is about the implicit OR that
/// scope-joining introduced, not about second-guessing explicit logic.
///
/// Strict mode can only ever *narrow* what is permitted. That direction matters:
/// a bug here should lock someone out, not let them through.
pub fn require_all(expr: Expr) -> Expr {
    match expr {
        Expr::Or(a, b) => Expr::And(Box::new(require_all(*a)), Box::new(require_all(*b))),
        other => other,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    fn names(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    fn view<'a>(e: &'a serde_json::Value, pn: &HashMap<String, String>) -> EntryView<'a> {
        EntryView::from_entry(e, pn)
    }

    fn entry() -> serde_json::Value {
        json!({
            "provider": "X",
            "categories": ["dev", "shared"],
            "projectIds": ["Universal", "p1"],
            "tags": ["team-a"],
            "environment": "production",
            "secretType": "api_key",
        })
    }

    // ── Parsing ───────────────────────────────────────────────────────────────

    #[test]
    fn precedence_is_not_then_and_then_or() {
        // a OR b AND c  ==  a OR (b AND c)
        let e = parse("category:a OR category:b AND category:c").unwrap();
        assert_eq!(e.to_string(), "(category:a OR (category:b AND category:c))");
    }

    #[test]
    fn not_binds_tighter_than_and() {
        let e = parse("NOT category:a AND category:b").unwrap();
        assert_eq!(e.to_string(), "(NOT category:a AND category:b)");
    }

    #[test]
    fn parentheses_override_precedence() {
        let e = parse("(category:a OR category:b) AND category:c").unwrap();
        assert_eq!(e.to_string(), "((category:a OR category:b) AND category:c)");
    }

    #[test]
    fn symbolic_operators_are_aliases() {
        assert_eq!(
            parse("category:a && category:b").unwrap(),
            parse("category:a AND category:b").unwrap()
        );
        assert_eq!(
            parse("category:a || category:b").unwrap(),
            parse("category:a OR category:b").unwrap()
        );
        assert_eq!(
            parse("!category:a").unwrap(),
            parse("NOT category:a").unwrap()
        );
    }

    #[test]
    fn operators_are_case_insensitive() {
        assert_eq!(
            parse("category:a and category:b").unwrap(),
            parse("category:a AND category:b").unwrap()
        );
    }

    #[test]
    fn quoted_values_may_contain_spaces() {
        let e = parse(r#"project:"My Project""#).unwrap();
        assert_eq!(
            e,
            Expr::Pred {
                field: Field::Project,
                glob: "My Project".into()
            }
        );
    }

    #[test]
    fn field_aliases_resolve() {
        assert_eq!(parse("proj:a").unwrap(), parse("project:a").unwrap());
        assert_eq!(parse("cat:a").unwrap(), parse("category:a").unwrap());
    }

    #[test]
    fn expressions_round_trip_through_display() {
        for src in [
            "project:a",
            "(project:a AND NOT category:b)",
            "((project:a OR tag:x) AND env:production)",
        ] {
            let once = parse(src).unwrap();
            let twice = parse(&once.to_string()).unwrap();
            assert_eq!(once, twice, "round-trip failed for {src}");
        }
    }

    // ── Malformed input must fail, never silently permit ──────────────────────

    #[test]
    fn malformed_expressions_are_rejected() {
        for bad in [
            "",                      // empty
            "category:",             // no value
            "bogus:a",               // unknown field
            "category:a AND",        // dangling operator
            "AND category:a",        // leading operator
            "(category:a",           // unclosed paren
            "category:a)",           // stray close
            "category:a category:b", // adjacency is not implicit AND
            "just-a-word",           // not a term
        ] {
            assert!(parse(bad).is_err(), "expected {bad:?} to be rejected");
        }
    }

    #[test]
    fn eval_str_denies_on_malformed_input() {
        let pn = names(&[]);
        let e = entry();
        assert!(
            !eval_str("category:a AND", &view(&e, &pn)),
            "a broken expression must deny, not permit"
        );
        assert!(!eval_str("", &view(&e, &pn)));
    }

    // ── Evaluation ────────────────────────────────────────────────────────────

    #[test]
    fn predicates_match_their_own_field() {
        let pn = names(&[("p1", "Alpha")]);
        let e = entry();
        let v = view(&e, &pn);
        assert!(eval_str("category:dev", &v));
        assert!(
            eval_str("project:Alpha", &v),
            "project matches by display name"
        );
        assert!(eval_str("project:p1", &v), "project matches by id");
        assert!(eval_str("tag:team-a", &v));
        assert!(eval_str("env:production", &v));
        assert!(eval_str("type:api_key", &v));
        assert!(!eval_str("category:nope", &v));
        assert!(!eval_str("env:staging", &v));
    }

    #[test]
    fn globs_work_inside_predicates() {
        let pn = names(&[("p1", "Alpha")]);
        let e = entry();
        assert!(eval_str("project:Al*", &view(&e, &pn)));
        assert!(eval_str("tag:team-?", &view(&e, &pn)));
        assert!(!eval_str("project:Be*", &view(&e, &pn)));
    }

    #[test]
    fn boolean_combinations_evaluate() {
        let pn = names(&[("p1", "Alpha")]);
        let e = entry();
        let v = view(&e, &pn);
        assert!(eval_str("category:dev AND env:production", &v));
        assert!(!eval_str("category:dev AND env:staging", &v));
        assert!(eval_str("category:nope OR tag:team-a", &v));
        assert!(eval_str("project:Alpha AND NOT category:secret", &v));
        assert!(!eval_str("project:Alpha AND NOT category:dev", &v));
        assert!(eval_str(
            "(category:nope OR project:Alpha) AND env:production",
            &v
        ));
    }

    #[test]
    fn untyped_entries_are_treated_as_api_key() {
        let pn = names(&[]);
        let e = json!({ "provider": "X", "projectIds": ["Universal"] });
        assert!(eval_str("type:api_key", &view(&e, &pn)));
    }

    // ── The two rules that bit us before ──────────────────────────────────────

    #[test]
    fn wildcards_are_unconditional_across_every_field() {
        let pn = names(&[]);
        // Unfiled: no categories, no tags, no env, only the Universal project.
        let e = json!({ "provider": "X", "projectIds": ["Universal"] });
        let v = view(&e, &pn);
        for src in [
            "project:*",
            "category:*",
            "tag:*",
            "env:*",
            "type:*",
            "vault:*",
        ] {
            assert!(eval_str(src, &v), "{src} must match an unfiled entry");
        }
    }

    #[test]
    fn a_specific_project_grant_is_never_satisfied_by_universal() {
        let pn = names(&[]);
        let e = json!({ "provider": "X", "projectIds": ["Universal"] });
        assert!(
            !eval_str("project:Universal", &view(&e, &pn)),
            "matching the catch-all would promote any project grant to vault-wide"
        );
    }

    // ── Legacy compilation and composition ────────────────────────────────────

    #[test]
    fn legacy_rows_compile_to_an_or_chain() {
        let e = compile_scopes(vec![("project", "Alpha"), ("category", "dev")]).unwrap();
        assert_eq!(e.to_string(), "(project:Alpha OR category:dev)");
    }

    #[test]
    fn compiling_no_rows_yields_no_grant() {
        assert!(compile_scopes(Vec::<(&str, &str)>::new()).is_none());
    }

    #[test]
    fn unknown_legacy_scope_types_are_dropped_not_widened() {
        // A row we cannot interpret must never become a broader grant.
        assert!(compile_scopes(vec![("nonsense", "*")]).is_none());
    }

    #[test]
    fn combine_ands_class_with_individual() {
        let c = parse("project:*").unwrap();
        let i = parse("NOT category:secret").unwrap();
        let combined = combine(Some(c), Some(i)).unwrap();
        assert_eq!(combined.to_string(), "(project:* AND NOT category:secret)");
    }

    #[test]
    fn a_class_exclusion_cannot_be_undone_individually() {
        let pn = names(&[("p1", "Alpha")]);
        let secret =
            json!({ "provider": "S", "categories": ["secret"], "projectIds": ["Universal", "p1"] });
        let combined = combine(
            Some(parse("NOT category:secret").unwrap()), // class says: never secrets
            Some(parse("project:*").unwrap()),           // individual says: all projects
        )
        .unwrap();
        assert!(
            !eval(&combined, &view(&secret, &pn)),
            "the class exclusion must win over the individual grant"
        );
    }

    #[test]
    fn no_expressions_at_all_means_no_grant() {
        // Guards the emptiness rule: with AND composition, treating absent as
        // `true` would give a user with no permissions full access.
        assert!(combine(None, None).is_none());
    }
}
