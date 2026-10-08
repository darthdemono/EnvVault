//! Bundle-local template resolution (Phase 24.1, step 4).
//!
//! Resolves local variables, composite parts, sibling fields and optional
//! global references. Missing inputs, cycles and excessive derived depth are
//! errors so a partially rendered credential cannot look valid.

use serde_json::Value;
use std::collections::HashMap;

const MAX_DEPTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedValue {
    pub value: String,
    pub secret: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    Unresolved(String),
    Cycle(Vec<String>),
    Depth(String),
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeOutput {
    pub value: ScopedValue,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeOutput {
    pub value: String,
    pub secret: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositeScopeError {
    Scope(ScopeError),
    Composite(crate::composite::RenderError),
}

fn string_field<'a>(entry: &'a Value, key: &str) -> Option<&'a str> {
    entry.get(key).and_then(Value::as_str)
}

fn bool_field(entry: &Value, key: &str) -> bool {
    entry.get(key).and_then(Value::as_bool) == Some(true)
}

fn variable<'a>(entry: &'a Value, key: &str) -> Option<&'a Value> {
    entry
        .get("extra_vars")
        .and_then(Value::as_array)?
        .iter()
        .find(|item| string_field(item, "key") == Some(key))
}

fn entry_field(entry: &Value, key: &str) -> Option<ScopedValue> {
    if matches!(key, "version_history" | "projectIds" | "categories") {
        return None;
    }
    let role = role_key(key);
    if role != "VALUE"
        && entry
            .get("primary_role")
            .and_then(Value::as_str)
            .is_some_and(|value| role_key(value) == role)
    {
        return Some(ScopedValue {
            value: string_field(entry, "api_key")?.to_owned(),
            secret: !bool_field(entry, "primary_public"),
        });
    }
    if role != "VALUE"
        && entry
            .get("secret_role")
            .and_then(Value::as_str)
            .is_some_and(|value| role_key(value) == role)
    {
        return Some(ScopedValue {
            value: string_field(entry, "api_secret")?.to_owned(),
            secret: !bool_field(entry, "secret_public"),
        });
    }
    let canonical = match key.to_ascii_uppercase().as_str() {
        "APIKEY" | "API_KEY" | "KEY" | "TOKEN" | "ACCESS_TOKEN" | "BEARER" | "SECRET_KEY"
        | "PASSWORD" | "PASS" | "PWD" => "api_key",
        "SECRET" | "API_SECRET" | "CLIENT_SECRET" | "SHARED_SECRET" => "api_secret",
        "USERNAME" | "USER" | "LOGIN" | "USER_NAME" => "username",
        "URL" | "URI" | "ENDPOINT" | "API_URL" | "BASE_URL" => "api_url",
        "EMAIL" | "MAIL" => "email",
        "KEY_ID" | "KEYID" | "KID" | "ID" | "CLIENT_ID" | "APP_ID" | "ACCOUNT_ID"
        | "APPLICATION_ID" => "key_id",
        "PATH" | "MOUNT" | "MOUNT_PATH" | "FILE" => "mount_path",
        _ => key,
    };
    let (field, secret) = match canonical {
        "api_key" => ("api_key", !bool_field(entry, "primary_public")),
        "api_secret" => ("api_secret", !bool_field(entry, "secret_public")),
        _ => (
            canonical,
            matches!(canonical, "totp_secret" | "user_agent" | "blob_data"),
        ),
    };
    if let Some(value) = string_field(entry, field) {
        return Some(ScopedValue {
            value: value.to_owned(),
            secret,
        });
    }
    let item = variable(entry, key).or_else(|| variable(entry, canonical))?;
    Some(ScopedValue {
        value: string_field(item, "value")?.to_owned(),
        secret: item.get("public").and_then(Value::as_bool) != Some(true)
            && item.get("secret").and_then(Value::as_bool) != Some(false),
    })
}

fn role_key(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Resolve `{local}` and `{slot.field}`. `globals` returns a value only when
/// the caller can resolve and read that reference; callers should mark a
/// reference secret unless its source is explicitly public.
pub fn resolve<F>(
    bundle: &Value,
    members: &[Value],
    template: &str,
    parts: &[Value],
    globals: F,
) -> Result<ScopeOutput, ScopeError>
where
    F: Fn(&str) -> Option<ScopedValue>,
{
    let mut slots = HashMap::new();
    for member in members {
        let slot = string_field(member, "bundle_slot")
            .filter(|s| !s.is_empty())
            .or_else(|| string_field(member, "provider"))
            .unwrap_or_default();
        if slots.insert(slot.to_owned(), member).is_some() {
            return Err(ScopeError::Invalid(format!(
                "duplicate bundle slot \"{slot}\""
            )));
        }
    }
    let mut locals = HashMap::new();
    if let Some(values) = bundle.get("extra_vars").and_then(Value::as_array) {
        for item in values {
            if let (Some(key), Some(_)) = (string_field(item, "key"), string_field(item, "value")) {
                locals.insert(key.to_owned(), item);
            }
        }
    }
    let own: HashMap<&str, &Value> = parts
        .iter()
        .filter_map(|part| Some((string_field(part, "key")?, part)))
        .collect();
    let mut warnings = Vec::new();
    for name in locals.keys() {
        if own.contains_key(name.as_str())
            || members
                .iter()
                .any(|m| string_field(m, "bundle_slot") == Some(name))
        {
            warnings.push(format!(
                "\"{name}\" exists at more than one scope level; the part wins over the local"
            ));
        }
    }
    let mut stack = Vec::new();
    let value = resolve_text(template, 0, &mut stack, &locals, &own, &slots, &globals)?;
    Ok(ScopeOutput { value, warnings })
}

/// Resolve scoped references into synthetic named parts, then pass those parts
/// through the shared zone-aware composite renderer.
pub fn render_composite<F>(
    bundle: &Value,
    members: &[Value],
    template: &str,
    own_parts: &[Value],
    kind: crate::composite::Kind,
    globals: F,
) -> Result<CompositeOutput, CompositeScopeError>
where
    F: Fn(&str) -> Option<ScopedValue>,
{
    let mut expanded = String::new();
    let mut parts = Vec::new();
    let mut warnings = Vec::new();
    let mut secret = false;
    let mut pos = 0;
    let mut index = 0;
    while pos < template.len() {
        let rest = &template[pos..];
        if rest.starts_with("{{") || rest.starts_with("}}") {
            expanded.push_str(&rest[..2]);
            pos += 2;
            continue;
        }
        let global_end = if rest.starts_with("${") {
            Some(rest.find('}').ok_or_else(|| {
                CompositeScopeError::Scope(ScopeError::Invalid(format!(
                    "unclosed global reference at {pos}"
                )))
            })?)
        } else {
            None
        };
        if let Some(end) = global_end {
            let scoped = resolve(bundle, members, &rest[..=end], own_parts, &globals)
                .map_err(CompositeScopeError::Scope)?;
            let key = format!("scope_{index}");
            index += 1;
            secret |= scoped.value.secret;
            warnings.extend(scoped.warnings);
            parts.push(crate::composite::Part {
                key: key.clone(),
                value: scoped.value.value,
            });
            expanded.push('{');
            expanded.push_str(&key);
            expanded.push('}');
            pos += end + 1;
            continue;
        }
        let ch = rest.chars().next().expect("pos is within template");
        if ch == '}' {
            return Err(CompositeScopeError::Scope(ScopeError::Invalid(format!(
                "unmatched closing brace at {pos}"
            ))));
        }
        if ch != '{' {
            expanded.push(ch);
            pos += ch.len_utf8();
            continue;
        }
        let end = rest.find('}').ok_or_else(|| {
            CompositeScopeError::Scope(ScopeError::Invalid(format!("unclosed brace at {pos}")))
        })?;
        let scoped = resolve(bundle, members, &rest[..=end], own_parts, &globals)
            .map_err(CompositeScopeError::Scope)?;
        let key = format!("scope_{index}");
        index += 1;
        secret |= scoped.value.secret;
        warnings.extend(scoped.warnings);
        parts.push(crate::composite::Part {
            key: key.clone(),
            value: scoped.value.value,
        });
        expanded.push('{');
        expanded.push_str(&key);
        expanded.push('}');
        pos += end + 1;
    }
    let rendered = crate::composite::render(&expanded, &parts, kind)
        .map_err(CompositeScopeError::Composite)?;
    Ok(CompositeOutput {
        value: rendered.text,
        secret,
        warnings,
    })
}

fn resolve_text<F>(
    text: &str,
    depth: usize,
    stack: &mut Vec<String>,
    locals: &HashMap<String, &Value>,
    own: &HashMap<&str, &Value>,
    slots: &HashMap<String, &Value>,
    globals: &F,
) -> Result<ScopedValue, ScopeError>
where
    F: Fn(&str) -> Option<ScopedValue>,
{
    let mut output = String::new();
    let mut secret = false;
    let mut pos = 0;
    while pos < text.len() {
        let rest = &text[pos..];
        if let Some(tail) = rest.strip_prefix("{{") {
            output.push('{');
            pos = text.len() - tail.len();
            continue;
        }
        if let Some(tail) = rest.strip_prefix("}}") {
            output.push('}');
            pos = text.len() - tail.len();
            continue;
        }
        if let Some(tail) = rest.strip_prefix("${") {
            let close = tail.find('}').ok_or_else(|| {
                ScopeError::Invalid(format!("unclosed global reference at {pos}"))
            })?;
            let name = &tail[..close];
            let value =
                globals(name).ok_or_else(|| ScopeError::Unresolved(format!("\u{24}{{{name}}}")))?;
            secret |= value.secret;
            output.push_str(&value.value);
            pos += 2 + close + 1;
            continue;
        }
        let ch = rest.chars().next().expect("pos is within text");
        if ch == '}' {
            return Err(ScopeError::Invalid(format!(
                "unmatched closing brace at {pos}"
            )));
        }
        if ch != '{' {
            output.push(ch);
            pos += ch.len_utf8();
            continue;
        }
        let close = rest
            .find('}')
            .ok_or_else(|| ScopeError::Invalid(format!("unclosed brace at {pos}")))?;
        let name = &rest[1..close];
        if !valid_name(name) {
            return Err(ScopeError::Invalid(format!("invalid reference \"{name}\"")));
        }
        let resolved = if let Some(part) = own.get(name) {
            value_from_var(part)?
        } else if let Some(local) = locals.get(name) {
            if stack.iter().any(|item| item == name) {
                let mut path = stack.clone();
                path.push(name.to_owned());
                return Err(ScopeError::Cycle(path));
            }
            let raw = string_field(local, "value").unwrap_or_default();
            let kind = string_field(local, "kind").unwrap_or_default();
            let inner = if kind == "template" {
                if depth >= MAX_DEPTH && has_reference(raw) {
                    return Err(ScopeError::Depth(name.to_owned()));
                }
                stack.push(name.to_owned());
                let result = resolve_text(raw, depth + 1, stack, locals, own, slots, globals);
                stack.pop();
                result?
            } else {
                ScopedValue {
                    value: raw.to_owned(),
                    secret: false,
                }
            };
            ScopedValue {
                value: inner.value,
                secret: inner.secret
                    || (!bool_field(local, "public")
                        && local.get("secret").and_then(Value::as_bool) != Some(false)),
            }
        } else if let Some((slot, field)) = name.split_once('.') {
            slots
                .get(slot)
                .and_then(|entry| entry_field(entry, field))
                .ok_or_else(|| ScopeError::Unresolved(name.to_owned()))?
        } else {
            return Err(ScopeError::Unresolved(name.to_owned()));
        };
        secret |= resolved.secret;
        output.push_str(&resolved.value);
        pos += close + 1;
    }
    Ok(ScopedValue {
        value: output,
        secret,
    })
}

fn valid_name(name: &str) -> bool {
    let mut parts = name.split('.');
    let valid_ident = |s: &str| {
        let mut chars = s.chars();
        chars
            .next()
            .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
            && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
    };
    let first = parts.next().is_some_and(valid_ident);
    first && parts.next().is_none_or(valid_ident) && parts.next().is_none()
}

fn has_reference(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.windows(2).any(|w| w == b"${") || bytes.windows(2).any(|w| w[0] == b'{' && w[1] != b'{')
}

fn value_from_var(value: &Value) -> Result<ScopedValue, ScopeError> {
    let raw = string_field(value, "value")
        .ok_or_else(|| ScopeError::Invalid("part has no string value".to_owned()))?;
    Ok(ScopedValue {
        value: raw.to_owned(),
        secret: value.get("public").and_then(Value::as_bool) != Some(true)
            && value.get("secret").and_then(Value::as_bool) != Some(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_the_shared_typescript_parity_fixture() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/parity/bundle-scope.json"
        ))
        .unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let members = case["members"].as_array().unwrap();
            let out = resolve(
                &case["bundle"],
                members,
                case["template"].as_str().unwrap(),
                &[],
                |_| None,
            )
            .unwrap_or_else(|err| panic!("{}: {err:?}", case["name"]));
            assert_eq!(out.value.value, case["expected"]["value"].as_str().unwrap());
            assert_eq!(
                out.value.secret,
                case["expected"]["secret"].as_bool().unwrap()
            );
        }
        for case in fixture["composites"].as_array().unwrap() {
            let out = render_composite(
                &case["bundle"],
                case["members"].as_array().unwrap(),
                case["template"].as_str().unwrap(),
                case["own_parts"].as_array().unwrap(),
                crate::composite::Kind::parse(case["kind"].as_str().unwrap()),
                |_| None,
            )
            .unwrap_or_else(|err| panic!("{}: {err:?}", case["name"]));
            assert_eq!(out.value, case["expected"]["value"].as_str().unwrap());
            assert_eq!(out.secret, case["expected"]["secret"].as_bool().unwrap());
        }
    }

    #[test]
    fn resolves_siblings_and_propagates_taint() {
        let bundle = json!({"secretType":"bundle", "extra_vars":[{"key":"prefix","value":">","public":true}]});
        let member = json!({"provider":"Discord", "bundle_slot":"discord", "api_key":"token", "extra_vars":[{"key":"id","value":"9007199254740993","public":true}]});
        let out = resolve(
            &bundle,
            &[member],
            "{prefix}{discord.id}:{discord.key}",
            &[],
            |_| None,
        )
        .unwrap();
        assert_eq!(
            out.value,
            ScopedValue {
                value: ">9007199254740993:token".into(),
                secret: true
            }
        );
    }

    #[test]
    fn unresolved_cycles_and_depth_refuse_rendering() {
        let missing = resolve(&json!({}), &[], "{missing}", &[], |_| None).unwrap_err();
        assert_eq!(missing, ScopeError::Unresolved("missing".into()));
        let cycle = json!({"extra_vars":[{"key":"a","value":"{b}","kind":"template"},{"key":"b","value":"{a}","kind":"template"}]});
        assert!(matches!(
            resolve(&cycle, &[], "{a}", &[], |_| None),
            Err(ScopeError::Cycle(_))
        ));
        let deep = json!({"extra_vars":[
            {"key":"a","value":"{b}","kind":"template"}, {"key":"b","value":"{c}","kind":"template"},
            {"key":"c","value":"{d}","kind":"template"}, {"key":"d","value":"{e}","kind":"template"},
            {"key":"e","value":"{f}","kind":"template"}, {"key":"f","value":"end","kind":"template"}
        ]});
        assert!(matches!(
            resolve(&deep, &[], "{a}", &[], |_| None),
            Err(ScopeError::Depth(_))
        ));
    }
}
